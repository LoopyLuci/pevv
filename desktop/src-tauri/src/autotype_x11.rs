//! Auto-type on Linux. X11: the foreground window comes from `_NET_ACTIVE_WINDOW` (title from
//! `_NET_WM_NAME`, process from `_NET_WM_PID` and `/proc/<pid>/exe`) and keys are typed with the
//! XTEST extension, through x11rb. Wayland: there is no reliable way to learn which window has
//! focus, and no permitted way to type into another program, so this reports "unsupported" and
//! the app falls back to copying the password to the clipboard (with the usual 30 s clear).
//!
//! The real X11 paths are not covered by unit tests (they need a running X server and would
//! type into it); the planning code below is.
//!
//! X11 gives injected keys no "extra info" field, so unlike the Windows path they cannot be
//! marked as ours. No key or character is ever logged here.

use crate::autotype_core::{Action, CtxError, Key, Platform, Support, Target, TypeError};
use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, KEY_PRESS_EVENT, KEY_RELEASE_EVENT};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

const XK_RETURN: u32 = 0xff0d;
const XK_TAB: u32 = 0xff09;
const XK_SHIFT_L: u32 = 0xffe1;

pub struct Linux;

/// Is this a Wayland session? (Under XWayland, X11 calls would only see X11 programs, so it counts.)
pub fn is_wayland(session_type: Option<&str>, wayland_display: Option<&str>, display: Option<&str>) -> bool {
    session_type.is_some_and(|s| s.eq_ignore_ascii_case("wayland")) || (wayland_display.is_some_and(|w| !w.is_empty()) && display.is_none_or(str::is_empty))
}

fn wayland_now() -> bool {
    let get = |k: &str| std::env::var(k).ok();
    is_wayland(get("XDG_SESSION_TYPE").as_deref(), get("WAYLAND_DISPLAY").as_deref(), get("DISPLAY").as_deref())
}

/// X11 keysym for a character: Latin-1 maps to itself, everything else to `0x0100_0000 + code point`.
pub fn keysym_of(c: char) -> u32 {
    match c {
        '\n' | '\r' => XK_RETURN,
        '\t' => XK_TAB,
        c if (c as u32) < 0x100 => c as u32,
        c => 0x0100_0000 + c as u32,
    }
}

/// How to produce one keysym with the keyboard as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// A key that already makes it, with Shift or without.
    Existing { keycode: u8, shift: bool },
    /// No key does: borrow the spare key for the moment.
    Scratch,
}

/// Look `ks` up in the keyboard map (`per` keysyms per key, first key `min`): level 0 is the key
/// alone, level 1 is with Shift.
pub fn plan_key(min: u8, per: usize, syms: &[u32], ks: u32) -> Plan {
    if per >= 1 && ks != 0 {
        for (i, chunk) in syms.chunks(per).enumerate() {
            let code = min as usize + i;
            if code > 255 {
                break;
            }
            if chunk.first() == Some(&ks) {
                return Plan::Existing { keycode: code as u8, shift: false };
            }
            if chunk.get(1) == Some(&ks) && chunk.first() != Some(&0) {
                return Plan::Existing { keycode: code as u8, shift: true };
            }
        }
    }
    Plan::Scratch
}

fn fail<E: std::fmt::Display>(e: E) -> CtxError {
    CtxError::Failed(e.to_string())
}

fn tfail<E: std::fmt::Display>(e: E) -> TypeError {
    TypeError::Failed(e.to_string())
}

fn atom(conn: &RustConnection, name: &str) -> Result<u32, CtxError> {
    Ok(conn.intern_atom(false, name.as_bytes()).map_err(fail)?.reply().map_err(fail)?.atom)
}

impl Platform for Linux {
    fn support(&self) -> Support {
        if wayland_now() {
            return Support {
                context: false,
                typing: false,
                session: "wayland",
                note: Some("Wayland does not let a program see which window has focus or type into other programs. PEVV copies the password to the clipboard instead (cleared after the usual time).".into()),
            };
        }
        match RustConnection::connect(None) {
            Ok((conn, _)) if conn.extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME).ok().flatten().is_some() => {
                Support { context: true, typing: true, session: "x11", note: None }
            }
            Ok(_) => Support {
                context: true,
                typing: false,
                session: "x11",
                note: Some("The X server has no XTEST extension, so PEVV cannot type into other programs.".into()),
            },
            Err(_) => Support { context: false, typing: false, session: "other", note: Some("No X11 display was found.".into()) },
        }
    }

    fn foreground(&self) -> Result<Target, CtxError> {
        if wayland_now() {
            return Err(CtxError::Unsupported);
        }
        let (conn, screen) = RustConnection::connect(None).map_err(fail)?;
        let root = conn.setup().roots[screen].root;
        let active = conn.get_property(false, root, atom(&conn, "_NET_ACTIVE_WINDOW")?, AtomEnum::WINDOW, 0, 1).map_err(fail)?.reply().map_err(fail)?;
        let win = active.value32().and_then(|mut v| v.next()).filter(|w| *w != 0).ok_or(CtxError::NoWindow)?;
        let utf8 = atom(&conn, "UTF8_STRING")?;
        let title = {
            let r = conn.get_property(false, win, atom(&conn, "_NET_WM_NAME")?, utf8, 0, 1024).map_err(fail)?.reply().map_err(fail)?;
            if r.value.is_empty() {
                let r = conn.get_property(false, win, AtomEnum::WM_NAME, AtomEnum::STRING, 0, 1024).map_err(fail)?.reply().map_err(fail)?;
                r.value.iter().map(|b| *b as char).collect()
            } else {
                String::from_utf8_lossy(&r.value).into_owned()
            }
        };
        let pid = conn
            .get_property(false, win, atom(&conn, "_NET_WM_PID")?, AtomEnum::CARDINAL, 0, 1)
            .map_err(fail)?
            .reply()
            .map_err(fail)?
            .value32()
            .and_then(|mut v| v.next())
            .unwrap_or(0);
        let exe =
            if pid != 0 { std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default() } else { String::new() };
        // X11 has no privilege levels between clients: XTEST reaches every window.
        Ok(Target { handle: u64::from(win), pid, title, exe, elevated: false })
    }

    fn send(&self, action: &Action) -> Result<(), TypeError> {
        if wayland_now() {
            return Err(TypeError::Unsupported);
        }
        let (conn, screen) = RustConnection::connect(None).map_err(tfail)?;
        let root = conn.setup().roots[screen].root;
        let keys: Vec<u32> = match action {
            Action::Key(Key::Tab) => vec![XK_TAB],
            Action::Key(Key::Enter) => vec![XK_RETURN],
            Action::Text(t) => t.chars().filter(|c| *c != '\r').map(keysym_of).collect(),
            Action::Delay(_) => return Ok(()),
        };
        let setup = conn.setup();
        let (min, max) = (setup.min_keycode, setup.max_keycode);
        let map = conn.get_keyboard_mapping(min, max - min + 1).map_err(tfail)?.reply().map_err(tfail)?;
        let per = map.keysyms_per_keycode as usize;
        // A key with no symbols at all is free to borrow; else the last one.
        let scratch = (min..=max).rev().find(|k| map.keysyms[(*k - min) as usize * per..][..per].iter().all(|s| *s == 0)).unwrap_or(max);
        let shift_code = match plan_key(min, per, &map.keysyms, XK_SHIFT_L) {
            Plan::Existing { keycode, .. } => Some(keycode),
            Plan::Scratch => None,
        };
        let tap = |code: u8, with_shift: bool| -> Result<(), TypeError> {
            let fake = |kind: u8, c: u8| conn.xtest_fake_input(kind, c, 0, root, 0, 0, 0).map(|_| ()).map_err(tfail);
            if let (true, Some(s)) = (with_shift, shift_code) {
                fake(KEY_PRESS_EVENT, s)?;
            }
            fake(KEY_PRESS_EVENT, code)?;
            fake(KEY_RELEASE_EVENT, code)?;
            if let (true, Some(s)) = (with_shift, shift_code) {
                fake(KEY_RELEASE_EVENT, s)?;
            }
            Ok(())
        };
        let sync = || conn.get_input_focus().map_err(tfail)?.reply().map(|_| ()).map_err(tfail);
        let mut borrowed = false;
        let mut result = Ok(());
        for ks in keys {
            let step = match plan_key(min, per, &map.keysyms, ks) {
                Plan::Existing { keycode, shift } => tap(keycode, shift),
                Plan::Scratch => {
                    borrowed = true;
                    conn.change_keyboard_mapping(1, scratch, 1, &[ks]).map_err(tfail).and_then(|_| sync()).and_then(|()| {
                        // Give the receiving program a moment to reload its keymap.
                        std::thread::sleep(std::time::Duration::from_millis(8));
                        tap(scratch, false)
                    })
                }
            };
            if let Err(e) = step.and_then(|()| sync()) {
                result = Err(e);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(4));
        }
        if borrowed {
            // Hand the spare key back empty.
            let _ = conn.change_keyboard_mapping(1, scratch, 1, &[0]);
        }
        let _ = conn.flush();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wayland_is_detected_from_the_session() {
        assert!(is_wayland(Some("wayland"), None, Some(":0")));
        assert!(is_wayland(Some("Wayland"), None, None));
        assert!(is_wayland(None, Some("wayland-0"), None), "no X display at all");
        assert!(!is_wayland(Some("x11"), None, Some(":0")));
        assert!(!is_wayland(None, None, Some(":0")));
        assert!(!is_wayland(None, Some(""), Some(":0")));
    }

    #[test]
    fn keysyms() {
        assert_eq!(keysym_of('a'), 0x61);
        assert_eq!(keysym_of('é'), 0xe9);
        assert_eq!(keysym_of('€'), 0x0100_20ac);
        assert_eq!(keysym_of('\n'), XK_RETURN);
        assert_eq!(keysym_of('\t'), XK_TAB);
    }

    #[test]
    fn plans_use_an_existing_key_when_there_is_one() {
        // Keys 8.. with 2 symbols each: 8 -> a/A, 9 -> b/B, 10 -> (empty), 11 -> Shift_L.
        let syms = [0x61, 0x41, 0x62, 0x42, 0, 0, XK_SHIFT_L, 0];
        assert_eq!(plan_key(8, 2, &syms, 0x61), Plan::Existing { keycode: 8, shift: false });
        assert_eq!(plan_key(8, 2, &syms, 0x42), Plan::Existing { keycode: 9, shift: true });
        assert_eq!(plan_key(8, 2, &syms, XK_SHIFT_L), Plan::Existing { keycode: 11, shift: false });
        assert_eq!(plan_key(8, 2, &syms, 0x0100_20ac), Plan::Scratch);
        assert_eq!(plan_key(8, 2, &syms, 0), Plan::Scratch, "symbol 0 means no key");
    }
}
