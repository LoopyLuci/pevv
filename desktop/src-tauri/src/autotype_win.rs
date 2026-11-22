//! Auto-type on Windows: read the foreground window (`GetForegroundWindow`, `GetWindowTextW`,
//! `QueryFullProcessImageNameW`) and type with `SendInput` and KEYEVENTF_UNICODE, so what is
//! typed does not depend on the keyboard layout. Not covered by unit tests (they would have to
//! type into a real window); `autotype_core` is, with a mock of this layer.
//!
//! Every injected key carries `dwExtraInfo = MARK`, so a program that watches input (or a
//! future PEVV hook) can tell it is ours. No key, character or window text is ever logged here.
//!
//! A window of higher integrity than PEVV (an elevated program, the UAC prompt) is reported as
//! `elevated`: Windows (UIPI) drops input aimed at it, so we say so instead of pretending.

use crate::autotype_core::{Action, CtxError, Key, Platform, Support, Target, TypeError};
use std::mem::size_of;
use std::time::{Duration, Instant};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, MapVirtualKeyW, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    MAPVK_VK_TO_VSC, VIRTUAL_KEY, VK_CONTROL, VK_LWIN, VK_MENU, VK_RETURN, VK_RWIN, VK_SHIFT, VK_TAB,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, SetForegroundWindow};

/// "PEVV": marks input that PEVV injected.
pub const MARK: usize = 0x5045_5656;
/// UTF-16 units per `SendInput` call, and the pause between calls (some programs drop a flood).
const BATCH: usize = 24;
const PAUSE: Duration = Duration::from_millis(6);

pub struct Win;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful Open* call and is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// The mandatory integrity level (RID) of a process token, or `None` if it cannot be read.
fn integrity_of(process: HANDLE) -> Option<u32> {
    // SAFETY: standard token query; the buffer is u64-aligned and sized by the first call.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut token).ok()?;
        let token = Handle(token);
        let mut len = 0u32;
        let _ = GetTokenInformation(token.0, TokenIntegrityLevel, None, 0, &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        GetTokenInformation(token.0, TokenIntegrityLevel, Some(buf.as_mut_ptr().cast()), len, &mut len).ok()?;
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return None;
        }
        Some(*GetSidSubAuthority(sid, u32::from(count) - 1))
    }
}

fn own_integrity() -> u32 {
    // SAFETY: the pseudo-handle of the current process needs no closing.
    integrity_of(unsafe { GetCurrentProcess() }).unwrap_or(0x2000)
}

fn title_of(hwnd: HWND) -> String {
    // SAFETY: the buffer is sized from GetWindowTextLengthW (+ the terminator).
    unsafe {
        let n = GetWindowTextLengthW(hwnd);
        if n <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; n as usize + 1];
        let got = GetWindowTextW(hwnd, &mut buf);
        String::from_utf16_lossy(&buf[..got.max(0) as usize])
    }
}

impl Platform for Win {
    fn support(&self) -> Support {
        Support { context: true, typing: true, session: "windows", note: None }
    }

    fn foreground(&self) -> Result<Target, CtxError> {
        // SAFETY: plain Win32 queries; handles are closed by `Handle`.
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return Err(CtxError::NoWindow);
            }
            let mut pid = 0u32;
            if GetWindowThreadProcessId(hwnd, Some(&mut pid)) == 0 || pid == 0 {
                return Err(CtxError::NoWindow);
            }
            let title = title_of(hwnd);
            let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                // A process we cannot even query is protected or elevated: we could not type into it.
                return Ok(Target { handle: hwnd.0 as usize as u64, pid, title, exe: String::new(), elevated: true });
            };
            let process = Handle(process);
            let mut buf = vec![0u16; 32 * 1024];
            let mut len = buf.len() as u32;
            let exe = QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
                .map(|()| String::from_utf16_lossy(&buf[..len as usize]))
                .unwrap_or_default();
            let elevated = match integrity_of(process.0) {
                Some(rid) => rid > own_integrity(),
                None => true,
            };
            Ok(Target { handle: hwnd.0 as usize as u64, pid, title, exe, elevated })
        }
    }

    fn refocus(&self, target: &Target) {
        // SAFETY: the handle is only a window id; a stale one makes the call fail harmlessly.
        unsafe {
            let _ = SetForegroundWindow(HWND(target.handle as usize as *mut core::ffi::c_void));
        }
        std::thread::sleep(Duration::from_millis(150));
    }

    fn wait_modifiers_released(&self) -> Result<(), TypeError> {
        let held = || [VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN].iter().any(|k| (unsafe { GetAsyncKeyState(i32::from(k.0)) } as u16) & 0x8000 != 0);
        let started = Instant::now();
        while held() {
            if started.elapsed() > Duration::from_secs(3) {
                return Err(TypeError::ModifiersHeld);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Ok(())
    }

    fn send(&self, action: &Action) -> Result<(), TypeError> {
        match action {
            Action::Key(k) => press(key_vk(*k)),
            Action::Text(t) => {
                let mut units: Vec<u16> = Vec::new();
                for c in t.chars() {
                    match c {
                        '\r' => {}
                        '\n' => {
                            flush(&mut units)?;
                            press(VK_RETURN)?;
                        }
                        '\t' => {
                            flush(&mut units)?;
                            press(VK_TAB)?;
                        }
                        c => {
                            let mut b = [0u16; 2];
                            units.extend_from_slice(c.encode_utf16(&mut b));
                        }
                    }
                }
                flush(&mut units)
            }
            Action::Delay(_) => Ok(()),
        }
    }
}

fn key_vk(k: Key) -> VIRTUAL_KEY {
    match k {
        Key::Tab => VK_TAB,
        Key::Enter => VK_RETURN,
    }
}

fn kb(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: MARK } } }
}

fn submit(inputs: &[INPUT]) -> Result<(), TypeError> {
    // SAFETY: `inputs` is a valid slice of fully initialised INPUT structures.
    let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };
    if sent as usize == inputs.len() {
        Ok(())
    } else {
        // Fewer events than asked for: another desktop is active or UIPI dropped them.
        Err(TypeError::Blocked)
    }
}

fn press(vk: VIRTUAL_KEY) -> Result<(), TypeError> {
    // SAFETY: MapVirtualKeyW has no preconditions.
    let scan = unsafe { MapVirtualKeyW(u32::from(vk.0), MAPVK_VK_TO_VSC) } as u16;
    submit(&[kb(vk, scan, KEYBD_EVENT_FLAGS(0)), kb(vk, scan, KEYEVENTF_KEYUP)])?;
    std::thread::sleep(PAUSE);
    Ok(())
}

/// Type UTF-16 units as Unicode key events (down + up each), in batches, then clear `units`.
fn flush(units: &mut Vec<u16>) -> Result<(), TypeError> {
    for chunk in units.chunks(BATCH) {
        let mut inputs = Vec::with_capacity(chunk.len() * 2);
        for u in chunk {
            inputs.push(kb(VIRTUAL_KEY(0), *u, KEYEVENTF_UNICODE));
            inputs.push(kb(VIRTUAL_KEY(0), *u, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
        }
        submit(&inputs)?;
        std::thread::sleep(PAUSE);
    }
    units.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading the foreground window is safe to run anywhere; typing is not tested (see the module docs).
    #[test]
    fn the_foreground_window_can_be_read_or_there_is_none() {
        match Win.foreground() {
            Ok(t) => {
                assert!(t.pid != 0);
                assert!(t.handle != 0);
            }
            Err(e) => assert_eq!(e, CtxError::NoWindow),
        }
    }

    #[test]
    fn our_own_integrity_level_is_readable() {
        assert!(own_integrity() >= 0x1000, "at least low integrity");
    }

    #[test]
    fn the_mark_is_pevv() {
        assert!(MARK.to_be_bytes().ends_with(b"PEVV"));
    }
}
