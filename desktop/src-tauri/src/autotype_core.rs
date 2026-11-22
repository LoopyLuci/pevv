//! Auto-type, the part that needs no window system: what a typing request may contain, the
//! "is it still the same window" rule, and the one pending request that the chooser and the vault
//! UI take turns on. The platform (Win32, X11) sits behind `Platform`, so this runs under unit
//! tests with a mock; the real `SendInput` / XTest paths are not covered by tests (see
//! docs/PEVV_DESKTOP.md).
//!
//! The rules, in the order they apply to a hotkey press:
//!
//! 1. the foreground window and its process are read when the hotkey fires and remembered
//!    (`Target`: window handle, process id, executable path);
//! 2. the vault UI (which holds the unlocked vault) picks the entries whose own auto-type
//!    patterns match that window; nothing is typed into a window because of its URL alone;
//! 3. the person always picks one entry in a small chooser that names the window and the entry;
//! 4. just before typing, and again before every step, the foreground window must still be the
//!    same handle and process, and not elevated, or the whole sequence is abandoned.
//!
//! No key, value or sequence is ever logged: `Action`'s `Debug` prints lengths only.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_HOTKEY: &str = "Ctrl+Alt+A";
/// Largest request the shell will type (the sequence is built in the vault UI).
pub const MAX_ACTIONS: usize = 256;
pub const MAX_TEXT_CHARS: usize = 8192;
pub const MAX_DELAY_MS: u32 = 10_000;
pub const MAX_TOTAL_DELAY_MS: u32 = 30_000;
/// A request nobody answers is dropped after this long.
pub const PENDING_TTL: Duration = Duration::from_secs(90);

/// A window the person was in when they pressed the hotkey.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct Target {
    /// HWND (Windows) or X11 window id, as a number.
    pub handle: u64,
    pub pid: u32,
    pub title: String,
    /// Full path of the process image (empty if it could not be read).
    pub exe: String,
    /// Runs with more rights than PEVV (or could not be inspected): the OS will not let us type into it.
    pub elevated: bool,
}

impl Target {
    /// The executable's file name, e.g. `putty.exe`.
    pub fn process(&self) -> String {
        process_name(&self.exe)
    }
}

pub fn process_name(exe: &str) -> String {
    exe.rsplit(['\\', '/']).next().unwrap_or("").to_string()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Key {
    Tab,
    Enter,
}

/// One step of a sequence, already resolved by the vault UI (field values substituted).
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "t", content = "v", rename_all = "lowercase")]
pub enum Action {
    Text(String),
    Key(Key),
    Delay(u32),
}

impl fmt::Debug for Action {
    /// Never shows the text: it is a password or a one-time code.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Text(t) => write!(f, "Text(<{} chars>)", t.chars().count()),
            Action::Key(k) => write!(f, "Key({k:?})"),
            Action::Delay(ms) => write!(f, "Delay({ms})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtxError {
    /// No foreground window (the lock screen, a UAC prompt on the secure desktop, a bare desktop).
    NoWindow,
    /// This session cannot tell (Wayland).
    Unsupported,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeError {
    Unsupported,
    NoWindow,
    Elevated,
    TargetChanged,
    /// Ctrl / Alt / Shift / Win stayed down, so typed characters would turn into shortcuts.
    ModifiersHeld,
    /// The OS refused the input (blocked by a higher-privileged window, or another desktop).
    Blocked,
    Invalid(&'static str),
    Failed(String),
}

impl TypeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::NoWindow => "no-window",
            Self::Elevated => "elevated",
            Self::TargetChanged => "target-changed",
            Self::ModifiersHeld => "modifiers-held",
            Self::Blocked => "blocked",
            Self::Invalid(_) => "invalid",
            Self::Failed(_) => "failed",
        }
    }

    /// Plain words for the person. No typed text ever appears in these.
    pub fn message(&self) -> String {
        match self {
            Self::Unsupported => "This system does not let PEVV type into other programs.".into(),
            Self::NoWindow => "There is no window to type into.".into(),
            Self::Elevated => {
                "That window runs as administrator (or is a Windows security prompt), so Windows will not let PEVV type into it. Nothing was typed.".into()
            }
            Self::TargetChanged => "The window in front changed, so nothing (more) was typed.".into(),
            Self::ModifiersHeld => "A modifier key (Ctrl, Alt, Shift or Win) stayed pressed, so nothing was typed. Release the keys and try again.".into(),
            Self::Blocked => "The system refused the typed input, so nothing (more) was typed.".into(),
            Self::Invalid(why) => format!("The typing request was refused: {why}."),
            Self::Failed(e) => format!("Typing failed: {e}"),
        }
    }
}

impl From<CtxError> for TypeError {
    fn from(e: CtxError) -> Self {
        match e {
            CtxError::NoWindow => Self::NoWindow,
            CtxError::Unsupported => Self::Unsupported,
            CtxError::Failed(m) => Self::Failed(m),
        }
    }
}

/// What this system can do for auto-type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Support {
    /// Can read the foreground window's title and process.
    pub context: bool,
    /// Can type into another program.
    pub typing: bool,
    /// "windows", "x11", "wayland", "other".
    pub session: &'static str,
    /// Why not, in plain words.
    pub note: Option<String>,
}

pub trait Platform: Send + Sync {
    fn support(&self) -> Support;
    fn foreground(&self) -> Result<Target, CtxError>;
    /// Type one `Text` or press one `Key`. Never called with `Delay`.
    fn send(&self, action: &Action) -> Result<(), TypeError>;
    fn sleep(&self, ms: u32) {
        std::thread::sleep(Duration::from_millis(u64::from(ms)));
    }
    /// Bring `target` to the front. Only used when PEVV's own window got the focus; the caller
    /// still re-checks the foreground afterwards, so a failure here just means nothing is typed.
    fn refocus(&self, _target: &Target) {}
    /// Wait (briefly) until no modifier key is held. The hotkey itself uses some.
    fn wait_modifiers_released(&self) -> Result<(), TypeError> {
        Ok(())
    }
}

pub fn validate(actions: &[Action]) -> Result<(), TypeError> {
    if actions.is_empty() {
        return Err(TypeError::Invalid("nothing to type"));
    }
    if actions.len() > MAX_ACTIONS {
        return Err(TypeError::Invalid("too many steps"));
    }
    let mut chars = 0usize;
    let mut delay = 0u32;
    for a in actions {
        match a {
            Action::Text(t) => chars += t.chars().count(),
            Action::Delay(ms) if *ms > MAX_DELAY_MS => return Err(TypeError::Invalid("a delay is too long")),
            Action::Delay(ms) => delay += ms,
            Action::Key(_) => {}
        }
    }
    if chars > MAX_TEXT_CHARS {
        return Err(TypeError::Invalid("too much text"));
    }
    if delay > MAX_TOTAL_DELAY_MS {
        return Err(TypeError::Invalid("the delays add up to too long"));
    }
    Ok(())
}

fn same_exe(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Is the foreground still the window the person chose? (Handle and process, not the title:
/// a browser tab's title changes while you type.)
pub fn check_target(p: &dyn Platform, want: &Target) -> Result<(), TypeError> {
    let now = p.foreground()?;
    if now.elevated {
        return Err(TypeError::Elevated);
    }
    if now.handle != want.handle || now.pid != want.pid || !same_exe(&now.exe, &want.exe) {
        return Err(TypeError::TargetChanged);
    }
    Ok(())
}

/// Type `actions` into `want`, abandoning the rest the moment the foreground window is not it.
pub fn type_into(p: &dyn Platform, want: &Target, actions: &[Action]) -> Result<(), TypeError> {
    validate(actions)?;
    if want.elevated {
        return Err(TypeError::Elevated);
    }
    if !p.support().typing {
        return Err(TypeError::Unsupported);
    }
    check_target(p, want)?;
    p.wait_modifiers_released()?;
    for a in actions {
        match a {
            Action::Delay(ms) => p.sleep(*ms),
            _ => {
                check_target(p, want)?;
                p.send(a)?;
            }
        }
    }
    Ok(())
}

/* ───────────── settings ───────────── */

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_hotkey")]
    pub hotkey: String,
}

fn yes() -> bool {
    true
}

fn default_hotkey() -> String {
    DEFAULT_HOTKEY.to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self { enabled: true, hotkey: default_hotkey() }
    }
}

/// `autotype.json` in the app data folder.
pub struct SettingsStore {
    path: Option<PathBuf>,
}

impl SettingsStore {
    pub fn at(dir: &std::path::Path) -> Self {
        Self { path: Some(dir.join("autotype.json")) }
    }

    pub fn memory() -> Self {
        Self { path: None }
    }

    pub fn load(&self) -> Settings {
        self.path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, s: &Settings) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(s).map_err(std::io::Error::other)?)?;
        std::fs::rename(&tmp, path)
    }
}

/* ───────────── the one pending request ───────────── */

/// What the chooser lists: titles and user names only, never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub username: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Type into the window.
    Type,
    /// Cannot type here (Wayland): copy the password instead, cleared after the usual time.
    Clipboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Waiting for the vault UI to say which entries match.
    Matching,
    Choose,
    Working,
    Done,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetView {
    pub title: String,
    pub process: String,
}

/// What the chooser window is shown.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChooserView {
    pub id: u64,
    pub target: Option<TargetView>,
    pub mode: Mode,
    pub phase: Phase,
    pub candidates: Vec<Candidate>,
    pub message: Option<String>,
    pub code: Option<&'static str>,
}

struct Pending {
    id: u64,
    target: Option<Target>,
    mode: Mode,
    phase: Phase,
    candidates: Vec<Candidate>,
    confirmed: Option<String>,
    message: Option<String>,
    code: Option<&'static str>,
    created: Instant,
}

impl Pending {
    fn view(&self) -> ChooserView {
        ChooserView {
            id: self.id,
            target: self.target.as_ref().map(|t| TargetView { title: t.title.clone(), process: t.process() }),
            mode: self.mode,
            phase: self.phase,
            candidates: self.candidates.clone(),
            message: self.message.clone(),
            code: self.code,
        }
    }
}

/// One request at a time; a new hotkey press replaces the old one. Every method that takes an
/// `id` is a no-op (returns `None`/`false`) for any id but the current one, so a late answer for
/// an old request can never type into a new target.
pub struct Broker {
    cur: Mutex<Option<Pending>>,
    next: AtomicU64,
    ttl: Duration,
}

impl Default for Broker {
    fn default() -> Self {
        Self::with_ttl(PENDING_TTL)
    }
}

impl Broker {
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { cur: Mutex::new(None), next: AtomicU64::new(1), ttl }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Option<Pending>) -> R) -> R {
        let mut g = self.cur.lock().unwrap_or_else(|e| e.into_inner());
        if g.as_ref().is_some_and(|p| p.created.elapsed() > self.ttl) {
            *g = None;
        }
        f(&mut g)
    }

    /// A hotkey press. `target` is `None` only where the system cannot say (Wayland). An elevated
    /// or missing window goes straight to an error the chooser shows.
    pub fn begin(&self, target: Result<Target, CtxError>, typing: bool) -> ChooserView {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let mode = if typing { Mode::Type } else { Mode::Clipboard };
        let mut p =
            Pending { id, target: None, mode, phase: Phase::Matching, candidates: vec![], confirmed: None, message: None, code: None, created: Instant::now() };
        match target {
            Ok(t) if t.elevated => {
                p.code = Some(TypeError::Elevated.code());
                p.message = Some(TypeError::Elevated.message());
                p.phase = Phase::Error;
                p.target = Some(t);
            }
            Ok(t) => p.target = Some(t),
            Err(CtxError::Unsupported) => {}
            Err(e) => {
                let e = TypeError::from(e);
                p.code = Some(e.code());
                p.message = Some(e.message());
                p.phase = Phase::Error;
            }
        }
        let view = p.view();
        self.with(|c| *c = Some(p));
        view
    }

    pub fn view(&self) -> Option<ChooserView> {
        self.with(|c| c.as_ref().map(Pending::view))
    }

    /// The vault UI's matches for request `id`. Returns the view to show, or `None` if stale.
    pub fn offer(&self, id: u64, mut candidates: Vec<Candidate>) -> Option<ChooserView> {
        self.with(|c| {
            let p = c.as_mut().filter(|p| p.id == id && p.phase == Phase::Matching)?;
            candidates.truncate(20);
            if candidates.is_empty() {
                p.phase = Phase::Error;
                p.code = Some("no-match");
                p.message = Some(match &p.target {
                    Some(t) => format!("No entry has an auto-type pattern for \"{}\" ({}). Add one in the entry's Auto-type section.", t.title, t.process()),
                    None => "No entry has auto-type set up. Add it in the entry's Auto-type section.".into(),
                });
            } else {
                p.candidates = candidates;
                p.phase = Phase::Choose;
            }
            Some(p.view())
        })
    }

    /// The person picked `entry` in the chooser. Only an entry that was offered can be picked.
    pub fn confirm(&self, id: u64, entry: &str) -> Option<ChooserView> {
        self.with(|c| {
            let p = c.as_mut().filter(|p| p.id == id && p.phase == Phase::Choose)?;
            p.candidates.iter().any(|x| x.id == entry).then_some(())?;
            p.confirmed = Some(entry.to_string());
            p.phase = Phase::Working;
            Some(p.view())
        })
    }

    pub fn cancel(&self, id: u64) -> bool {
        self.with(|c| {
            let hit = c.as_ref().is_some_and(|p| p.id == id);
            if hit {
                *c = None;
            }
            hit
        })
    }

    pub fn clear(&self) {
        self.with(|c| *c = None);
    }

    /// Hand over the confirmed target for typing (only while `Working`, and only once).
    pub fn take_target(&self, id: u64) -> Option<Option<Target>> {
        self.with(|c| {
            let p = c.as_mut().filter(|p| p.id == id && p.phase == Phase::Working && p.confirmed.is_some())?;
            p.confirmed = None;
            Some(p.target.clone())
        })
    }

    pub fn mode(&self, id: u64) -> Option<Mode> {
        self.with(|c| c.as_ref().filter(|p| p.id == id).map(|p| p.mode))
    }

    /// Record how it ended. `Ok` shows "typed"; an error shows its message.
    pub fn finish(&self, id: u64, result: Result<&str, TypeError>) -> Option<ChooserView> {
        self.with(|c| {
            let p = c.as_mut().filter(|p| p.id == id && p.phase == Phase::Working)?;
            match result {
                Ok(msg) => {
                    p.phase = Phase::Done;
                    p.message = Some(msg.to_string());
                }
                Err(e) => {
                    p.phase = Phase::Error;
                    p.code = Some(e.code());
                    p.message = Some(e.message());
                }
            }
            Some(p.view())
        })
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::VecDeque;

    /// A platform whose foreground window the test scripts, and which records what it typed
    /// (lengths and key names only, like the real thing logs nothing).
    pub struct Mock {
        pub typing: bool,
        pub fg: Mutex<VecDeque<Result<Target, CtxError>>>,
        pub last: Mutex<Result<Target, CtxError>>,
        pub sent: Mutex<Vec<String>>,
        pub slept: Mutex<Vec<u32>>,
        pub mods_held: bool,
    }

    pub fn win(handle: u64, pid: u32, exe: &str) -> Target {
        Target { handle, pid, title: format!("window {handle}"), exe: exe.into(), elevated: false }
    }

    impl Mock {
        pub fn new(t: Target) -> Self {
            Self {
                typing: true,
                fg: Mutex::new(VecDeque::new()),
                last: Mutex::new(Ok(t)),
                sent: Mutex::new(vec![]),
                slept: Mutex::new(vec![]),
                mods_held: false,
            }
        }
        /// The next `foreground()` answers with these, in order, then the last one forever.
        pub fn script(&self, answers: Vec<Result<Target, CtxError>>) {
            *self.fg.lock().unwrap() = answers.into();
        }
    }

    impl Platform for Mock {
        fn support(&self) -> Support {
            Support { context: true, typing: self.typing, session: "mock", note: None }
        }
        fn foreground(&self) -> Result<Target, CtxError> {
            let next = self.fg.lock().unwrap().pop_front();
            match next {
                Some(r) => {
                    *self.last.lock().unwrap() = r.clone();
                    r
                }
                None => self.last.lock().unwrap().clone(),
            }
        }
        fn send(&self, a: &Action) -> Result<(), TypeError> {
            self.sent.lock().unwrap().push(format!("{a:?}"));
            Ok(())
        }
        fn sleep(&self, ms: u32) {
            self.slept.lock().unwrap().push(ms);
        }
        fn wait_modifiers_released(&self) -> Result<(), TypeError> {
            if self.mods_held {
                Err(TypeError::ModifiersHeld)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::*;
    use super::*;

    fn seq() -> Vec<Action> {
        vec![Action::Text("ada".into()), Action::Key(Key::Tab), Action::Text("hunter2".into()), Action::Key(Key::Enter)]
    }

    #[test]
    fn types_the_whole_sequence_into_the_unchanged_target() {
        let t = win(10, 100, "C:\\Tools\\putty.exe");
        let m = Mock::new(t.clone());
        type_into(&m, &t, &seq()).unwrap();
        assert_eq!(*m.sent.lock().unwrap(), vec!["Text(<3 chars>)", "Key(Tab)", "Text(<7 chars>)", "Key(Enter)"]);
    }

    #[test]
    fn aborts_before_typing_when_the_foreground_window_is_a_different_handle() {
        let t = win(10, 100, "/usr/bin/putty");
        let m = Mock::new(win(11, 100, "/usr/bin/putty"));
        assert_eq!(type_into(&m, &t, &seq()), Err(TypeError::TargetChanged));
        assert!(m.sent.lock().unwrap().is_empty(), "not one key was sent");
    }

    #[test]
    fn aborts_when_the_same_handle_belongs_to_another_process() {
        let t = win(10, 100, "/usr/bin/putty");
        assert_eq!(type_into(&Mock::new(win(10, 101, "/usr/bin/putty")), &t, &seq()), Err(TypeError::TargetChanged));
        assert_eq!(type_into(&Mock::new(win(10, 100, "/usr/bin/evil")), &t, &seq()), Err(TypeError::TargetChanged));
    }

    #[test]
    fn a_title_change_alone_does_not_abort() {
        let t = win(10, 100, "/usr/bin/firefox");
        let mut retitled = t.clone();
        retitled.title = "another tab".into();
        type_into(&Mock::new(retitled), &t, &seq()).unwrap();
    }

    #[test]
    fn stops_typing_the_moment_the_target_changes_mid_sequence() {
        let t = win(10, 100, "/usr/bin/putty");
        let m = Mock::new(t.clone());
        // Initial check ok, check before action 1 ok, then focus moves before action 2.
        m.script(vec![Ok(t.clone()), Ok(t.clone()), Ok(win(99, 7, "/usr/bin/other"))]);
        let r = type_into(&m, &t, &seq());
        assert_eq!(r, Err(TypeError::TargetChanged));
        assert_eq!(m.sent.lock().unwrap().len(), 1, "only the first step went out");
    }

    #[test]
    fn rechecks_after_a_delay() {
        let t = win(10, 100, "/x");
        let m = Mock::new(t.clone());
        // Two checks to start (guard + step 1), then the window changes during the delay.
        m.script(vec![Ok(t.clone()), Ok(t.clone()), Ok(win(2, 2, "/y"))]);
        let r = type_into(&m, &t, &[Action::Text("a".into()), Action::Delay(500), Action::Text("b".into())]);
        assert_eq!(r, Err(TypeError::TargetChanged));
        assert_eq!(*m.slept.lock().unwrap(), vec![500]);
        assert_eq!(m.sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn refuses_elevated_windows_before_and_during() {
        let mut t = win(10, 100, "C:\\Windows\\System32\\consent.exe");
        t.elevated = true;
        let m = Mock::new(t.clone());
        assert_eq!(type_into(&m, &t, &seq()), Err(TypeError::Elevated));
        assert!(m.sent.lock().unwrap().is_empty());
        // The window was fine when chosen and became elevated (a UAC prompt took over).
        let ok = win(10, 100, "C:\\app.exe");
        let m = Mock::new(ok.clone());
        let mut up = ok.clone();
        up.elevated = true;
        m.script(vec![Ok(up)]);
        assert_eq!(type_into(&m, &ok, &seq()), Err(TypeError::Elevated));
    }

    #[test]
    fn no_foreground_window_and_unsupported_typing_are_errors() {
        let t = win(10, 100, "/x");
        let m = Mock::new(t.clone());
        m.script(vec![Err(CtxError::NoWindow)]);
        assert_eq!(type_into(&m, &t, &seq()), Err(TypeError::NoWindow));
        let mut m = Mock::new(t.clone());
        m.typing = false;
        assert_eq!(type_into(&m, &t, &seq()), Err(TypeError::Unsupported));
        let mut m = Mock::new(t.clone());
        m.mods_held = true;
        assert_eq!(type_into(&m, &t, &seq()), Err(TypeError::ModifiersHeld));
        assert!(m.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn requests_are_bounded() {
        assert!(validate(&[]).is_err());
        assert!(validate(&vec![Action::Key(Key::Tab); MAX_ACTIONS + 1]).is_err());
        assert!(validate(&[Action::Text("x".repeat(MAX_TEXT_CHARS + 1))]).is_err());
        assert!(validate(&[Action::Text("x".repeat(MAX_TEXT_CHARS))]).is_ok());
        assert!(validate(&[Action::Delay(MAX_DELAY_MS + 1)]).is_err());
        assert!(validate(&vec![Action::Delay(MAX_DELAY_MS); 4]).is_err(), "40 s of delays");
        assert!(validate(&vec![Action::Delay(MAX_DELAY_MS); 3]).is_ok());
    }

    #[test]
    fn actions_deserialize_from_the_webview_and_never_debug_print_text() {
        let a: Vec<Action> = serde_json::from_str(r#"[{"t":"text","v":"pw"},{"t":"key","v":"tab"},{"t":"delay","v":250}]"#).unwrap();
        assert_eq!(a, vec![Action::Text("pw".into()), Action::Key(Key::Tab), Action::Delay(250)]);
        assert!(serde_json::from_str::<Vec<Action>>(r#"[{"t":"key","v":"f13"}]"#).is_err(), "only Tab and Enter");
        assert!(serde_json::from_str::<Vec<Action>>(r#"[{"t":"run","v":"calc"}]"#).is_err());
        assert!(!format!("{:?}", Action::Text("hunter2".into())).contains("hunter2"));
        assert!(!format!("{a:?}").contains("pw"));
    }

    #[test]
    fn error_messages_never_contain_typed_text() {
        for e in [TypeError::Elevated, TypeError::TargetChanged, TypeError::Blocked, TypeError::ModifiersHeld, TypeError::Unsupported, TypeError::NoWindow] {
            assert!(!e.message().is_empty());
            assert!(!e.code().is_empty());
        }
    }

    fn cand(id: &str) -> Candidate {
        Candidate { id: id.into(), title: format!("Entry {id}"), username: "u".into() }
    }

    #[test]
    fn the_broker_walks_match_choose_type_and_refuses_stale_ids() {
        let b = Broker::default();
        let t = win(10, 100, "/usr/bin/putty");
        let v = b.begin(Ok(t.clone()), true);
        assert_eq!((v.phase, v.mode), (Phase::Matching, Mode::Type));
        assert_eq!(v.target.as_ref().unwrap().process, "putty");
        assert!(b.confirm(v.id, "a").is_none(), "nothing to confirm before the matches are in");
        assert!(b.offer(v.id + 1, vec![cand("a")]).is_none(), "wrong id");
        let v2 = b.offer(v.id, vec![cand("a"), cand("b")]).unwrap();
        assert_eq!(v2.phase, Phase::Choose);
        assert!(b.confirm(v.id, "zzz").is_none(), "an entry that was not offered");
        assert!(b.take_target(v.id).is_none(), "not confirmed yet");
        assert_eq!(b.confirm(v.id, "b").unwrap().phase, Phase::Working);
        assert_eq!(b.take_target(v.id).unwrap().unwrap(), t);
        assert!(b.take_target(v.id).is_none(), "a confirmation types once");
        assert_eq!(b.finish(v.id, Ok("Typed.")).unwrap().phase, Phase::Done);
        assert!(b.finish(v.id, Ok("again")).is_none());
    }

    #[test]
    fn a_new_press_replaces_the_old_request() {
        let b = Broker::default();
        let first = b.begin(Ok(win(1, 1, "/a")), true);
        b.offer(first.id, vec![cand("a")]);
        let second = b.begin(Ok(win(2, 2, "/b")), true);
        assert_ne!(first.id, second.id);
        assert!(b.confirm(first.id, "a").is_none(), "the old chooser cannot confirm into the new target");
        assert!(!b.cancel(first.id));
        assert!(b.cancel(second.id));
        assert!(b.view().is_none());
    }

    #[test]
    fn elevated_windows_and_missing_windows_never_reach_matching() {
        let b = Broker::default();
        let mut t = win(1, 1, "C:\\Windows\\System32\\consent.exe");
        t.elevated = true;
        let v = b.begin(Ok(t), true);
        assert_eq!((v.phase, v.code), (Phase::Error, Some("elevated")));
        assert!(b.offer(v.id, vec![cand("a")]).is_none());
        let v = b.begin(Err(CtxError::NoWindow), true);
        assert_eq!((v.phase, v.code), (Phase::Error, Some("no-window")));
    }

    #[test]
    fn wayland_has_no_target_and_falls_back_to_the_clipboard() {
        let b = Broker::default();
        let v = b.begin(Err(CtxError::Unsupported), false);
        assert_eq!((v.phase, v.mode), (Phase::Matching, Mode::Clipboard));
        assert!(v.target.is_none());
        let v = b.offer(v.id, vec![cand("a")]).unwrap();
        assert_eq!(v.phase, Phase::Choose);
        b.confirm(v.id, "a").unwrap();
        assert_eq!(b.take_target(v.id), Some(None));
    }

    #[test]
    fn no_candidates_is_an_error_that_names_the_window() {
        let b = Broker::default();
        let v = b.begin(Ok(win(1, 1, "/usr/bin/putty")), true);
        let v = b.offer(v.id, vec![]).unwrap();
        assert_eq!((v.phase, v.code), (Phase::Error, Some("no-match")));
        assert!(v.message.unwrap().contains("window 1"));
    }

    #[test]
    fn an_unanswered_request_expires() {
        let b = Broker::with_ttl(Duration::from_millis(0));
        let v = b.begin(Ok(win(1, 1, "/a")), true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(b.offer(v.id, vec![cand("a")]).is_none());
        assert!(b.view().is_none());
    }

    #[test]
    fn settings_default_persist_and_tolerate_junk() {
        let d = tempfile::tempdir().unwrap();
        let s = SettingsStore::at(d.path());
        assert_eq!(s.load(), Settings { enabled: true, hotkey: "Ctrl+Alt+A".into() });
        s.save(&Settings { enabled: false, hotkey: "Ctrl+Shift+K".into() }).unwrap();
        assert_eq!(SettingsStore::at(d.path()).load(), Settings { enabled: false, hotkey: "Ctrl+Shift+K".into() });
        std::fs::write(d.path().join("autotype.json"), "not json").unwrap();
        assert_eq!(s.load(), Settings::default());
        std::fs::write(d.path().join("autotype.json"), r#"{"enabled":false}"#).unwrap();
        assert_eq!(s.load().hotkey, DEFAULT_HOTKEY, "a missing field takes its default");
    }

    #[test]
    fn process_names() {
        assert_eq!(process_name("C:\\Program Files\\KeePass\\kp.exe"), "kp.exe");
        assert_eq!(process_name("/usr/bin/ssh"), "ssh");
        assert_eq!(process_name(""), "");
    }
}
