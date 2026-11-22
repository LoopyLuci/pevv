//! Auto-type, Tauri side: the global hotkey (only while the vault is unlocked), the small
//! always-on-top chooser window, and the hand-offs to the vault UI. The rules live in
//! `autotype_core` and are tested there; the platform layers are `autotype_win` / `autotype_x11`.
//!
//! The vault never leaves the main window: Rust reads the foreground window and sends only its
//! title and process to the vault UI, which matches its entries and answers with titles; the
//! chooser (a second window with no vault access) shows those titles; the person's pick goes back
//! to the vault UI, which resolves the sequence (user name, password, one-time code) and sends
//! the keys here to type. At that point, and before every step, the foreground window must still
//! be the one the person started in.

use crate::autotype_core::{
    type_into, Action, Broker, Candidate, ChooserView, Mode, Phase, Platform, Settings, SettingsStore, Support, TypeError, DEFAULT_HOTKEY,
};
use crate::link;
use serde::Serialize;
use serde_json::json;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

/// Rust asks the vault UI which entries match this window.
pub const EVENT_REQUEST: &str = "autotype-request";
/// The person picked an entry; the vault UI builds the keys and calls `autotype_type`.
pub const EVENT_RUN: &str = "autotype-run";
/// The chooser's content changed.
pub const EVENT_VIEW: &str = "autotype-view";
pub const CHOOSER: &str = "autotype";

#[cfg(not(any(windows, target_os = "linux")))]
mod other {
    use crate::autotype_core::{Action, CtxError, Platform, Support, Target, TypeError};

    pub struct NoPlatform;

    impl Platform for NoPlatform {
        fn support(&self) -> Support {
            Support { context: false, typing: false, session: "other", note: Some("Auto-type is available on Windows and Linux (X11).".into()) }
        }
        fn foreground(&self) -> Result<Target, CtxError> {
            Err(CtxError::Unsupported)
        }
        fn send(&self, _action: &Action) -> Result<(), TypeError> {
            Err(TypeError::Unsupported)
        }
    }
}

pub fn platform() -> Arc<dyn Platform> {
    #[cfg(windows)]
    return Arc::new(crate::autotype_win::Win);
    #[cfg(target_os = "linux")]
    return Arc::new(crate::autotype_x11::Linux);
    #[cfg(not(any(windows, target_os = "linux")))]
    return Arc::new(other::NoPlatform);
}

pub struct AutoType {
    platform: Arc<dyn Platform>,
    pub broker: Broker,
    store: SettingsStore,
    settings: Mutex<Settings>,
    registered: Mutex<Option<Shortcut>>,
    error: Mutex<Option<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    enabled: bool,
    hotkey: String,
    default_hotkey: &'static str,
    /// The hotkey is live right now (needs the vault unlocked).
    registered: bool,
    error: Option<String>,
    support: Support,
}

#[derive(Serialize)]
pub struct AutoTypeError {
    code: &'static str,
    message: String,
}

impl From<TypeError> for AutoTypeError {
    fn from(e: TypeError) -> Self {
        Self { code: e.code(), message: e.message() }
    }
}

/// A hotkey that needs at least one of Ctrl, Alt or Win/Super, so it cannot swallow ordinary typing.
pub fn parse_hotkey(text: &str) -> Result<Shortcut, String> {
    if text.len() > 40 {
        return Err("That shortcut is too long.".into());
    }
    let sc = Shortcut::from_str(text.trim()).map_err(|_| "That is not a shortcut PEVV understands. Try something like Ctrl+Alt+A.".to_string())?;
    if !sc.mods.intersects(Modifiers::CONTROL | Modifiers::ALT | Modifiers::SUPER) {
        return Err("Use Ctrl, Alt or Win in the shortcut, so it cannot interfere with normal typing.".into());
    }
    Ok(sc)
}

impl AutoType {
    fn new(dir: &std::path::Path) -> Arc<Self> {
        let store = SettingsStore::at(dir);
        let settings = store.load();
        Arc::new(Self {
            platform: platform(),
            broker: Broker::default(),
            store,
            settings: Mutex::new(settings),
            registered: Mutex::new(None),
            error: Mutex::new(None),
        })
    }

    fn view(&self) -> SettingsView {
        let s = self.settings.lock().map(|s| s.clone()).unwrap_or_default();
        SettingsView {
            enabled: s.enabled,
            hotkey: s.hotkey,
            default_hotkey: DEFAULT_HOTKEY,
            registered: self.registered.lock().map(|r| r.is_some()).unwrap_or(false),
            error: self.error.lock().ok().and_then(|e| e.clone()),
            support: self.platform.support(),
        }
    }
}

fn unlocked(app: &AppHandle) -> bool {
    app.try_state::<Arc<link::Runtime>>().is_some_and(|rt| rt.ui.is_unlocked())
}

/// Make the registered hotkey match "enabled and unlocked". Called on every lock change and
/// every settings change. Locking also drops any request in flight and closes the chooser.
pub fn sync(app: &AppHandle) {
    let Some(at) = app.try_state::<Arc<AutoType>>() else { return };
    let at: Arc<AutoType> = at.inner().clone();
    let want = unlocked(app) && at.settings.lock().map(|s| s.enabled).unwrap_or(false);
    let gs = app.global_shortcut();
    if let Ok(mut reg) = at.registered.lock() {
        if let Some(old) = reg.take() {
            let _ = gs.unregister(old);
        }
        if want {
            let hotkey = at.settings.lock().map(|s| s.hotkey.clone()).unwrap_or_default();
            match parse_hotkey(&hotkey) {
                Ok(sc) => {
                    let result = gs.on_shortcut(sc, |app, _sc, ev| {
                        if ev.state == ShortcutState::Pressed {
                            let app = app.clone();
                            // Off the shortcut thread: reading windows and building a window can take a moment.
                            std::thread::spawn(move || on_hotkey(&app));
                        }
                    });
                    match result {
                        Ok(()) => {
                            *reg = Some(sc);
                            if let Ok(mut e) = at.error.lock() {
                                *e = None;
                            }
                        }
                        Err(e) => {
                            if let Ok(mut slot) = at.error.lock() {
                                *slot = Some(format!(
                                    "The shortcut {hotkey} could not be registered ({e}). Another program may be using it; choose a different one."
                                ));
                            }
                        }
                    }
                }
                Err(msg) => {
                    if let Ok(mut e) = at.error.lock() {
                        *e = Some(msg);
                    }
                }
            }
        }
    }
    if !want {
        at.broker.clear();
        close_chooser(app);
    }
}

fn close_chooser(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(CHOOSER) {
        let _ = w.destroy();
    }
}

/// The chooser, created the first time it is needed, always on top and never taking focus (so the
/// window the person is typing into stays in front, and the re-check before typing can pass).
fn show_chooser(app: &AppHandle, view: &ChooserView) {
    if let Some(w) = app.get_webview_window(CHOOSER) {
        let _ = app.emit_to(CHOOSER, EVENT_VIEW, view);
        let _ = w.show();
        return;
    }
    let mut builder = WebviewWindowBuilder::new(app, CHOOSER, WebviewUrl::App("index.html".into()));
    // With PEVV_DATA_DIR the chooser shares the vault window's webview profile, not the installed app's.
    if let Some(d) = crate::datadir::override_dir() {
        builder = builder.data_directory(d.join("webview"));
    }
    let built = builder
        .title("PEVV auto-type")
        .inner_size(380.0, 300.0)
        .resizable(false)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .focusable(false)
        .focused(false)
        .center()
        .initialization_script("window.__PEVV_CHOOSER__ = true;")
        .build();
    if built.is_ok() {
        let _ = app.emit_to(CHOOSER, EVENT_VIEW, view);
    }
}

fn on_hotkey(app: &AppHandle) {
    let Some(at) = app.try_state::<Arc<AutoType>>() else { return };
    if !unlocked(app) {
        return;
    }
    let sup = at.platform.support();
    let ctx = at.platform.foreground();
    // Pressed while PEVV itself (or its chooser) is in front: there is nothing to type into.
    if matches!(&ctx, Ok(t) if t.pid == std::process::id()) {
        return;
    }
    let view = at.broker.begin(ctx, sup.typing);
    if view.phase == Phase::Matching {
        let (title, process) = view.target.as_ref().map(|t| (t.title.clone(), t.process.clone())).unwrap_or_default();
        let _ =
            app.emit_to("main", EVENT_REQUEST, json!({ "id": view.id, "title": title, "process": process, "known": view.target.is_some(), "mode": view.mode }));
    } else {
        show_chooser(app, &view);
    }
}

/* ───────────── commands ───────────── */

#[tauri::command]
pub fn autotype_support(at: State<'_, Arc<AutoType>>) -> Support {
    at.platform.support()
}

#[tauri::command]
pub fn autotype_settings_get(at: State<'_, Arc<AutoType>>) -> SettingsView {
    at.view()
}

#[tauri::command]
pub fn autotype_settings_set(app: AppHandle, at: State<'_, Arc<AutoType>>, enabled: bool, hotkey: String) -> Result<SettingsView, String> {
    let sc = parse_hotkey(&hotkey)?;
    let next = Settings { enabled, hotkey: sc.into_string() };
    at.store.save(&next).map_err(|e| e.to_string())?;
    if let Ok(mut s) = at.settings.lock() {
        *s = next;
    }
    sync(&app);
    Ok(at.view())
}

/// The vault UI's matches for request `id` (titles and user names only).
#[tauri::command]
pub async fn autotype_offer(app: AppHandle, at: State<'_, Arc<AutoType>>, id: u64, candidates: Vec<Candidate>) -> Result<(), String> {
    let Some(view) = at.broker.offer(id, candidates) else { return Ok(()) };
    show_chooser(&app, &view);
    Ok(())
}

/// What the chooser should show now (it may have opened after the event).
#[tauri::command]
pub fn autotype_pending(at: State<'_, Arc<AutoType>>) -> Option<ChooserView> {
    at.broker.view()
}

/// The person picked an entry in the chooser.
#[tauri::command]
pub fn autotype_confirm(app: AppHandle, window: tauri::Window, at: State<'_, Arc<AutoType>>, id: u64, entry_id: String) -> Result<(), String> {
    if window.label() != CHOOSER {
        return Err("not the chooser".into());
    }
    let view = at.broker.confirm(id, &entry_id).ok_or_else(|| "that request is no longer current".to_string())?;
    let _ = app.emit_to(CHOOSER, EVENT_VIEW, &view);
    let _ = app.emit_to("main", EVENT_RUN, json!({ "id": id, "entryId": entry_id, "mode": view.mode }));
    Ok(())
}

#[tauri::command]
pub fn autotype_cancel(app: AppHandle, at: State<'_, Arc<AutoType>>, id: u64) {
    at.broker.cancel(id);
    close_chooser(&app);
}

/// Type the keys the vault UI built, if the target is still in front. Runs on a worker thread.
#[tauri::command]
pub async fn autotype_type(app: AppHandle, at: State<'_, Arc<AutoType>>, id: u64, actions: Vec<Action>) -> Result<(), AutoTypeError> {
    let at: Arc<AutoType> = at.inner().clone();
    let Some(Some(target)) = at.broker.take_target(id) else { return Err(TypeError::Invalid("that request is no longer current").into()) };
    let (p, t) = (at.platform.clone(), target);
    let result = tauri::async_runtime::spawn_blocking(move || {
        // The chooser never takes focus, but if a click did land focus on it, hand focus back to the
        // window the person chose. This is only done when the foreground is PEVV's own, and the
        // same-handle-and-process check inside `type_into` still decides whether anything is typed.
        if matches!(p.foreground(), Ok(fg) if fg.pid == std::process::id()) {
            p.refocus(&t);
        }
        type_into(p.as_ref(), &t, &actions)
    })
    .await
    .map_err(|_| TypeError::Failed("interrupted".into()))
    .and_then(|r| r);
    let view = at.broker.finish(id, result.clone().map(|()| "Typed."));
    if let Some(v) = view {
        let _ = app.emit_to(CHOOSER, EVENT_VIEW, &v);
    }
    result.map_err(Into::into)
}

/// The vault UI could not (or need not) type: the clipboard fallback, or an error such as a missing one-time-code secret.
#[tauri::command]
pub fn autotype_finish(app: AppHandle, at: State<'_, Arc<AutoType>>, id: u64, ok: bool, message: Option<String>) {
    let text: String = message.unwrap_or_default().chars().take(300).collect();
    let result = if ok { Ok(text.as_str()) } else { Err(TypeError::Failed(text.clone())) };
    // Taking the target makes sure the request cannot be typed after this.
    let _ = at.broker.take_target(id);
    if let Some(v) = at.broker.finish(id, result) {
        let _ = app.emit_to(CHOOSER, EVENT_VIEW, &v);
    }
}

/// Used by the vault UI to learn whether this request is the clipboard fallback.
#[tauri::command]
pub fn autotype_mode(at: State<'_, Arc<AutoType>>, id: u64) -> Option<Mode> {
    at.broker.mode(id)
}

/// Register the hotkey machinery. Called once from setup.
pub fn start(app: &AppHandle, data_dir: &std::path::Path) {
    app.manage(AutoType::new(data_dir));
    sync(app);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_hotkey_is_valid_and_ctrl_alt_a() {
        let sc = parse_hotkey(DEFAULT_HOTKEY).unwrap();
        assert!(sc.mods.contains(Modifiers::CONTROL | Modifiers::ALT));
    }

    #[test]
    fn hotkeys_need_a_real_modifier_and_must_parse() {
        assert!(parse_hotkey("A").is_err(), "a bare letter would swallow typing");
        assert!(parse_hotkey("Shift+A").is_err(), "Shift alone types capitals");
        assert!(parse_hotkey("Ctrl+Shift+K").is_ok());
        assert!(parse_hotkey("Alt+F9").is_ok());
        assert!(parse_hotkey("ctrl+alt+a").is_ok());
        assert!(parse_hotkey("Ctrl+").is_err());
        assert!(parse_hotkey("Ctrl+Alt+Banana").is_err());
        assert!(parse_hotkey("").is_err());
        assert!(parse_hotkey(&"Ctrl+".repeat(20)).is_err());
    }

    #[test]
    fn saved_hotkeys_round_trip_through_the_parser() {
        for s in ["Ctrl+Alt+A", "Ctrl+Shift+K", "Alt+F9"] {
            let sc = parse_hotkey(s).unwrap();
            assert_eq!(parse_hotkey(&sc.into_string()).unwrap(), sc, "{s}");
        }
    }
}
