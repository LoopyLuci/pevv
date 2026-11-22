//! PEVV desktop shell. The vault UI, crypto, sync and imports are the existing
//! TypeScript app; this crate only does what a webview can't: keep the
//! ciphertext file safely on disk, lock on OS signals, handle the clipboard
//! carefully, and be a well-behaved desktop app (single instance, tray).

mod autotype;
mod autotype_core;
#[cfg(windows)]
mod autotype_win;
#[cfg(target_os = "linux")]
mod autotype_x11;
mod cli_core;
mod cli_proto;
mod clipboard;
mod datadir;
mod link;
mod link_core;
mod link_ipc;
mod link_proto;
mod link_register;
#[cfg(target_os = "linux")]
mod lock_linux;
#[cfg(windows)]
mod lock_win;
mod passkey;
#[cfg(target_os = "linux")]
mod passkey_linux;
#[cfg(windows)]
mod passkey_win;
mod presence;
mod provider;
#[cfg(feature = "win-passkey-provider")]
mod provider_core;
#[cfg(all(feature = "win-passkey-provider", windows))]
mod provider_win;
mod usbkey;
mod vault_store;
mod winpath;

use clipboard::{clamp_secs, SecretClipboard, System};
use std::sync::Arc;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use vault_store::{StoreError, VaultStore};

/// Events the webview listens for.
const EVENT_LOCK: &str = "lock";
const EVENT_VAULT_CHANGED: &str = "vault-changed";

struct Clip(SecretClipboard<System>);

#[tauri::command]
fn vault_read(store: State<'_, Arc<VaultStore>>) -> Result<Option<String>, StoreError> {
    store.read()
}

/// `expected_rev`: the newest revision the UI has seen on disk. A write below it, or below
/// what is on disk now, is refused with `rev-conflict` so a stale window cannot roll the vault back.
#[tauri::command]
fn vault_write(store: State<'_, Arc<VaultStore>>, json: String, expected_rev: Option<u64>) -> Result<u64, StoreError> {
    store.write(&json, expected_rev)
}

#[tauri::command]
fn vault_clear(store: State<'_, Arc<VaultStore>>) -> Result<(), StoreError> {
    store.clear()
}

/// What the browser-extension link is doing (enabled, registered browsers, pairings).
#[tauri::command]
fn link_state(rt: State<'_, Arc<link::Runtime>>) -> link::StateView {
    rt.view()
}

#[tauri::command]
fn link_set_enabled(rt: State<'_, Arc<link::Runtime>>, enabled: bool) -> Result<link::StateView, String> {
    rt.set_enabled(enabled)?;
    Ok(rt.view())
}

#[tauri::command]
fn link_unpair(rt: State<'_, Arc<link::Runtime>>, ext_id: String) -> Result<link::StateView, String> {
    rt.link.unpair(&ext_id).map_err(|e| e.to_string())?;
    Ok(rt.view())
}

/// Pairing approvals waiting for an answer (the window may have missed the event).
#[tauri::command]
fn link_prompts(rt: State<'_, Arc<link::Runtime>>) -> Vec<link::PromptView> {
    rt.prompts()
}

#[tauri::command]
fn link_prompt_answer(rt: State<'_, Arc<link::Runtime>>, id: u64, approve: bool) {
    rt.answer_prompt(id, approve);
}

/// The vault UI's answer to a `link-request`: `ok` with a JSON value, or not ok with an error code.
#[tauri::command]
fn link_respond(rt: State<'_, Arc<link::Runtime>>, id: u64, ok: bool, value: serde_json::Value) {
    let result = if ok { Ok(value) } else { Err(value.as_str().unwrap_or("failed").chars().take(40).collect()) };
    rt.respond(id, result);
}

/// The vault UI tells the shell whether it is unlocked, so `status` can answer without asking it.
#[tauri::command]
fn link_report_state(app: AppHandle, rt: State<'_, Arc<link::Runtime>>, unlocked: bool) {
    rt.ui.set_unlocked(unlocked);
    // The auto-type hotkey exists only while the vault is unlocked.
    autotype::sync(&app);
}

/// What the `pevv` command-line tool may do: programs allowed to call, commands allowed for 8 hours.
#[tauri::command]
fn cli_state(rt: State<'_, Arc<link::Runtime>>) -> link::CliView {
    rt.cli_view()
}

/// `pevv` approvals waiting for an answer (the window may have missed the event).
#[tauri::command]
fn cli_prompts(rt: State<'_, Arc<link::Runtime>>) -> Vec<serde_json::Value> {
    rt.cli_prompts()
}

/// `answer`: "deny", "once" or "8h".
#[tauri::command]
fn cli_prompt_answer(rt: State<'_, Arc<link::Runtime>>, id: u64, answer: String) {
    rt.cli_answer(id, &answer);
}

#[tauri::command]
fn cli_revoke_client(rt: State<'_, Arc<link::Runtime>>, path: String) -> Result<link::CliView, String> {
    rt.cli.revoke_client(&path).map_err(|e| e.to_string())?;
    Ok(rt.cli_view())
}

#[tauri::command]
fn cli_revoke_command(rt: State<'_, Arc<link::Runtime>>, key: String) -> Result<link::CliView, String> {
    rt.cli.revoke_command(&key).map_err(|e| e.to_string())?;
    Ok(rt.cli_view())
}

/// Copy a secret; clear it after `clear_after_secs` (0 = never) only if the clipboard is unchanged.
#[tauri::command]
fn clipboard_copy(clip: State<'_, Clip>, text: String, clear_after_secs: u64) -> Result<(), String> {
    clip.0.copy(&text, clamp_secs(clear_after_secs).map(Duration::from_secs))
}

/// Native passkey / security-key unlock: what the shell can do on this system.
#[tauri::command]
fn passkey_support() -> passkey::Support {
    passkey::support()
}

/// Ask the OS / the USB key for the PRF secrets of the vault's passkeys. The relying party is
/// the constant `passkey::RP_ID`; the page cannot choose it. Blocks on the user, so it runs on a worker thread.
#[tauri::command]
async fn passkey_prf(window: tauri::WebviewWindow, req: passkey::PrfRequest) -> Result<passkey::PrfResponse, passkey::PasskeyError> {
    let prep = passkey::prepare(&req)?;
    #[cfg(windows)]
    let hwnd = window.hwnd().map(|h| h.0 as usize).unwrap_or(0);
    #[cfg(not(windows))]
    let hwnd = {
        let _ = &window;
        0usize
    };
    let pin = req.pin.clone();
    tauri::async_runtime::spawn_blocking(move || passkey::run(hwnd as *mut core::ffi::c_void, &prep, pin.as_deref()))
        .await
        .map_err(|_| passkey::PasskeyError::new("failed", "the passkey request was interrupted"))?
}

/// Windows passkey provider: what this PC and this build can do (the settings section reads it).
#[tauri::command]
fn passkey_provider_support() -> provider::Support {
    provider::support()
}

/// Register PEVV as a passkey provider with Windows. The person still switches it on in Windows Settings.
#[tauri::command]
async fn passkey_provider_register() -> Result<provider::Support, String> {
    tauri::async_runtime::spawn_blocking(provider::register).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn passkey_provider_unregister() -> Result<provider::Support, String> {
    tauri::async_runtime::spawn_blocking(provider::unregister).await.map_err(|e| e.to_string())?
}

/// The vault window's answer to a `passkey-provider-request`: `ok` with a JSON value, or not ok with an error code.
#[tauri::command]
fn passkey_provider_respond(app: AppHandle, id: u64, ok: bool, value: serde_json::Value) {
    #[cfg(feature = "win-passkey-provider")]
    if let Some(b) = app.try_state::<Arc<provider::Bridge>>() {
        b.respond(id, ok, value);
    }
    #[cfg(not(feature = "win-passkey-provider"))]
    let _ = (app, id, ok, value);
}

/// The names (never keys) of the passkeys PEVV holds, so Windows can list the accounts.
#[tauri::command]
async fn passkey_provider_sync(credentials: Vec<provider::CredMeta>) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || provider::sync_credentials(&credentials)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn usb_volumes() -> Vec<usbkey::Volume> {
    tauri::async_runtime::spawn_blocking(usbkey::list_volumes).await.unwrap_or_default()
}

#[tauri::command]
async fn usb_keyfile_read(path: String) -> Result<String, String> {
    let dir = usbkey::resolve_volume(&path)?;
    usbkey::read_key_file(&dir)
}

#[tauri::command]
async fn usb_keyfile_write(path: String, content: String) -> Result<(), String> {
    let dir = usbkey::resolve_volume(&path)?;
    usbkey::write_key_file(&dir, &content)
}

#[tauri::command]
async fn usb_devices() -> Result<Vec<presence::UsbDevice>, String> {
    tauri::async_runtime::spawn_blocking(presence::list_devices).await.map_err(|e| e.to_string())?
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PresenceState {
    designation: Option<presence::Designation>,
    /// `None` when there is no designation or the device list could not be read.
    present: Option<bool>,
}

#[tauri::command]
async fn presence_get(p: State<'_, Arc<presence::Presence>>) -> Result<PresenceState, String> {
    let designation = p.designation();
    let present = match &designation {
        Some(d) => {
            let id = d.id.clone();
            tauri::async_runtime::spawn_blocking(move || presence::list_devices().ok().map(|l| presence::is_present(&l, &id)))
                .await
                .map_err(|e| e.to_string())?
        }
        None => None,
    };
    Ok(PresenceState { designation, present })
}

#[tauri::command]
fn presence_set(p: State<'_, Arc<presence::Presence>>, designation: Option<presence::Designation>) -> Result<(), String> {
    p.set(designation)
}

fn data_dir(app: &AppHandle) -> std::path::PathBuf {
    datadir::data_dir(|| app.path().data_dir().unwrap_or_else(|_| std::env::temp_dir()))
}

/// WebView2 saves what is typed into text fields (usernames, an environment variable's value) to
/// `Web Data` in its profile, in plaintext. A vault app must not let it: switch autofill off.
#[cfg(windows)]
fn harden_webview(w: &tauri::WebviewWindow) {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings4;
    use windows_core_webview::Interface;
    let _ = w.with_webview(|wv| unsafe {
        if let Ok(core) = wv.controller().CoreWebView2() {
            if let Ok(settings) = core.Settings() {
                if let Ok(s4) = settings.cast::<ICoreWebView2Settings4>() {
                    let _ = s4.SetIsGeneralAutofillEnabled(false);
                    let _ = s4.SetIsPasswordAutosaveEnabled(false);
                }
            }
        }
    });
}

#[cfg(not(windows))]
fn harden_webview(_: &tauri::WebviewWindow) {}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn emit_lock(app: &AppHandle) {
    // The extension link must never see a stale "unlocked" while the lock event is in flight.
    if let Some(rt) = app.try_state::<Arc<link::Runtime>>() {
        rt.ui.set_unlocked(false);
    }
    autotype::sync(app);
    let _ = app.emit(EVENT_LOCK, ());
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show PEVV", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &lock, &quit])?;
    let mut tray = TrayIconBuilder::with_id("pevv")
        .tooltip("PEVV")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id().as_ref() {
            "show" => show_main(app),
            "lock" => emit_lock(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                show_main(tray.app_handle());
            }
        });
    // The simplified padlock reads better at tray size than the full window icon.
    match tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png")) {
        Ok(icon) => tray = tray.icon(icon),
        Err(_) => {
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
        }
    }
    tray.build(app)?;
    Ok(())
}

/// Tell the webview when the vault file changes underneath it (a second instance, a sync tool).
fn watch_vault(app: AppHandle, store: Arc<VaultStore>) -> Option<notify::RecommendedWatcher> {
    use notify::{RecursiveMode, Watcher};
    let dir = store.dir().to_path_buf();
    std::fs::create_dir_all(&dir).ok()?;
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            if ev.paths.iter().any(|p| p.file_name().is_some_and(|n| n == vault_store::FILE_NAME)) {
                let _ = tx.send(());
            }
        }
    })
    .ok()?;
    watcher.watch(&dir, RecursiveMode::NonRecursive).ok()?;
    std::thread::spawn(move || {
        while rx.recv().is_ok() {
            // Coalesce the burst a rename produces.
            while rx.recv_timeout(Duration::from_millis(200)).is_ok() {}
            match store.read() {
                Ok(Some(content)) if !store.is_own_write(&content) => {
                    let _ = app.emit(EVENT_VAULT_CHANGED, ());
                }
                Ok(None) => {
                    let _ = app.emit(EVENT_VAULT_CHANGED, ());
                }
                _ => {}
            }
        }
    });
    Some(watcher)
}

fn start_lock_signals(app: &AppHandle) {
    let handle = app.clone();
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || emit_lock(&handle));
    #[cfg(windows)]
    lock_win::start(notify);
    #[cfg(target_os = "linux")]
    lock_linux::start(notify);
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = notify;
}

pub fn run() {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_global_shortcut::Builder::new().build());
    // The auto-type chooser is placed by the app each time, never restored. With PEVV_DATA_DIR the
    // plugin is left out: it keeps its file in the OS config folder, outside the override.
    if datadir::override_dir().is_none() {
        builder = builder.plugin(tauri_plugin_window_state::Builder::default().with_denylist(&[autotype::CHOOSER]).build());
    }
    builder
        .invoke_handler(tauri::generate_handler![
            vault_read,
            vault_write,
            vault_clear,
            clipboard_copy,
            passkey_support,
            passkey_prf,
            passkey_provider_support,
            passkey_provider_register,
            passkey_provider_unregister,
            passkey_provider_respond,
            passkey_provider_sync,
            usb_volumes,
            usb_keyfile_read,
            usb_keyfile_write,
            usb_devices,
            presence_get,
            presence_set,
            link_state,
            link_set_enabled,
            link_unpair,
            link_prompts,
            link_prompt_answer,
            link_respond,
            link_report_state,
            cli_state,
            cli_prompts,
            cli_prompt_answer,
            cli_revoke_client,
            cli_revoke_command,
            autotype::autotype_support,
            autotype::autotype_settings_get,
            autotype::autotype_settings_set,
            autotype::autotype_offer,
            autotype::autotype_pending,
            autotype::autotype_confirm,
            autotype::autotype_cancel,
            autotype::autotype_type,
            autotype::autotype_finish,
            autotype::autotype_mode
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            // The main window is made here (tauri.conf.json has `create: false`) so that, with
            // PEVV_DATA_DIR, its webview profile (localStorage copy of the vault) lives in the override too.
            if let Some(cfg) = app.config().app.windows.iter().find(|w| w.label == "main") {
                let mut wb = tauri::WebviewWindowBuilder::from_config(&handle, cfg)?;
                if let Some(d) = datadir::override_dir() {
                    eprintln!("PEVV data folder (PEVV_DATA_DIR): {}", d.display());
                    wb = wb.data_directory(d.join("webview"));
                }
                let w = wb.build()?;
                harden_webview(&w);
            }
            let store = Arc::new(VaultStore::new(data_dir(&handle)));
            app.manage(store.clone());
            let presence = presence::Presence::new(&data_dir(&handle));
            app.manage(presence.clone());
            let lock_handle = handle.clone();
            presence::spawn_poller(presence, Arc::new(move || emit_lock(&lock_handle)));
            app.manage(Clip(SecretClipboard::new(System::new())));
            if let Some(w) = watch_vault(handle.clone(), store) {
                app.manage(w);
            }
            app.manage(link::start(&handle, data_dir(&handle), show_main, emit_lock));
            autotype::start(&handle, &data_dir(&handle));
            provider::start(&handle);
            let _ = setup_tray(&handle);
            start_lock_signals(&handle);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Windows: closing hides to the tray, locked. Elsewhere there may be no tray to get back to, so quit.
                if cfg!(windows) && window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                    emit_lock(window.app_handle());
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running PEVV");
}

/// `--register-link` / `--unregister-link` (installer hooks). False if the flag is not ours.
pub fn run_link_cli(flag: &str) -> bool {
    link::run_cli(flag)
}

/// `--add-path` / `--remove-path` (installer hooks): the install folder on the user's PATH, for `pevv`.
pub fn run_path_cli(flag: &str) -> bool {
    winpath::run_cli(flag)
}
