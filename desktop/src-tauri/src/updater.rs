//! Auto-update, Tauri side. The webview asks `update_check` (on start and daily, only if the person
//! left checking on) and shows an "Update now" / "Later" prompt; only `update_install` downloads and
//! installs, and only after the person pressed the button. Nothing installs silently.
//!
//! The release is fetched from the endpoint in `tauri.conf.json` and its minisign signature is
//! checked by `tauri-plugin-updater` against the `pubkey` there; that check cannot be turned off.
//! While the pubkey is the placeholder the updater is disabled and both commands say so.

use serde::Serialize;
use std::sync::Mutex;
use tauri::{AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};

/// What `tauri.conf.json` holds until a maintainer pastes the real public key (docs/CLIENT_DESKTOP.md).
pub const PUBKEY_PLACEHOLDER: &str = "REPLACE_WITH_UPDATER_PUBKEY";

/// The update found by the last check, and its package once downloaded and verified, so the install
/// is exactly what was offered. Replaced by each check.
#[derive(Default)]
pub struct Pending(Mutex<Slot>);

#[derive(Default)]
struct Slot {
    update: Option<Update>,
    bytes: Option<Vec<u8>>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub version: String,
    pub current: String,
    pub notes: Option<String>,
}

/// True when the configured pubkey is a real one (not empty, not the placeholder).
pub fn pubkey_usable(pubkey: &str) -> bool {
    let p = pubkey.trim();
    !p.is_empty() && p != PUBKEY_PLACEHOLDER
}

fn configured_pubkey(app: &AppHandle) -> String {
    app.config().plugins.0.get("updater").and_then(|v| v.get("pubkey")).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// Is the updater on in this build? (`false` while the pubkey is the placeholder.)
#[tauri::command]
pub fn update_enabled(app: AppHandle) -> bool {
    pubkey_usable(&configured_pubkey(&app))
}

/// Ask the endpoint whether a newer signed release exists. `None` when up to date or disabled.
#[tauri::command]
pub async fn update_check(app: AppHandle, pending: State<'_, Pending>) -> Result<Option<UpdateInfo>, String> {
    if !pubkey_usable(&configured_pubkey(&app)) {
        return Ok(None);
    }
    let updater = app.updater().map_err(|e| e.to_string())?;
    let found = updater.check().await.map_err(|e| e.to_string())?;
    let info = found.as_ref().map(|u| UpdateInfo { version: u.version.clone(), current: u.current_version.clone(), notes: u.body.clone() });
    let mut slot = pending.0.lock().unwrap();
    // The same version found again keeps its downloaded package; anything else starts over.
    let same = matches!((&slot.update, &found), (Some(a), Some(b)) if a.version == b.version);
    if !same {
        slot.bytes = None;
    }
    slot.update = found;
    Ok(info)
}

/// Download the offered update and check its signature, but do not install it. Safe to call in the
/// background; `update_install` then installs without another download.
#[tauri::command]
pub async fn update_download(app: AppHandle, pending: State<'_, Pending>) -> Result<(), String> {
    if !pubkey_usable(&configured_pubkey(&app)) {
        return Err("updater-disabled".into());
    }
    let update = pending.0.lock().unwrap().update.clone().ok_or_else(|| "no-update".to_string())?;
    if pending.0.lock().unwrap().bytes.is_some() {
        return Ok(());
    }
    // `download` verifies the minisign signature against the configured pubkey.
    let bytes = update.download(|_, _| {}, || {}).await.map_err(|e| e.to_string())?;
    pending.0.lock().unwrap().bytes = Some(bytes);
    Ok(())
}

/// Install (downloading first if needed) and restart. The package is verified again by the plugin
/// before it runs. The webview calls this only when the chosen mode and the vault state allow it.
#[tauri::command]
pub async fn update_install(app: AppHandle, pending: State<'_, Pending>) -> Result<(), String> {
    if !pubkey_usable(&configured_pubkey(&app)) {
        return Err("updater-disabled".into());
    }
    let (update, bytes) = {
        let slot = pending.0.lock().unwrap();
        (slot.update.clone().ok_or_else(|| "no-update".to_string())?, slot.bytes.clone())
    };
    match bytes {
        Some(b) => update.install(b).map_err(|e| e.to_string())?,
        None => update.download_and_install(|_, _| {}, || {}).await.map_err(|e| e.to_string())?,
    }
    app.restart()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_and_empty_keys_are_not_usable() {
        assert!(!pubkey_usable(""));
        assert!(!pubkey_usable("  "));
        assert!(!pubkey_usable(PUBKEY_PLACEHOLDER));
        assert!(!pubkey_usable(&format!(" {PUBKEY_PLACEHOLDER}\n")));
        assert!(pubkey_usable("dW50cnVzdGVkIGNvbW1lbnQ6"));
    }

    #[test]
    fn a_new_state_holds_nothing_to_install() {
        let p = Pending::default();
        let slot = p.0.lock().unwrap();
        assert!(slot.update.is_none() && slot.bytes.is_none());
    }

    #[test]
    fn update_info_serializes_camel_case() {
        let v = serde_json::to_value(UpdateInfo { version: "0.3.0".into(), current: "0.2.0".into(), notes: None }).unwrap();
        assert_eq!(v["version"], "0.3.0");
        assert_eq!(v["current"], "0.2.0");
        assert!(v["notes"].is_null());
    }
}
