//! PEVV as a Windows 11 passkey provider (plugin authenticator): what the app tells the vault window
//! about it, and the glue between the OS-facing COM class (`provider_win`, cargo feature
//! `win-passkey-provider`) and the webview that holds the vault.
//!
//! This file always compiles, with or without the feature, so the settings section can say honestly
//! what is missing ("this build was made without the provider"). The parts that need `ciborium` or
//! the Windows plugin API are behind the feature.

use serde::{Deserialize, Serialize};

/// Windows 11 24H2. The plugin authenticator API (`webauthnplugin.h`) shipped with the 24H2 servicing
/// updates; this is the lowest build the app will even look for it on. The real test is whether the
/// functions resolve at run time.
pub const MIN_BUILD: u32 = 26100;

/// What `passkey_provider_support` answers.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Support {
    /// This build includes the provider (cargo feature `win-passkey-provider`).
    pub compiled: bool,
    /// "windows", "linux" or "other".
    pub os: &'static str,
    pub build: Option<u32>,
    pub min_build: u32,
    /// The OS is new enough and (when compiled in) the plugin functions are there.
    pub api_present: bool,
    /// Running from an MSIX package, which Windows requires of a plugin authenticator.
    pub packaged: bool,
    /// Registered with Windows. None when it could not be asked.
    pub registered: Option<bool>,
    /// Switched on by the person under Settings > Accounts > Passkeys > Advanced options.
    pub enabled: Option<bool>,
    pub reason: Option<String>,
}

/// One passkey's public details, for Windows' account lists (never a key).
#[derive(Deserialize, Clone, Debug)]
#[cfg_attr(not(all(feature = "win-passkey-provider", windows)), allow(dead_code))]
#[serde(rename_all = "camelCase")]
pub struct CredMeta {
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: String,
    pub user_name: String,
    pub user_display_name: String,
}

/// The build number out of a `CurrentBuildNumber` registry value ("26100").
pub fn parse_build(s: &str) -> Option<u32> {
    s.trim().trim_end_matches('\0').parse().ok().filter(|b| *b > 0)
}

/// The one line the settings section shows when something blocks the provider (None = nothing does).
pub fn reason(compiled: bool, os: &str, build: Option<u32>, api_present: bool, packaged: bool) -> Option<String> {
    if os != "windows" {
        return Some("Passkey provider: Windows 11 only.".into());
    }
    match build {
        Some(b) if b < MIN_BUILD => {
            return Some(format!("Windows build {b} is too old; the passkey plugin API needs build {MIN_BUILD} (Windows 11 24H2) or later."))
        }
        None => return Some("The Windows build could not be read.".into()),
        _ => {}
    }
    if !compiled {
        return Some("This PEVV build was made without the passkey provider (cargo feature win-passkey-provider). Use the MSIX build.".into());
    }
    if !api_present {
        return Some("Windows does not offer the passkey plugin API yet. Install the latest Windows 11 updates.".into());
    }
    if !packaged {
        return Some("PEVV is not running from an MSIX package. Windows only lets packaged apps be a passkey provider; install the MSIX build.".into());
    }
    None
}

pub fn os_name() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

/// The Windows build number from the registry (`None` elsewhere).
#[cfg(windows)]
pub fn windows_build() -> Option<u32> {
    use windows::core::w;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let mut buf = [0u16; 32];
    let mut bytes = std::mem::size_of_val(&buf) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            w!("CurrentBuildNumber"),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let n = (bytes as usize / 2).saturating_sub(1).min(buf.len());
    parse_build(&String::from_utf16_lossy(&buf[..n]))
}

#[cfg(not(windows))]
pub fn windows_build() -> Option<u32> {
    None
}

/// Is this process running with MSIX package identity?
#[cfg(windows)]
pub fn is_packaged() -> bool {
    use windows::Win32::Foundation::{APPMODEL_ERROR_NO_PACKAGE, ERROR_INSUFFICIENT_BUFFER};
    use windows::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
    let mut len = 0u32;
    let rc = unsafe { GetCurrentPackageFullName(&mut len, None) };
    rc != APPMODEL_ERROR_NO_PACKAGE && (rc == ERROR_INSUFFICIENT_BUFFER || rc.0 == 0)
}

#[cfg(not(windows))]
pub fn is_packaged() -> bool {
    false
}

pub fn support() -> Support {
    let os = os_name();
    let build = windows_build();
    let compiled = cfg!(feature = "win-passkey-provider");
    let new_enough = os == "windows" && build.is_some_and(|b| b >= MIN_BUILD);
    let packaged = is_packaged();
    #[cfg(all(feature = "win-passkey-provider", windows))]
    let (api_present, registered, enabled) = if new_enough {
        let present = crate::provider_win::api_present();
        let (r, e) = if present && packaged { crate::provider_win::state() } else { (None, None) };
        (present, r, e)
    } else {
        (false, None, None)
    };
    #[cfg(not(all(feature = "win-passkey-provider", windows)))]
    let (api_present, registered, enabled) = (new_enough && !compiled, None, None);
    Support {
        compiled,
        os,
        build,
        min_build: MIN_BUILD,
        api_present,
        packaged,
        registered,
        enabled,
        reason: reason(compiled, os, build, api_present, packaged),
    }
}

/// "Add PEVV to Windows": registers the authenticator. Needs the feature, Windows 11 and MSIX identity.
pub fn register() -> Result<Support, String> {
    #[cfg(all(feature = "win-passkey-provider", windows))]
    {
        let s = support();
        if let Some(r) = &s.reason {
            return Err(r.clone());
        }
        crate::provider_win::register()?;
        Ok(support())
    }
    #[cfg(not(all(feature = "win-passkey-provider", windows)))]
    Err(support().reason.unwrap_or_else(|| "Not available in this build.".into()))
}

pub fn unregister() -> Result<Support, String> {
    #[cfg(all(feature = "win-passkey-provider", windows))]
    {
        let s = support();
        if let Some(r) = &s.reason {
            return Err(r.clone());
        }
        crate::provider_win::unregister()?;
        Ok(support())
    }
    #[cfg(not(all(feature = "win-passkey-provider", windows)))]
    Err(support().reason.unwrap_or_else(|| "Not available in this build.".into()))
}

/// Tell Windows which accounts PEVV holds. A no-op where the provider does not exist.
pub fn sync_credentials(list: &[CredMeta]) -> Result<(), String> {
    #[cfg(all(feature = "win-passkey-provider", windows))]
    {
        if support().registered == Some(true) {
            return crate::provider_win::sync(list);
        }
    }
    let _ = list;
    Ok(())
}

/// Called once at startup, after the link runtime exists. With the feature, on Windows, from an MSIX
/// package: make the COM class available to Windows. Anywhere else this does nothing.
pub fn start(app: &tauri::AppHandle) {
    #[cfg(all(feature = "win-passkey-provider", windows))]
    {
        use std::sync::Arc;
        use tauri::Manager;
        if !is_packaged() {
            return;
        }
        let Some(link) = app.try_state::<Arc<crate::link::Runtime>>() else { return };
        let bridge = Bridge::new(app.clone(), link.inner().clone());
        app.manage(bridge.clone());
        let ids = bridge.clone();
        crate::provider_win::serve(Arc::new(crate::provider_win::Service { host: bridge, next_id: Box::new(move || ids.next_id()) }));
    }
    let _ = app;
}

#[cfg(feature = "win-passkey-provider")]
pub use bridge::Bridge;

/// The Tauri half of the broker: the `Host` the COM class talks to.
#[cfg(feature = "win-passkey-provider")]
mod bridge {
    use crate::link;
    use crate::link_core::Ui;
    use crate::provider_core::Host;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{sync_channel, SyncSender};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tauri::{AppHandle, Emitter};

    /// Emitted to the webview for every Windows request (a `ProviderRequest` in passkeyProvider.ts).
    const EVENT_REQUEST: &str = "passkey-provider-request";
    /// Windows cancelled a request the webview may still be asking the person about.
    const EVENT_CANCEL: &str = "passkey-provider-cancel";

    /// How long the person has to answer the PEVV confirmation card.
    const ANSWER_WAIT: Duration = Duration::from_secs(120);

    pub struct Bridge {
        app: AppHandle,
        link: Arc<link::Runtime>,
        next: AtomicU64,
        waiters: Mutex<HashMap<u64, SyncSender<Result<Value, String>>>>,
    }

    impl Bridge {
        pub fn new(app: AppHandle, link: Arc<link::Runtime>) -> Arc<Bridge> {
            Arc::new(Bridge { app, link, next: AtomicU64::new(1), waiters: Mutex::new(HashMap::new()) })
        }

        pub fn next_id(&self) -> u64 {
            self.next.fetch_add(1, Ordering::SeqCst)
        }

        /// The webview's answer (`passkey_provider_respond`). Unknown or late ids are ignored.
        pub fn respond(&self, id: u64, ok: bool, value: Value) {
            let tx = self.waiters.lock().ok().and_then(|mut w| w.remove(&id));
            if let Some(tx) = tx {
                let _ = tx.send(if ok { Ok(value) } else { Err(value.as_str().unwrap_or("failed").chars().take(40).collect()) });
            }
        }
    }

    impl Host for Bridge {
        fn unlocked(&self) -> bool {
            self.link.ui.is_unlocked()
        }

        fn show_window(&self) {
            Ui::show_window(&*self.link.ui);
        }

        fn ask(&self, body: &Value, cancel: &AtomicBool) -> Result<Value, String> {
            let id = body.get("id").and_then(Value::as_u64).ok_or("failed")?;
            let (tx, rx) = sync_channel(1);
            self.waiters.lock().map_err(|_| "failed".to_string())?.insert(id, tx);
            // The person answers in the PEVV window: make sure it is in front.
            Ui::show_window(&*self.link.ui);
            let _ = self.app.emit(EVENT_REQUEST, body);
            let end = Instant::now() + ANSWER_WAIT;
            let result = loop {
                if cancel.load(Ordering::SeqCst) {
                    let _ = self.app.emit(EVENT_CANCEL, json!({ "id": id }));
                    break Err("cancelled".to_string());
                }
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(r) => break r,
                    Err(_) if Instant::now() >= end => {
                        let _ = self.app.emit(EVENT_CANCEL, json!({ "id": id }));
                        break Err("declined".to_string());
                    }
                    Err(_) => {}
                }
            };
            if let Ok(mut w) = self.waiters.lock() {
                w.remove(&id);
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_build_numbers() {
        assert_eq!(parse_build("26100"), Some(26100));
        assert_eq!(parse_build(" 19045\0"), Some(19045));
        assert_eq!(parse_build(""), None);
        assert_eq!(parse_build("0"), None);
        assert_eq!(parse_build("abc"), None);
    }

    #[test]
    fn the_reason_names_the_first_blocker() {
        assert!(reason(true, "linux", None, false, false).unwrap().contains("Windows 11 only"));
        assert!(reason(true, "windows", Some(19045), false, false).unwrap().contains("too old"));
        assert!(reason(true, "windows", None, false, false).unwrap().contains("could not be read"));
        assert!(reason(false, "windows", Some(26100), true, true).unwrap().contains("without the passkey provider"));
        assert!(reason(true, "windows", Some(26100), false, true).unwrap().contains("updates"));
        assert!(reason(true, "windows", Some(26100), true, false).unwrap().contains("MSIX"));
        assert_eq!(reason(true, "windows", Some(26100), true, true), None);
        assert_eq!(reason(true, "windows", Some(26200), true, true), None);
    }

    #[test]
    fn support_never_claims_what_this_machine_cannot_do() {
        let s = support();
        assert_eq!(s.min_build, MIN_BUILD);
        assert_eq!(s.compiled, cfg!(feature = "win-passkey-provider"));
        // Nothing here is packaged, so there is always a reason to show, and registration is refused.
        assert!(s.reason.is_some());
        assert!(register().is_err());
        assert!(unregister().is_err());
        assert!(sync_credentials(&[]).is_ok());
    }

    #[test]
    fn credential_metadata_deserialises_from_what_the_webview_sends() {
        let m: CredMeta =
            serde_json::from_str(r#"{"credentialId":"a","rpId":"example.com","rpName":"Ex","userHandle":"dTE","userName":"ada","userDisplayName":"Ada"}"#)
                .unwrap();
        assert_eq!((m.rp_id.as_str(), m.user_name.as_str()), ("example.com", "ada"));
    }

    #[test]
    fn the_support_json_has_the_camel_case_names_the_page_reads() {
        let v = serde_json::to_value(support()).unwrap();
        for k in ["compiled", "os", "build", "minBuild", "apiPresent", "packaged", "registered", "enabled", "reason"] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
    }
}
