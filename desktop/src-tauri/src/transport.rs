//! Device transport (Transferd), Tauri side: the commands the vault window calls and the glue to
//! the `pevv-transport` crate. Policy and storage are in `transport_core` (unit-tested); the
//! protocol is the crate (docs/TRANSPORT.md).
//!
//! * Off by default (`transferd.json`, `enabled: false`) and no relay unless the person adds one.
//! * Ciphertext only: a file from a peer is **held**, never written to the vault file here. The
//!   vault UI takes it (`transport_take_staged`) and merges it like the cloud copy, because it
//!   alone holds a key. A locked window stages it and checks it at the next unlock.
//! * Built without the `transferd` feature the commands still exist and answer `available: false`.

// Without the `transferd` feature only the status side is used; the rest is the same surface.
#![cfg_attr(not(feature = "transferd"), allow(dead_code))]

use crate::transport_core::{PeerState, Settings, SettingsStore, Staged};
use crate::vault_store::VaultStore;
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

/// The webview listens for this; the payload is `{ kind }` and never carries vault bytes.
pub const EVENT: &str = "transport-event";
/// Folder (inside the app data folder) for the sealed seed, overlay state and `transferd.json`.
pub const DIR_NAME: &str = "transferd";

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PeerView {
    pub node_id: String,
    pub name: String,
    pub state: PeerState,
    /// Did the last sync attempt reach it? `None` before the first attempt.
    pub reachable: Option<bool>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PendingView {
    pub node_id: String,
    pub name: String,
    /// The six words that must match the other screen.
    pub sas: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    pub text: String,
    /// Unix milliseconds.
    pub expires_at: u64,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JoinView {
    pub node_id: String,
    pub sas: Vec<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    /// Is the transport compiled into this build?
    pub available: bool,
    pub enabled: bool,
    pub running: bool,
    pub device_name: String,
    pub node_id: Option<String>,
    /// Eight words from the key fingerprint, to compare two screens.
    pub fingerprint: Vec<String>,
    /// `os-keystore` or `file-permissions`: how the seed is protected at rest. Never claims hardware.
    pub seed_protection: Option<String>,
    pub relays: Vec<String>,
    pub direct: Vec<String>,
    pub peers: Vec<PeerView>,
    pub pending: Vec<PendingView>,
    pub invite: Option<InviteView>,
    /// Unix milliseconds of the last sync that reached a peer.
    pub last_sync: Option<u64>,
    pub last_error: Option<String>,
    /// A peer's file is waiting for the vault window to merge it.
    pub staged: bool,
}

#[derive(Default)]
struct Notes {
    last_sync: Option<u64>,
    last_error: Option<String>,
    reach: std::collections::HashMap<String, bool>,
    invite: Option<InviteView>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub struct Runtime {
    app: AppHandle,
    dir: PathBuf,
    settings: Arc<SettingsStore>,
    staged: Arc<Staged>,
    vault: Arc<VaultStore>,
    notes: Mutex<Notes>,
    #[cfg(feature = "transferd")]
    live: Mutex<Option<Arc<pevv_transport::Transport>>>,
    /// Serialises enable / disable.
    #[cfg(feature = "transferd")]
    gate: tokio::sync::Mutex<()>,
}

/// Create the runtime and, if the person had switched the transport on, start it in the background.
pub fn start(app: &AppHandle, data_dir: PathBuf, vault: Arc<VaultStore>) -> Arc<Runtime> {
    let dir = data_dir.join(DIR_NAME);
    let rt = Arc::new(Runtime {
        app: app.clone(),
        settings: Arc::new(SettingsStore::load(&dir)),
        dir,
        staged: Arc::new(Staged::default()),
        vault,
        notes: Mutex::new(Notes::default()),
        #[cfg(feature = "transferd")]
        live: Mutex::new(None),
        #[cfg(feature = "transferd")]
        gate: tokio::sync::Mutex::new(()),
    });
    #[cfg(feature = "transferd")]
    if rt.settings.get().enabled {
        let rt2 = rt.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = rt2.start_live().await {
                rt2.note_error(Some(e));
            }
        });
    }
    rt
}

impl Runtime {
    fn note_error(&self, e: Option<String>) {
        if let Ok(mut n) = self.notes.lock() {
            n.last_error = e;
        }
        let _ = self.app.emit(EVENT, json!({ "kind": "status" }));
    }

    fn peers_view(&self, s: &Settings) -> Vec<PeerView> {
        let reach = self.notes.lock().map(|n| n.reach.clone()).unwrap_or_default();
        s.peers
            .iter()
            .map(|p| PeerView { node_id: p.node_id.clone(), name: p.name.clone(), state: p.state, reachable: reach.get(&p.node_id).copied() })
            .collect()
    }

    pub fn view(&self) -> StatusView {
        let s = self.settings.get();
        let (last_sync, last_error, invite) =
            self.notes.lock().map(|n| (n.last_sync, n.last_error.clone(), n.invite.clone().filter(|i| i.expires_at > now_ms()))).unwrap_or((None, None, None));
        #[cfg_attr(not(feature = "transferd"), allow(unused_mut))]
        let mut v = StatusView {
            available: cfg!(feature = "transferd"),
            enabled: s.enabled,
            device_name: s.device_name.clone(),
            relays: s.relays.clone(),
            direct: s.direct.clone(),
            peers: self.peers_view(&s),
            last_sync,
            last_error,
            invite,
            staged: !self.staged.is_empty(),
            ..Default::default()
        };
        #[cfg(feature = "transferd")]
        if let Some(t) = self.live_handle() {
            v.running = true;
            v.node_id = Some(t.node_id());
            v.fingerprint = t.fingerprint_words();
            v.seed_protection = Some(
                match t.seed_protection() {
                    pevv_transport::seal::Protection::OsKeystore => "os-keystore",
                    pevv_transport::seal::Protection::FilePermissionsOnly => "file-permissions",
                }
                .to_string(),
            );
            v.pending = t.pending_pairings().into_iter().map(|(node_id, name, sas)| PendingView { node_id, name, sas }).collect();
        }
        v
    }

    pub fn take_staged(&self) -> Option<String> {
        self.staged.take()
    }
}

#[cfg(not(feature = "transferd"))]
impl Runtime {
    const NA: &'static str = "not-in-this-build";

    async fn enable(&self, enabled: bool, device_id: Option<String>, name: Option<String>) -> Result<(), String> {
        // Switching it off is always allowed (and harmless); switching it on is not possible here.
        if enabled {
            return Err(Self::NA.into());
        }
        self.settings.set_enabled(false, device_id.as_deref(), name.as_deref())
    }
    async fn invite_create(&self, _ttl: u64) -> Result<InviteView, String> {
        Err(Self::NA.into())
    }
    fn invite_cancel(&self) {}
    async fn join(&self, _invite: &str, _name: Option<String>) -> Result<JoinView, String> {
        Err(Self::NA.into())
    }
    async fn pair_confirm(&self, _node: &str, _approved: bool) -> Result<(), String> {
        Err(Self::NA.into())
    }
    async fn peer_revoke(&self, node: &str) -> Result<(), String> {
        self.settings.revoke_peer(node)
    }
    async fn apply_addresses(&self) -> Result<(), String> {
        Ok(())
    }
    async fn sync_now(&self) -> Result<(), String> {
        Err(Self::NA.into())
    }
}

#[cfg(feature = "transferd")]
mod live {
    use super::*;
    use crate::transport_core::{acceptable, envelope, hash_hex};
    use pevv_transport::seal::default_sealer;
    use pevv_transport::{ApplyOutcome, ForkOutcome, Head, Transport, TransportConfig, TransportEvent};
    use std::time::Duration;

    const SYNC_TIMEOUT: Duration = Duration::from_secs(25);

    /// The vault file on disk, seen by the sync engine. Reads are the plain file; a file from a
    /// peer is only held for the vault window (see the module note).
    pub struct DesktopStore {
        pub vault: Arc<VaultStore>,
        pub staged: Arc<Staged>,
        pub device_id: String,
        pub notify: Arc<dyn Fn() + Send + Sync>,
    }

    impl DesktopStore {
        fn file(&self) -> Option<(String, u64, Vec<u8>)> {
            let text = self.vault.read().ok()??;
            let bytes = text.into_bytes();
            let (id, rev) = envelope(&bytes)?;
            Some((id, rev, bytes))
        }

        fn hold(&self, rev: u64, bytes: Vec<u8>) {
            if self.staged.put(rev, &bytes) {
                (self.notify)();
            }
        }
    }

    impl pevv_transport::VaultStore for DesktopStore {
        fn vault_id(&self) -> String {
            self.file().map(|f| f.0).unwrap_or_default()
        }
        fn device_id(&self) -> String {
            self.device_id.clone()
        }
        fn head(&self) -> Option<Head> {
            self.file().map(|(_, rev, b)| Head { rev, hash: hash_hex(&b) })
        }
        fn current(&self) -> Option<Vec<u8>> {
            self.file().map(|f| f.2)
        }
        fn validate(&self, rev: u64, bytes: &[u8]) -> bool {
            acceptable(&self.vault_id(), rev, bytes)
        }
        /// Never writes the vault file: holds the copy for the vault window, which merges it.
        fn apply(&self, base: u64, rev: u64, bytes: Vec<u8>) -> ApplyOutcome {
            let cur = self.file().map_or(0, |f| f.1);
            if cur != base {
                return ApplyOutcome::Stale { rev: cur };
            }
            self.hold(rev, bytes);
            ApplyOutcome::Applied
        }
        /// Equal revision, different file: the merge in the vault window keeps both sides' changes
        /// (and the loser's version inside the winner), so the file is held, not swapped.
        fn resolve_fork(&self, remote: Head, remote_bytes: Vec<u8>) -> ForkOutcome {
            self.hold(remote.rev, remote_bytes);
            ForkOutcome { remote_adopted: false }
        }
    }

    impl Runtime {
        pub(super) fn live_handle(&self) -> Option<Arc<Transport>> {
            self.live.lock().ok()?.clone()
        }

        fn live_or_err(&self) -> Result<Arc<Transport>, String> {
            self.live_handle().ok_or_else(|| "not-running".to_string())
        }

        /// Start the transport from the saved settings. Creates the sealed seed on first use.
        pub(super) async fn start_live(self: &Arc<Self>) -> Result<(), String> {
            let _g = self.gate.lock().await;
            if self.live_handle().is_some() {
                return Ok(());
            }
            let s = self.settings.get();
            let cfg = TransportConfig {
                enabled: true,
                name: if s.device_name.is_empty() { "PEVV desktop".into() } else { s.device_name.clone() },
                state_dir: self.dir.clone(),
                relays: s.relays.clone(),
                direct: s.direct.clone(),
                listen: None,
                punch: true,
            };
            let app = self.app.clone();
            let store = Arc::new(DesktopStore {
                vault: self.vault.clone(),
                staged: self.staged.clone(),
                device_id: s.device_id.clone(),
                notify: Arc::new(move || {
                    let _ = app.emit(EVENT, json!({ "kind": "staged" }));
                }),
            });
            let sealer = default_sealer();
            let t = Transport::start(cfg, sealer.as_ref(), store).await.map_err(|e| e.to_string())?;
            t.set_allow(self.settings.approved()).await.map_err(|e| e.to_string())?;
            self.forward_events(t.events());
            if let Ok(mut l) = self.live.lock() {
                *l = Some(t);
            }
            self.note_error(None);
            Ok(())
        }

        fn forward_events(self: &Arc<Self>, mut rx: tokio::sync::broadcast::Receiver<TransportEvent>) {
            use tokio::sync::broadcast::error::RecvError;
            let rt = self.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let ev = match rx.recv().await {
                        Ok(e) => e,
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    };
                    let kind = match ev {
                        TransportEvent::PairRequest { .. } => "pair-request",
                        TransportEvent::PairingResolved { .. } => "pair-resolved",
                        TransportEvent::Sync(pevv_transport::SyncEvent::Revoked { nodes }) => {
                            // A ROSTER_HINT from a peer: they can only restrict.
                            for n in nodes {
                                let _ = rt.settings.revoke_peer(&n);
                            }
                            "peers"
                        }
                        TransportEvent::Sync(_) => "sync",
                    };
                    let _ = rt.app.emit(EVENT, json!({ "kind": kind }));
                }
            });
        }

        pub(super) async fn enable(self: &Arc<Self>, enabled: bool, device_id: Option<String>, name: Option<String>) -> Result<(), String> {
            self.settings.set_enabled(enabled, device_id.as_deref(), name.as_deref())?;
            if enabled {
                return self.start_live().await;
            }
            let _g = self.gate.lock().await;
            let t = self.live.lock().ok().and_then(|mut l| l.take());
            if let Some(t) = t {
                t.shutdown();
            }
            if let Ok(mut n) = self.notes.lock() {
                n.reach.clear();
                n.invite = None;
            }
            Ok(())
        }

        pub(super) async fn invite_create(&self, ttl: u64) -> Result<InviteView, String> {
            let t = self.live_or_err()?;
            t.cancel_invite();
            let text = t.invite_create(ttl).map_err(|e| e.to_string())?;
            let ttl = pevv_transport::config::clamp_ttl(if ttl == 0 { pevv_transport::config::INVITE_TTL_DEFAULT } else { ttl });
            let v = InviteView { text, expires_at: now_ms() + ttl * 1000 };
            if let Ok(mut n) = self.notes.lock() {
                n.invite = Some(v.clone());
            }
            Ok(v)
        }

        pub(super) fn invite_cancel(&self) {
            if let Some(t) = self.live_handle() {
                t.cancel_invite();
            }
            if let Ok(mut n) = self.notes.lock() {
                n.invite = None;
            }
        }

        /// We scanned their invite, so we trust that node; the words are compared on both screens
        /// and the inviting device's person has the final say.
        pub(super) async fn join(&self, invite: &str, name: Option<String>) -> Result<JoinView, String> {
            let t = self.live_or_err()?;
            let info = t.invite_accept(invite.trim(), name.clone()).await.map_err(|e| e.to_string())?;
            self.settings.approve_peer(&info.node_id, "")?;
            Ok(JoinView { node_id: info.node_id, sas: info.sas })
        }

        pub(super) async fn pair_confirm(&self, node: &str, approved: bool) -> Result<(), String> {
            let t = self.live_or_err()?;
            let node = node.to_ascii_lowercase();
            let name = t.pending_pairings().into_iter().find(|p| p.0 == node).map(|p| p.1).unwrap_or_default();
            t.confirm_pairing(&node, approved).await.map_err(|e| e.to_string())?;
            if approved {
                self.settings.approve_peer(&node, &name)?;
            }
            if let Ok(mut n) = self.notes.lock() {
                n.invite = None;
            }
            Ok(())
        }

        /// Stops the transport using the node at once. The vault key is rotated by the vault window
        /// (the existing `rotateKey`), because only it holds the master password.
        pub(super) async fn peer_revoke(&self, node: &str) -> Result<(), String> {
            let node = node.to_ascii_lowercase();
            self.settings.revoke_peer(&node)?;
            if let Some(t) = self.live_handle() {
                let rev = self.vault.read().ok().flatten().and_then(|text| envelope(text.as_bytes())).map_or(0, |e| e.1);
                t.revoke(&node, rev).await.map_err(|e| e.to_string())?;
            }
            if let Ok(mut n) = self.notes.lock() {
                n.reach.remove(&node);
            }
            Ok(())
        }

        /// Relays or direct addresses changed: restart so the overlay registers on the new ones.
        pub(super) async fn apply_addresses(self: &Arc<Self>) -> Result<(), String> {
            if self.live_handle().is_none() {
                return Ok(());
            }
            let s = self.settings.get();
            self.enable(false, None, None).await?;
            self.settings.set_enabled(s.enabled, None, None)?;
            self.start_live().await
        }

        /// Reconcile with every approved peer (and push our head when we are ahead).
        pub(super) async fn sync_now(&self) -> Result<(), String> {
            let t = self.live_or_err()?;
            let mut last_err = None;
            for peer in self.settings.approved() {
                let r = tokio::time::timeout(SYNC_TIMEOUT, t.push_to(&peer)).await;
                let ok = matches!(r, Ok(Ok(_)));
                if let Ok(mut n) = self.notes.lock() {
                    n.reach.insert(peer.clone(), ok);
                    if ok {
                        n.last_sync = Some(now_ms());
                    }
                }
                match r {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => last_err = Some(e.to_string()),
                    Err(_) => last_err = Some("timed out".to_string()),
                }
            }
            self.note_error(last_err);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pevv_transport::VaultStore as _;

        fn setup() -> (tempfile::TempDir, DesktopStore, Arc<std::sync::atomic::AtomicUsize>) {
            let t = tempfile::tempdir().unwrap();
            let vault = Arc::new(VaultStore::new(t.path().join("data")));
            let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let h2 = hits.clone();
            let store = DesktopStore {
                vault,
                staged: Arc::new(Staged::default()),
                device_id: "dev".into(),
                notify: Arc::new(move || {
                    h2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            };
            (t, store, hits)
        }

        fn vault_json(rev: u64, tag: &str) -> String {
            format!(r#"{{"format":"luciverse.pevv","id":"v1","rev":{rev},"tag":"{tag}"}}"#)
        }

        #[test]
        fn head_and_current_follow_the_vault_file() {
            let (_t, s, _) = setup();
            assert!(s.head().is_none() && s.vault_id().is_empty());
            s.vault.write(&vault_json(3, "a"), None).unwrap();
            let h = s.head().unwrap();
            assert_eq!(h.rev, 3);
            assert_eq!(s.vault_id(), "v1");
            assert_eq!(h.hash, hash_hex(&s.current().unwrap()));
        }

        #[test]
        fn apply_holds_the_copy_and_never_touches_the_vault_file() {
            let (_t, s, hits) = setup();
            let mine = vault_json(3, "mine");
            s.vault.write(&mine, None).unwrap();
            let theirs = vault_json(5, "theirs");
            assert!(s.validate(5, theirs.as_bytes()));
            assert_eq!(s.apply(3, 5, theirs.clone().into_bytes()), ApplyOutcome::Applied);
            assert_eq!(s.vault.read().unwrap().unwrap(), mine, "the file on disk is untouched");
            assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(s.staged.take().unwrap(), theirs);
            // A base that is not the current revision is the compare-and-swap failing.
            assert_eq!(s.apply(2, 5, theirs.into_bytes()), ApplyOutcome::Stale { rev: 3 });
        }

        #[test]
        fn a_fork_is_held_for_the_merge_not_swapped() {
            let (_t, s, _) = setup();
            let mine = vault_json(4, "mine");
            s.vault.write(&mine, None).unwrap();
            let out = s.resolve_fork(Head { rev: 4, hash: "x".into() }, vault_json(4, "theirs").into_bytes());
            assert!(!out.remote_adopted);
            assert_eq!(s.vault.read().unwrap().unwrap(), mine);
            assert!(s.staged.take().unwrap().contains("theirs"));
        }

        #[test]
        fn another_vault_or_a_forged_revision_is_refused() {
            let (_t, s, _) = setup();
            s.vault.write(&vault_json(1, "a"), None).unwrap();
            let other = r#"{"format":"luciverse.pevv","id":"v2","rev":9}"#;
            assert!(!s.validate(9, other.as_bytes()));
            assert!(!s.validate(10, vault_json(9, "x").as_bytes()));
        }
    }
}

// ---- commands (the webview's whole surface; capabilities/transport.json lists them) ----

fn rt_arc(rt: &State<'_, Arc<Runtime>>) -> Arc<Runtime> {
    Arc::clone(rt)
}

/// What the Devices panel shows. Never contains vault bytes or the seed.
#[tauri::command]
pub fn transport_status(rt: State<'_, Arc<Runtime>>) -> StatusView {
    rt.view()
}

/// Switch the transport on or off. `device_id` is this device's PEVV roster id; `name` its display name.
#[tauri::command]
pub async fn transport_enable(rt: State<'_, Arc<Runtime>>, enabled: bool, device_id: Option<String>, name: Option<String>) -> Result<StatusView, String> {
    let r = rt_arc(&rt);
    r.enable(enabled, device_id, name).await.inspect_err(|e| r.note_error(Some(e.clone())))?;
    Ok(r.view())
}

/// Relays (UDP `host:port`, at most 4) and direct addresses. Empty by default: there is no default relay.
#[tauri::command]
pub async fn transport_set_addresses(rt: State<'_, Arc<Runtime>>, relays: Vec<String>, direct: Vec<String>) -> Result<StatusView, String> {
    let r = rt_arc(&rt);
    r.settings.set_addresses(&relays, &direct)?;
    r.apply_addresses().await?;
    Ok(r.view())
}

/// A pairing invite (QR / text) valid for `ttl_secs` (0 = 3 minutes). At most one is outstanding.
#[tauri::command]
pub async fn transport_invite_create(rt: State<'_, Arc<Runtime>>, ttl_secs: Option<u64>) -> Result<InviteView, String> {
    rt.invite_create(ttl_secs.unwrap_or(0)).await
}

#[tauri::command]
pub fn transport_invite_cancel(rt: State<'_, Arc<Runtime>>) -> StatusView {
    rt.invite_cancel();
    rt.view()
}

/// Join the device that made `invite`. Returns the six words to compare with its screen.
#[tauri::command]
pub async fn transport_join(rt: State<'_, Arc<Runtime>>, invite: String, name: Option<String>) -> Result<JoinView, String> {
    rt.join(&invite, name).await
}

/// The person compared the six words on the inviting device and decided.
#[tauri::command]
pub async fn transport_pair_confirm(rt: State<'_, Arc<Runtime>>, node_id: String, approved: bool) -> Result<StatusView, String> {
    rt.pair_confirm(&node_id, approved).await?;
    Ok(rt.view())
}

/// Approve a waiting pairing request (the same as `transport_pair_confirm` with `approved: true`).
#[tauri::command]
pub async fn transport_peer_approve(rt: State<'_, Arc<Runtime>>, node_id: String) -> Result<StatusView, String> {
    rt.pair_confirm(&node_id, true).await?;
    Ok(rt.view())
}

/// Stop using a peer now. The vault window then rotates the vault key (`rotateKey`).
#[tauri::command]
pub async fn transport_peer_revoke(rt: State<'_, Arc<Runtime>>, node_id: String) -> Result<StatusView, String> {
    rt.peer_revoke(&node_id).await?;
    Ok(rt.view())
}

/// Reconcile with every approved peer now (after a local write, on a timer).
#[tauri::command]
pub async fn transport_sync_now(rt: State<'_, Arc<Runtime>>) -> Result<StatusView, String> {
    rt.sync_now().await?;
    Ok(rt.view())
}

/// The sealed vault file a peer sent, once. The vault window merges it with `reconcileRemote`.
#[tauri::command]
pub fn transport_take_staged(rt: State<'_, Arc<Runtime>>) -> Option<String> {
    rt.take_staged()
}

/// Register the runtime (called from `setup`).
pub fn init(app: &AppHandle, data_dir: PathBuf, vault: Arc<VaultStore>) {
    let rt = start(app, data_dir, vault);
    app.manage(rt);
}
