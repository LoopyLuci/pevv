//! Device transport (Transferd), policy side: the settings file, the list of peers the person
//! approved, the slot where a file from a peer waits for the vault UI, and the checks on that
//! file. No Tauri and no network here, so it is unit-tested on its own and builds with or without
//! the `transferd` feature. The wiring is in `transport.rs`; the protocol is the `pevv-transport`
//! crate (docs/TRANSPORT.md).
//!
//! Only the **sealed** vault file (ciphertext) ever passes through this module. A file from a peer
//! is not written to disk here: it is held and handed to the vault UI, which runs the same
//! merge as for the cloud copy (`reconcileRemote`, `merge.ts`), because only the UI holds a key.

// Parts are used only by the `transferd` build (`transport.rs`); the tests cover all of them.
#![cfg_attr(not(feature = "transferd"), allow(dead_code))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const FILE_NAME: &str = "transferd.json";
/// A sealed vault is about 200 KB at most (docs/TRANSPORT.md 9.4: blob cap 400 KB).
pub const MAX_FILE_BYTES: usize = 400 * 1024;
pub const MAX_RELAYS: usize = 4;
pub const MAX_PEERS: usize = 40;
const MAX_NAME: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    Approved,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerRec {
    pub node_id: String,
    pub name: String,
    pub state: PeerState,
    /// Unix milliseconds of the decision.
    pub at: u64,
}

/// What survives a restart. Off by default; no relay by default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub enabled: bool,
    /// This device's PEVV roster id (the vault UI tells us when it switches the transport on).
    pub device_id: String,
    /// The name shown to the other device when pairing.
    pub device_name: String,
    pub relays: Vec<String>,
    pub direct: Vec<String>,
    pub peers: Vec<PeerRec>,
}

/// A 64-character lowercase hex node id.
pub fn valid_node_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn clean_name(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>().trim().chars().take(MAX_NAME).collect()
}

/// `host:port` for a UDP relay or a direct address. WebSocket relays are not supported by the pinned overlay.
pub fn valid_addr(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.starts_with("ws://") || s.starts_with("wss://") {
        return Err("ws-relay-unsupported".into());
    }
    let ok = s.len() <= 255
        && !s.is_empty()
        && !s.contains(char::is_whitespace)
        && !s.contains('/')
        && s.rsplit_once(':').is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok_and(|p| p > 0));
    if ok {
        Ok(s.to_string())
    } else {
        Err("bad-address".into())
    }
}

fn clean_list(list: &[String], max: usize) -> Result<Vec<String>, String> {
    if list.len() > max {
        return Err("too-many".into());
    }
    let mut out: Vec<String> = Vec::new();
    for a in list {
        let a = valid_addr(a)?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    Ok(out)
}

pub struct SettingsStore {
    path: PathBuf,
    inner: Mutex<Settings>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl SettingsStore {
    /// Load `dir/transferd.json` (missing or unreadable means defaults: off). Creates nothing.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE_NAME);
        let inner = fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str::<Settings>(&s).ok()).unwrap_or_default();
        Self { path, inner: Mutex::new(inner) }
    }

    pub fn get(&self) -> Settings {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn update<T>(&self, f: impl FnOnce(&mut Settings) -> Result<T, String>) -> Result<T, String> {
        let mut g = self.inner.lock().map_err(|_| "poisoned".to_string())?;
        let mut next = g.clone();
        let out = f(&mut next)?;
        if next != *g {
            save(&self.path, &next)?;
            *g = next;
        }
        Ok(out)
    }

    pub fn set_enabled(&self, enabled: bool, device_id: Option<&str>, name: Option<&str>) -> Result<(), String> {
        self.update(|s| {
            s.enabled = enabled;
            if let Some(d) = device_id.filter(|d| !d.is_empty()) {
                s.device_id = d.chars().take(64).collect();
            }
            if let Some(n) = name.map(clean_name).filter(|n| !n.is_empty()) {
                s.device_name = n;
            }
            Ok(())
        })
    }

    pub fn set_addresses(&self, relays: &[String], direct: &[String]) -> Result<(), String> {
        let relays = clean_list(relays, MAX_RELAYS)?;
        let direct = clean_list(direct, MAX_RELAYS)?;
        self.update(|s| {
            s.relays = relays;
            s.direct = direct;
            Ok(())
        })
    }

    /// Record an approved peer (or approve a revoked one again, after a new pairing).
    pub fn approve_peer(&self, node_id: &str, name: &str) -> Result<(), String> {
        if !valid_node_id(node_id) {
            return Err("bad-node-id".into());
        }
        let name = clean_name(name);
        self.update(|s| {
            match s.peers.iter_mut().find(|p| p.node_id == node_id) {
                Some(p) => {
                    p.state = PeerState::Approved;
                    if !name.is_empty() {
                        p.name = name;
                    }
                    p.at = now_ms();
                }
                None => {
                    if s.peers.len() >= MAX_PEERS {
                        return Err("too-many".into());
                    }
                    s.peers.push(PeerRec { node_id: node_id.into(), name, state: PeerState::Approved, at: now_ms() });
                }
            }
            Ok(())
        })
    }

    /// Mark a peer revoked. Unknown nodes are recorded too, so a later pairing cannot silently reuse them.
    pub fn revoke_peer(&self, node_id: &str) -> Result<(), String> {
        if !valid_node_id(node_id) {
            return Err("bad-node-id".into());
        }
        self.update(|s| {
            match s.peers.iter_mut().find(|p| p.node_id == node_id) {
                Some(p) => {
                    p.state = PeerState::Revoked;
                    p.at = now_ms();
                }
                None => s.peers.push(PeerRec { node_id: node_id.into(), name: String::new(), state: PeerState::Revoked, at: now_ms() }),
            }
            Ok(())
        })
    }

    /// The allow-list: approved peers only.
    pub fn approved(&self) -> Vec<String> {
        self.get().peers.into_iter().filter(|p| p.state == PeerState::Approved).map(|p| p.node_id).collect()
    }
}

fn save(path: &Path, s: &Settings) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// SHA-256 of the file bytes, lowercase hex: the `hash` of PSP/1 (as `pevv_transport::psp::hash_hex`).
pub fn hash_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The plaintext envelope fields of a vault file: format, id and rev. Nothing else is read.
pub fn envelope(bytes: &[u8]) -> Option<(String, u64)> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if v.get("format")?.as_str()? != crate::vault_store::VAULT_FORMAT {
        return None;
    }
    Some((v.get("id")?.as_str()?.to_string(), v.get("rev")?.as_u64()?))
}

/// Cheap checks before a peer's file is even held for the vault UI (which then runs `validateFile`,
/// the key checks and the merge): size, format, same vault id, and the revision it claims.
pub fn acceptable(vault_id: &str, rev: u64, bytes: &[u8]) -> bool {
    bytes.len() <= MAX_FILE_BYTES && !vault_id.is_empty() && envelope(bytes).is_some_and(|(id, r)| id == vault_id && r == rev)
}

/// A file from a peer, waiting for the vault UI to merge it.
#[derive(Default)]
pub struct Staged {
    slot: Mutex<Option<(u64, String, String)>>,
}

impl Staged {
    /// Hold `bytes` (a sealed vault file). A copy with a lower revision never replaces a higher one.
    /// Returns false when this exact copy is already held (so no second event is raised).
    pub fn put(&self, rev: u64, bytes: &[u8]) -> bool {
        let Ok(text) = String::from_utf8(bytes.to_vec()) else { return false };
        let hash = hash_hex(bytes);
        let Ok(mut g) = self.slot.lock() else { return false };
        match g.as_ref() {
            Some((r, h, _)) if *r > rev || (*r == rev && *h == hash) => false,
            _ => {
                *g = Some((rev, hash, text));
                true
            }
        }
    }

    pub fn take(&self) -> Option<String> {
        self.slot.lock().ok()?.take().map(|(_, _, t)| t)
    }

    pub fn is_empty(&self) -> bool {
        self.slot.lock().map(|g| g.is_none()).unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const N2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn vault(id: &str, rev: u64) -> Vec<u8> {
        format!(r#"{{"format":"luciverse.pevv","id":"{id}","rev":{rev},"items":[]}}"#).into_bytes()
    }

    #[test]
    fn defaults_are_off_with_no_relay_and_nothing_is_created() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("data");
        let s = SettingsStore::load(&dir);
        let g = s.get();
        assert!(!g.enabled && g.relays.is_empty() && g.direct.is_empty() && g.peers.is_empty());
        assert!(!dir.exists(), "loading writes nothing");
    }

    #[test]
    fn settings_round_trip_and_stay_under_the_given_folder() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("data");
        let s = SettingsStore::load(&dir);
        s.set_enabled(true, Some("dev-1"), Some("  Laptop\n")).unwrap();
        s.set_addresses(&["relay.example:5901".into(), "relay.example:5901".into()], &[]).unwrap();
        s.approve_peer(N1, "Phone").unwrap();
        let again = SettingsStore::load(&dir).get();
        assert!(again.enabled);
        assert_eq!(again.device_id, "dev-1");
        assert_eq!(again.device_name, "Laptop");
        assert_eq!(again.relays, vec!["relay.example:5901"]);
        assert_eq!(again.peers.len(), 1);
        let siblings: Vec<_> = fs::read_dir(t.path()).unwrap().flatten().collect();
        assert_eq!(siblings.len(), 1);
    }

    #[test]
    fn addresses_are_validated() {
        assert!(valid_addr("10.0.0.2:5901").is_ok());
        assert_eq!(valid_addr("wss://relay.example").unwrap_err(), "ws-relay-unsupported");
        assert!(valid_addr("nocolon").is_err());
        assert!(valid_addr("host:0").is_err());
        assert!(valid_addr("a b:1").is_err());
        assert!(valid_addr("http://x:1").is_err());
        let s = SettingsStore::load(tempfile::tempdir().unwrap().path());
        let five: Vec<String> = (0..5).map(|i| format!("a{i}:1")).collect();
        assert!(s.set_addresses(&five, &[]).is_err());
    }

    #[test]
    fn only_approved_peers_are_allowed_and_revoking_removes_them() {
        let t = tempfile::tempdir().unwrap();
        let s = SettingsStore::load(t.path());
        s.approve_peer(N1, "A").unwrap();
        s.approve_peer(N2, "B").unwrap();
        assert_eq!(s.approved().len(), 2);
        s.revoke_peer(N1).unwrap();
        assert_eq!(s.approved(), vec![N2.to_string()]);
        assert!(s.approve_peer("not-a-node", "x").is_err());
        assert!(s.revoke_peer("XYZ").is_err());
        // Revoking an unknown node is remembered.
        let n3 = "c".repeat(64);
        s.revoke_peer(&n3).unwrap();
        assert!(!s.approved().contains(&n3));
        assert_eq!(s.get().peers.len(), 3);
    }

    #[test]
    fn node_ids() {
        assert!(valid_node_id(N1));
        assert!(!valid_node_id(&N1.to_uppercase()));
        assert!(!valid_node_id(&N1[1..]));
    }

    #[test]
    fn peer_files_are_checked_before_they_are_held() {
        let ok = vault("v1", 5);
        assert!(acceptable("v1", 5, &ok));
        assert!(!acceptable("v2", 5, &ok), "another vault");
        assert!(!acceptable("v1", 6, &ok), "rev must match the claim");
        assert!(!acceptable("", 5, &ok));
        assert!(!acceptable("v1", 5, b"not json"));
        assert!(!acceptable("v1", 5, br#"{"format":"other","id":"v1","rev":5}"#));
        let big = format!(r#"{{"format":"luciverse.pevv","id":"v1","rev":5,"pad":"{}"}}"#, "x".repeat(MAX_FILE_BYTES));
        assert!(!acceptable("v1", 5, big.as_bytes()));
    }

    #[test]
    fn staged_keeps_the_newest_and_hands_it_over_once() {
        let st = Staged::default();
        assert!(st.put(3, &vault("v", 3)));
        assert!(!st.put(3, &vault("v", 3)), "same copy again");
        assert!(!st.put(2, &vault("v", 2)), "older never replaces newer");
        assert!(st.put(4, &vault("v", 4)));
        assert!(st.take().unwrap().contains(r#""rev":4"#));
        assert!(st.take().is_none() && st.is_empty());
    }

    #[test]
    fn hash_is_sha256_hex() {
        assert_eq!(hash_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
