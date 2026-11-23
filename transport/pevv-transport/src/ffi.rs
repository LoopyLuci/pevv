//! UniFFI surface for Android (interface: `pevv_transport.udl`). Generation only for now: the
//! Android app does not load this yet (docs/TRANSPORT.md phase 5).
//!
//! The wrapper owns a small Tokio runtime and exposes blocking calls, so Kotlin can call it
//! from a background dispatcher without any async bridging.

// Type and field names are dictated by the UDL; they are documented there.
#![allow(missing_docs)]

use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::config::TransportConfig;
use crate::engine::{Report, SyncEvent};
use crate::error::Error;
use crate::policy::Head;
use crate::psp::PushResult;
use crate::seal::{Protection, SeedSealer};
use crate::store::{ApplyOutcome, ForkOutcome, VaultStore};
use crate::transport::{Transport, TransportEvent};

/// Errors across the boundary. Flat on purpose: messages never carry secrets.
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    #[error("disabled")]
    Disabled,
    #[error("config")]
    Config,
    #[error("seal")]
    Seal,
    #[error("overlay")]
    Overlay,
    #[error("protocol")]
    Protocol,
    #[error("denied")]
    Denied,
    #[error("invalid")]
    Invalid,
    #[error("timeout")]
    Timeout,
    #[error("io")]
    Io,
    #[error("callback")]
    Callback,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        FfiError::Callback
    }
}

impl From<Error> for FfiError {
    fn from(e: Error) -> Self {
        match e {
            Error::Disabled => FfiError::Disabled,
            Error::Protocol(_) | Error::TooLarge(_) => FfiError::Protocol,
            Error::Denied => FfiError::Denied,
            Error::Invalid(_) => FfiError::Invalid,
            Error::Timeout => FfiError::Timeout,
            Error::Config(_) => FfiError::Config,
            Error::Seal(_) => FfiError::Seal,
            Error::Io(_) => FfiError::Io,
            Error::Overlay(_) => FfiError::Overlay,
        }
    }
}

pub struct FfiConfig {
    pub enabled: bool,
    pub name: String,
    pub state_dir: String,
    pub relays: Vec<String>,
    pub direct: Vec<String>,
    pub punch: bool,
}

pub struct FfiHead {
    pub rev: u64,
    pub hash: String,
}

pub enum FfiApply {
    Applied,
    Stale,
    Rejected,
}

pub struct FfiPairing {
    pub node_id: String,
    pub key_fingerprint: String,
    pub sas: Vec<String>,
}

pub struct FfiReport {
    pub adopted_rev: Option<u64>,
    pub fork_rev: Option<u64>,
    pub push_result: Option<String>,
}

pub struct FfiEvent {
    pub kind: String,
    pub node_id: String,
    pub detail: String,
    pub sas: Vec<String>,
}

pub trait SeedSealerCallback: Send + Sync {
    fn seal(&self, seed: Vec<u8>) -> Result<Vec<u8>, FfiError>;
    fn unseal(&self, sealed: Vec<u8>) -> Result<Vec<u8>, FfiError>;
}

pub trait VaultStoreCallback: Send + Sync {
    fn vault_id(&self) -> String;
    fn device_id(&self) -> String;
    fn head(&self) -> Option<FfiHead>;
    fn current(&self) -> Option<Vec<u8>>;
    fn validate(&self, rev: u64, sealed_file: Vec<u8>) -> bool;
    fn apply(&self, base: u64, rev: u64, sealed_file: Vec<u8>) -> FfiApply;
    fn resolve_fork(&self, rev: u64, hash: String, sealed_file: Vec<u8>) -> bool;
}

pub trait EventCallback: Send + Sync {
    fn on_event(&self, event: FfiEvent);
}

struct CallbackSealer(Box<dyn SeedSealerCallback>);

impl SeedSealer for CallbackSealer {
    fn seal(&self, seed: &[u8; 64]) -> crate::Result<Vec<u8>> {
        self.0
            .seal(seed.to_vec())
            .map_err(|_| Error::Seal("keystore refused to wrap the seed".into()))
    }
    fn unseal(&self, sealed: &[u8]) -> crate::Result<zeroize::Zeroizing<[u8; 64]>> {
        let plain = zeroize::Zeroizing::new(
            self.0
                .unseal(sealed.to_vec())
                .map_err(|_| Error::Seal("keystore could not unwrap the seed".into()))?,
        );
        if plain.len() != 64 {
            return Err(Error::Seal("unwrapped seed has the wrong length".into()));
        }
        let mut out = zeroize::Zeroizing::new([0u8; 64]);
        out.copy_from_slice(&plain);
        Ok(out)
    }
    fn protection(&self) -> Protection {
        // The Kotlin side is required to use the Android Keystore (doc 4.3).
        Protection::OsKeystore
    }
}

struct CallbackStore(Box<dyn VaultStoreCallback>);

impl VaultStore for CallbackStore {
    fn vault_id(&self) -> String {
        self.0.vault_id()
    }
    fn device_id(&self) -> String {
        self.0.device_id()
    }
    fn head(&self) -> Option<Head> {
        self.0.head().map(|h| Head {
            rev: h.rev,
            hash: h.hash,
        })
    }
    fn current(&self) -> Option<Vec<u8>> {
        self.0.current()
    }
    fn validate(&self, rev: u64, bytes: &[u8]) -> bool {
        self.0.validate(rev, bytes.to_vec())
    }
    fn apply(&self, base: u64, rev: u64, bytes: Vec<u8>) -> ApplyOutcome {
        match self.0.apply(base, rev, bytes) {
            FfiApply::Applied => ApplyOutcome::Applied,
            FfiApply::Stale => ApplyOutcome::Stale {
                rev: self.0.head().map_or(0, |h| h.rev),
            },
            FfiApply::Rejected => ApplyOutcome::Rejected,
        }
    }
    fn resolve_fork(&self, remote: Head, bytes: Vec<u8>) -> ForkOutcome {
        ForkOutcome {
            remote_adopted: self.0.resolve_fork(remote.rev, remote.hash, bytes),
        }
    }
}

pub fn psp_version() -> u32 {
    crate::psp::PSP_VERSION
}

pub fn psp_hash(sealed_file: Vec<u8>) -> String {
    crate::psp::hash_hex(&sealed_file)
}

fn result_str(r: PushResult) -> &'static str {
    match r {
        PushResult::Ok => "ok",
        PushResult::Stale => "stale",
        PushResult::Fork => "fork",
        PushResult::Invalid => "invalid",
        PushResult::Denied => "denied",
    }
}

fn report(r: Report) -> FfiReport {
    FfiReport {
        adopted_rev: r.adopted.map(|h| h.rev),
        fork_rev: r.fork.map(|f| f.0),
        push_result: r.push.map(|p| result_str(p).to_string()),
    }
}

fn event(e: TransportEvent) -> FfiEvent {
    let mk = |kind: &str, node: String, detail: String| FfiEvent {
        kind: kind.into(),
        node_id: node,
        detail,
        sas: vec![],
    };
    match e {
        TransportEvent::Sync(SyncEvent::Adopted { peer, head }) => {
            mk("adopted", peer, format!("rev {}", head.rev))
        }
        TransportEvent::Sync(SyncEvent::Fork {
            peer,
            rev,
            remote_adopted,
            ..
        }) => mk(
            "fork",
            peer,
            format!("rev {rev}, remote adopted: {remote_adopted}"),
        ),
        TransportEvent::Sync(SyncEvent::PushAnswered { peer, result }) => {
            mk("push-answered", peer, result_str(result).into())
        }
        TransportEvent::Sync(SyncEvent::PushHandled { peer, result }) => {
            mk("push-handled", peer, result_str(result).into())
        }
        TransportEvent::Sync(SyncEvent::Refused { peer, reason }) => mk("refused", peer, reason),
        TransportEvent::Sync(SyncEvent::Revoked { nodes }) => {
            mk("revoked", String::new(), nodes.join(","))
        }
        TransportEvent::PairRequest { node_id, name, sas } => FfiEvent {
            kind: "pair-request".into(),
            node_id,
            detail: name,
            sas,
        },
        TransportEvent::PairingResolved { node_id, approved } => {
            mk("pair-resolved", node_id, approved.to_string())
        }
    }
}

/// The object Kotlin holds.
pub struct PevvTransport {
    rt: Runtime,
    inner: Arc<Transport>,
}

impl PevvTransport {
    pub fn new(
        config: FfiConfig,
        sealer: Box<dyn SeedSealerCallback>,
        store: Box<dyn VaultStoreCallback>,
        events: Box<dyn EventCallback>,
    ) -> Result<Self, FfiError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| FfiError::Io)?;
        let cfg = TransportConfig {
            enabled: config.enabled,
            name: config.name,
            state_dir: config.state_dir.into(),
            relays: config.relays,
            direct: config.direct,
            listen: None, // outbound only on a phone
            punch: config.punch,
        };
        let inner = rt.block_on(Transport::start(
            cfg,
            &CallbackSealer(sealer),
            Arc::new(CallbackStore(store)),
        ))?;
        let mut rx = inner.events();
        rt.spawn(async move {
            while let Ok(e) = rx.recv().await {
                events.on_event(event(e));
            }
        });
        Ok(Self { rt, inner })
    }

    pub fn node_id(&self) -> String {
        self.inner.node_id()
    }
    pub fn key_fingerprint(&self) -> String {
        self.inner.key_fingerprint_hex()
    }
    pub fn fingerprint_words(&self) -> Vec<String> {
        self.inner.fingerprint_words()
    }
    pub fn invite_create(&self, ttl_secs: u64) -> Result<String, FfiError> {
        Ok(self.inner.invite_create(ttl_secs)?)
    }
    pub fn cancel_invite(&self) {
        self.inner.cancel_invite()
    }
    pub fn invite_accept(
        &self,
        invite: String,
        name: Option<String>,
    ) -> Result<FfiPairing, FfiError> {
        let p = self.rt.block_on(self.inner.invite_accept(&invite, name))?;
        Ok(FfiPairing {
            node_id: p.node_id,
            key_fingerprint: p.key_fingerprint,
            sas: p.sas,
        })
    }
    pub fn confirm_pairing(&self, node_id: String, approved: bool) -> Result<(), FfiError> {
        Ok(self
            .rt
            .block_on(self.inner.confirm_pairing(&node_id, approved))?)
    }
    pub fn set_allow(&self, node_ids: Vec<String>) -> Result<(), FfiError> {
        Ok(self.rt.block_on(self.inner.set_allow(node_ids))?)
    }
    pub fn revoke(&self, node_id: String, roster_rev: u64) -> Result<(), FfiError> {
        Ok(self.rt.block_on(self.inner.revoke(&node_id, roster_rev))?)
    }
    pub fn sync_with(&self, node_id: String) -> Result<FfiReport, FfiError> {
        Ok(report(self.rt.block_on(self.inner.sync_with(&node_id))?))
    }
    pub fn push_to(&self, node_id: String) -> Result<FfiReport, FfiError> {
        Ok(report(self.rt.block_on(self.inner.push_to(&node_id))?))
    }
    pub fn shutdown(&self) {
        self.inner.shutdown()
    }
}
