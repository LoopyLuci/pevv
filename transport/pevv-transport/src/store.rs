//! The seam to the vault engine. The transport only ever sees the **sealed** vault file as
//! opaque bytes plus its revision and hash; it never parses, opens or logs it. The host (the
//! Tauri shell, or Kotlin through UniFFI) implements [`VaultStore`] on top of its own storage,
//! where `reconcileRemote`, `validateFile` and the on-disk CAS (`vault_write(json, expectedRev)`)
//! already live.

use parking_lot::Mutex;

use crate::policy::{fork_remote_wins, Head};
use crate::psp::hash_hex;

/// Result of applying a file to the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Stored.
    Applied,
    /// The store was not at `base` any more (a local write won the race): reconcile again.
    Stale {
        /// The store's current revision.
        rev: u64,
    },
    /// The host rejected the file.
    Rejected,
}

/// What the store did with a fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkOutcome {
    /// True when the peer's copy became the current one (the tiebreak), false when ours stayed.
    pub remote_adopted: bool,
}

/// Storage the engine syncs. Methods are quick and synchronous; the host serialises them.
pub trait VaultStore: Send + Sync {
    /// The vault id this device holds. A peer for another vault is refused at HELLO (R4).
    fn vault_id(&self) -> String;
    /// This device's PEVV roster id.
    fn device_id(&self) -> String;
    /// The current head, if any file is held.
    fn head(&self) -> Option<Head>;
    /// The current sealed file, if any.
    fn current(&self) -> Option<Vec<u8>>;
    /// The host's own check before adoption (`validateFile`, and `readMeta` when unlocked).
    fn validate(&self, rev: u64, bytes: &[u8]) -> bool;
    /// Compare-and-swap: store `bytes` at `rev` only if the current revision is still `base`.
    fn apply(&self, base: u64, rev: u64, bytes: Vec<u8>) -> ApplyOutcome;
    /// Equal revision, different hash (T3). Keep **both** copies (the loser to the device's
    /// local backup), make the deterministic winner current, and tell the user.
    fn resolve_fork(&self, remote: Head, remote_bytes: Vec<u8>) -> ForkOutcome;
}

type Validator = Box<dyn Fn(u64, &[u8]) -> bool + Send + Sync>;

#[derive(Default)]
struct MemInner {
    rev: u64,
    bytes: Option<Vec<u8>>,
    /// Copies that lost a fork, kept for the user.
    forks: Vec<(Head, Vec<u8>)>,
    accept: Option<Validator>,
}

/// In-memory store: the reference implementation and the test double (it is a real store, not
/// a mock of the engine).
pub struct MemoryStore {
    vault: String,
    device: String,
    inner: Mutex<MemInner>,
}

impl MemoryStore {
    /// An empty store for `vault`, as device `device`.
    pub fn new(vault: &str, device: &str) -> Self {
        Self {
            vault: vault.into(),
            device: device.into(),
            inner: Mutex::new(MemInner::default()),
        }
    }

    /// Install a validation hook (stands in for `validateFile`).
    pub fn set_validator(&self, f: impl Fn(u64, &[u8]) -> bool + Send + Sync + 'static) {
        self.inner.lock().accept = Some(Box::new(f));
    }

    /// A local write: bumps nothing, just sets `rev` (the host chooses revisions).
    pub fn write_local(&self, rev: u64, bytes: &[u8]) {
        let mut g = self.inner.lock();
        g.rev = rev;
        g.bytes = Some(bytes.to_vec());
    }

    /// Copies that lost a fork.
    pub fn fork_losers(&self) -> Vec<(Head, Vec<u8>)> {
        self.inner.lock().forks.clone()
    }
}

impl VaultStore for MemoryStore {
    fn vault_id(&self) -> String {
        self.vault.clone()
    }
    fn device_id(&self) -> String {
        self.device.clone()
    }
    fn head(&self) -> Option<Head> {
        let g = self.inner.lock();
        g.bytes.as_ref().map(|b| Head {
            rev: g.rev,
            hash: hash_hex(b),
        })
    }
    fn current(&self) -> Option<Vec<u8>> {
        self.inner.lock().bytes.clone()
    }
    fn validate(&self, rev: u64, bytes: &[u8]) -> bool {
        let g = self.inner.lock();
        g.accept.as_ref().is_none_or(|f| f(rev, bytes))
    }
    fn apply(&self, base: u64, rev: u64, bytes: Vec<u8>) -> ApplyOutcome {
        let mut g = self.inner.lock();
        if g.rev != base {
            return ApplyOutcome::Stale { rev: g.rev };
        }
        g.rev = rev;
        g.bytes = Some(bytes);
        ApplyOutcome::Applied
    }
    fn resolve_fork(&self, remote: Head, remote_bytes: Vec<u8>) -> ForkOutcome {
        let mut g = self.inner.lock();
        let local_hash = g.bytes.as_deref().map(hash_hex).unwrap_or_default();
        if fork_remote_wins(&local_hash, &remote.hash) {
            let loser = g.bytes.replace(remote_bytes);
            let rev = g.rev;
            if let Some(b) = loser {
                g.forks.push((
                    Head {
                        rev,
                        hash: local_hash,
                    },
                    b,
                ));
            }
            ForkOutcome {
                remote_adopted: true,
            }
        } else {
            g.forks.push((remote, remote_bytes));
            ForkOutcome {
                remote_adopted: false,
            }
        }
    }
}
