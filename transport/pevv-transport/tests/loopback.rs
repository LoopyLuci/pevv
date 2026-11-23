//! Two real nodes in one process, talking over the real Transferd overlay on loopback:
//! pairing with the six-word check, a vault blob sync, a CAS conflict, a fork, revocation.
//!
//! Needs `--features overlay`. No relay and no Supabase: node A listens on 127.0.0.1 and its
//! invite carries that address (the LAN / tailnet case); node B has no inbound port at all.
#![cfg(feature = "overlay")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pevv_transport::policy::Head;
use pevv_transport::psp::PushResult;
use pevv_transport::seal::FileSealer;
use pevv_transport::{
    ApplyOutcome, ForkOutcome, MemoryStore, Transport, TransportConfig, TransportEvent, VaultStore,
};

/// A real [`MemoryStore`] that can simulate a local write landing right after the first
/// `head()` call, i.e. just after this device told a peer its revision in HELLO.
struct Racy {
    inner: MemoryStore,
    armed: AtomicBool,
    race: (u64, Vec<u8>),
}

impl VaultStore for Racy {
    fn vault_id(&self) -> String {
        self.inner.vault_id()
    }
    fn device_id(&self) -> String {
        self.inner.device_id()
    }
    fn head(&self) -> Option<Head> {
        let h = self.inner.head();
        if self.armed.swap(false, Ordering::SeqCst) {
            self.inner.write_local(self.race.0, &self.race.1);
        }
        h
    }
    fn current(&self) -> Option<Vec<u8>> {
        self.inner.current()
    }
    fn validate(&self, rev: u64, bytes: &[u8]) -> bool {
        self.inner.validate(rev, bytes)
    }
    fn apply(&self, base: u64, rev: u64, bytes: Vec<u8>) -> ApplyOutcome {
        self.inner.apply(base, rev, bytes)
    }
    fn resolve_fork(&self, remote: Head, bytes: Vec<u8>) -> ForkOutcome {
        self.inner.resolve_fork(remote, bytes)
    }
}

async fn start(
    dir: &std::path::Path,
    name: &str,
    listen: bool,
    store: Arc<dyn VaultStore>,
) -> Arc<Transport> {
    Transport::start(
        TransportConfig {
            enabled: true,
            name: name.into(),
            state_dir: dir.join(name),
            listen: listen.then(|| "127.0.0.1:0".parse().unwrap()),
            direct: vec![],
            relays: vec![], // no relay, and none is defaulted
            punch: false,
        },
        &FileSealer,
        store,
    )
    .await
    .expect("transport starts")
}

async fn next_pair_request(
    rx: &mut tokio::sync::broadcast::Receiver<TransportEvent>,
) -> (String, Vec<String>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("a pairing request arrives")
            .expect("event channel open");
        if let TransportEvent::PairRequest { node_id, sas, .. } = ev {
            return (node_id, sas);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_pair_sync_conflict_fork_and_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let store_a = Arc::new(MemoryStore::new("vault-1", "dev-a"));
    let store_b = Arc::new(Racy {
        inner: MemoryStore::new("vault-1", "dev-b"),
        armed: AtomicBool::new(false),
        race: (5, b"rev5-written-on-b".to_vec()),
    });
    let a = start(dir.path(), "a", true, store_a.clone()).await;
    let b = start(dir.path(), "b", false, store_b.clone()).await;
    assert_ne!(a.node_id(), b.node_id());

    // ---- pairing: invite, six words on both screens, a person approves on A ----------------
    let mut a_events = a.events();
    let invite = a.invite_create(120).expect("invite");
    assert!(
        a.invite_create(120).is_err(),
        "only one invite may be outstanding"
    );
    let info = b
        .invite_accept(&invite, Some("A".into()))
        .await
        .expect("accept");
    assert_eq!(info.node_id, a.node_id());
    let (joiner, a_words) = next_pair_request(&mut a_events).await;
    assert_eq!(joiner, b.node_id());
    assert_eq!(info.sas, a_words, "both screens show the same six words");
    assert_eq!(a_words.len(), 6);

    // Before approval nothing is served to B.
    store_a.write_local(3, b"sealed-vault-ciphertext-rev3");
    assert!(
        b.sync_with(&a.node_id()).await.is_err(),
        "an unapproved node gets no service"
    );
    assert!(store_b.head().is_none());
    a.confirm_pairing(&b.node_id(), true)
        .await
        .expect("approve");

    // ---- 1. a vault blob syncs: B is empty, A is at rev 3 ------------------------------------
    let report = b.sync_with(&a.node_id()).await.expect("sync");
    assert_eq!(report.adopted.as_ref().map(|h| h.rev), Some(3));
    assert_eq!(store_b.current().unwrap(), b"sealed-vault-ciphertext-rev3");

    // ---- 2. CAS conflict: A pushes rev 4 on base 3 while B has just written rev 5 ------------
    store_a.write_local(4, b"sealed-vault-ciphertext-rev4");
    store_b.armed.store(true, Ordering::SeqCst);
    let report = a.push_to(&b.node_id()).await.expect("push");
    assert_eq!(report.push, Some(PushResult::Stale), "B was not at base 3");
    assert_eq!(
        store_b.current().unwrap(),
        b"rev5-written-on-b",
        "the stale push did not overwrite B's newer write"
    );
    // A then fetches and reconciles, and never goes backwards.
    let report = a.sync_with(&b.node_id()).await.expect("reconcile");
    assert_eq!(report.adopted.map(|h| h.rev), Some(5));
    assert_eq!(store_a.current().unwrap(), b"rev5-written-on-b");

    // ---- 3. fork: both write rev 6 independently --------------------------------------------
    store_a.write_local(6, b"edit-on-a");
    store_b.inner.write_local(6, b"edit-on-b");
    let report = a.sync_with(&b.node_id()).await.expect("fork sync");
    assert_eq!(report.fork.map(|f| f.0), Some(6));
    let report_b = b.sync_with(&a.node_id()).await.expect("converge");
    let _ = report_b;
    assert_eq!(store_a.head(), store_b.head(), "both devices converge");
    assert_eq!(store_a.fork_losers().len(), 1, "the losing copy is kept");

    // ---- 4. revoke: B is cut off at once ------------------------------------------------------
    a.revoke(&b.node_id(), 7).await.expect("revoke");
    assert!(
        b.sync_with(&a.node_id()).await.is_err(),
        "revoked node is refused"
    );
    let denied = a.sync_with(&b.node_id()).await;
    assert!(denied.is_err(), "and A will not talk to it either");

    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn disabled_by_default_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = TransportConfig {
        state_dir: dir.path().join("x"),
        ..Default::default()
    };
    assert!(!cfg.enabled);
    let store = Arc::new(MemoryStore::new("v", "d"));
    let r = Transport::start(cfg, &FileSealer, store).await;
    assert!(matches!(r, Err(pevv_transport::Error::Disabled)));
    assert!(!dir.path().join("x").exists());
}
