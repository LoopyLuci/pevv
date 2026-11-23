//! Two engines over an in-memory byte pipe: sync, CAS conflict, fork, policy. Real engines and
//! real stores; only the byte pipe is in memory (the overlay version is in `loopback.rs`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pevv_transport::engine::EventSink;
use pevv_transport::psp::{
    hash_hex, read_message, write_message, Announce, ErrBody, Hello, Message, PushResult,
};
use pevv_transport::{AllowList, Engine, Error, Head, MemoryStore, SyncEvent, VaultStore};

const A: &str = "aa";
const B: &str = "bb";

struct Side {
    me: &'static str,
    store: Arc<MemoryStore>,
    engine: Engine,
    events: Arc<Mutex<Vec<SyncEvent>>>,
}

fn side(vault: &str, dev: &str, peer: &str) -> Side {
    let me = if peer == A { B } else { A };
    let store = Arc::new(MemoryStore::new(vault, dev));
    let allow = AllowList::new();
    allow.allow(peer);
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink: EventSink = {
        let e = events.clone();
        Arc::new(move |ev| e.lock().unwrap().push(ev))
    };
    Side {
        me,
        engine: Engine::new(store.clone(), allow, sink).with_idle_timeout(Duration::from_secs(5)),
        store,
        events,
    }
}

/// Run `initiator.sync/push` against `responder.serve` over a pipe.
async fn exchange(
    init: &Side,
    resp: &Side,
    push: bool,
) -> (
    pevv_transport::Result<pevv_transport::Report>,
    pevv_transport::Result<pevv_transport::Report>,
) {
    let (x, y) = tokio::io::duplex(64 * 1024);
    let i = async {
        if push {
            init.engine.push(resp.me, x).await
        } else {
            init.engine.sync(resp.me, x).await
        }
    };
    let r = resp.engine.serve(init.me, y);
    tokio::join!(i, r)
}

#[tokio::test]
async fn a_newer_file_is_fetched_by_the_side_that_is_behind() {
    let a = side("v", "devA", B);
    let b = side("v", "devB", A);
    a.store.write_local(3, b"ciphertext-rev-3");
    let (ra, rb) = exchange(&b, &a, false).await; // b dials a; b is empty
    rb.unwrap();
    ra.unwrap();
    assert_eq!(b.store.current().unwrap(), b"ciphertext-rev-3");
    assert_eq!(b.store.head().unwrap().rev, 3);
    // And the other way round: a never adopts a lower revision.
    let (_, _) = exchange(&a, &b, false).await;
    assert_eq!(a.store.head().unwrap().rev, 3);
    assert!(b
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, SyncEvent::Adopted { .. })));
}

#[tokio::test]
async fn push_is_a_compare_and_swap_on_base() {
    let a = side("v", "devA", B);
    let b = side("v", "devB", A);
    a.store.write_local(1, b"v1");
    b.store.write_local(1, b"v1");
    // a writes revision 2 and pushes it with base 1: applied.
    a.store.write_local(2, b"v2-from-a");
    let (ra, _) = exchange(&a, &b, true).await;
    assert_eq!(ra.unwrap().push, Some(PushResult::Ok));
    assert_eq!(b.store.current().unwrap(), b"v2-from-a");

    // Now b moves on locally to 3, while a (still believing b is at 2) pushes its own 3.
    b.store.write_local(3, b"v3-from-b");
    a.store.write_local(3, b"v3-from-a"); // same rev, different file: a fork, not a stale push
    let (ra, _) = exchange(&a, &b, true).await;
    // base was b's HELLO rev (3) so a will not push (peer not behind); sync sees the fork instead.
    let ra = ra.unwrap();
    assert!(ra.push.is_none());
    assert!(ra.fork.is_some());

    // A true CAS conflict: b is ahead of the base a believed, so the push is `stale`,
    // answered over the wire, and b keeps its file.
    let (x, y) = tokio::io::duplex(64 * 1024);
    let b2 = side("v", "devB", A);
    b2.store.write_local(6, b"v6");
    let fake = async move {
        let mut x = x;
        write_message(
            &mut x,
            &Message::Hello(Hello {
                psp: 1,
                vault: "v".into(),
                dev: "old".into(),
                rev: 4,
                hash: hash_hex(b"v4"),
                caps: vec![],
            }),
        )
        .await
        .unwrap();
        // pushes rev 5 with base 4 (it thinks b2 is at 4)
        let blob = b"v5-other".to_vec();
        write_message(
            &mut x,
            &Message::Push(
                pevv_transport::psp::PushHeader {
                    base: 4,
                    rev: 5,
                    hash: hash_hex(&blob),
                    size: blob.len() as u64,
                },
                blob,
            ),
        )
        .await
        .unwrap();
        let mut acks = vec![];
        loop {
            match read_message(&mut x).await.unwrap() {
                Some(Message::PushAck(a)) => {
                    acks.push(a);
                    write_message(
                        &mut x,
                        &Message::Announce(Announce {
                            rev: 4,
                            hash: hash_hex(b"v4"),
                            size: 2,
                        }),
                    )
                    .await
                    .unwrap();
                    write_message(&mut x, &Message::Bye).await.unwrap();
                }
                Some(Message::Bye) | None => break,
                _ => {}
            }
        }
        acks
    };
    let (acks, r) = tokio::join!(fake, b2.engine.serve(A, y));
    r.unwrap();
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].result, PushResult::Stale);
    assert_eq!(acks[0].rev, 6);
    assert_eq!(b2.store.current().unwrap(), b"v6");
}

#[tokio::test]
async fn a_fork_keeps_both_copies_and_both_devices_converge() {
    let a = side("v", "devA", B);
    let b = side("v", "devB", A);
    a.store.write_local(4, b"edit-made-on-a");
    b.store.write_local(4, b"edit-made-on-b");
    let (ra, rb) = exchange(&a, &b, false).await;
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra.fork.map(|f| f.0), Some(4));
    assert_eq!(rb.fork.map(|f| f.0), Some(4));
    // Both ended on the same file (higher hash wins) ...
    assert_eq!(a.store.head(), b.store.head());
    // ... and each kept the other's copy as the loser.
    let (ha, hb) = (hash_hex(b"edit-made-on-a"), hash_hex(b"edit-made-on-b"));
    let winner = if hb > ha { &hb } else { &ha };
    assert_eq!(&a.store.head().unwrap().hash, winner);
    let loser_a: Vec<Head> = a.store.fork_losers().into_iter().map(|l| l.0).collect();
    let loser_b: Vec<Head> = b.store.fork_losers().into_iter().map(|l| l.0).collect();
    assert_eq!(loser_a.len(), 1);
    assert_eq!(loser_b.len(), 1);
    assert_ne!(&loser_a[0].hash, winner);
    assert_eq!(loser_a[0].hash, loser_b[0].hash);
    assert!(a
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, SyncEvent::Fork { rev: 4, .. })));
}

#[tokio::test]
async fn a_peer_outside_the_allow_list_gets_nothing_and_another_vault_is_refused() {
    let a = side("v", "devA", B);
    a.store.write_local(2, b"secret-ciphertext");
    // not allowed
    let (x, y) = tokio::io::duplex(1024);
    let outsider = a.engine.serve("cc", y);
    let reader = async move {
        let mut x = x;
        read_message(&mut x).await
    };
    let (r, first) = tokio::join!(outsider, reader);
    assert!(matches!(r, Err(Error::Denied)));
    // The only thing it ever receives is an ERR, never a HELLO or any vault data.
    assert!(matches!(first.unwrap(), Some(Message::Err(ErrBody { .. }))));

    // different vault id
    let other = side("other-vault", "devX", A);
    other.store.write_local(9, b"other");
    let (ra, rb) = exchange(&other, &a, false).await;
    assert!(ra.is_err() && rb.is_err());
    assert_eq!(a.store.head().unwrap().rev, 2);
}

#[tokio::test]
async fn a_roster_hint_revokes_at_once_and_only_restricts() {
    let a = side("v", "devA", B);
    let b = side("v", "devB", A);
    a.engine.allow_list().allow("ee");
    // b tells a that node `bb` (b itself, as a sees it) and an unknown node `dd` were revoked.
    let (x, y) = tokio::io::duplex(64 * 1024);
    let hint = b
        .engine
        .hint(A, x, 9, vec![B.to_string(), "dd".to_string()]);
    let serve = a.engine.serve(B, y);
    let (hr, sr) = tokio::join!(hint, serve);
    hr.unwrap();
    assert!(matches!(sr, Err(Error::Denied)));
    assert!(!a.engine.allow_list().permits(B));
    assert!(!a.engine.allow_list().permits("dd")); // a hint never adds anyone
    assert!(a.engine.allow_list().permits("ee"));
    // After revocation the same peer is refused from the first byte.
    let (x, y) = tokio::io::duplex(1024);
    let (r, first) = tokio::join!(a.engine.serve(B, y), async move {
        let mut x = x;
        read_message(&mut x).await
    });
    assert!(matches!(r, Err(Error::Denied)));
    assert!(matches!(first.unwrap(), Some(Message::Err(_))));
}

#[tokio::test]
async fn a_hostile_blob_the_host_rejects_is_never_stored() {
    let a = side("v", "devA", B);
    let b = side("v", "devB", A);
    a.store.write_local(7, b"not-a-valid-vault");
    b.store.set_validator(|_, bytes| bytes.starts_with(b"{"));
    let (_, rb) = exchange(&b, &a, false).await;
    assert!(rb.is_err());
    assert!(b.store.head().is_none());
}
