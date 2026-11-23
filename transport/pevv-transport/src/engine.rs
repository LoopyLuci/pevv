//! The PSP/1 engine: drives one stream between two devices, enforcing the rules of
//! docs/TRANSPORT.md section 6 (CAS on `rev`, fork detection, hash checks before parsing,
//! one transfer in flight per peer and direction, idle timeout).
//!
//! It works on any `AsyncRead + AsyncWrite` and a peer id the *caller* has already
//! authenticated (the Transferd session, see `bridge`). It never opens, parses or logs the
//! sealed vault file: it carries ciphertext only.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::policy::{decide, push_verdict, AllowList, Decision, Head, PushVerdict};
use crate::psp::{
    hash_hex, read_message, write_message, Announce, BlobHeader, ErrBody, Fetch, Hello, Message,
    PushAck, PushHeader, PushResult, RosterHint, Want, PSP_VERSION,
};
use crate::store::{ApplyOutcome, VaultStore};

/// Idle timeout for one read (doc: blob streams time out after 20 s without progress).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// Something the host may want to show or log. Never carries vault bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEvent {
    /// A newer file from `peer` replaced ours.
    Adopted {
        /// Peer node id.
        peer: String,
        /// New head.
        head: Head,
    },
    /// Equal revision, different file (T3). Both copies are kept by the store.
    Fork {
        /// Peer node id.
        peer: String,
        /// The shared revision.
        rev: u64,
        /// Our hash before resolution.
        local_hash: String,
        /// The peer's hash.
        remote_hash: String,
        /// Whether the peer's copy became current.
        remote_adopted: bool,
    },
    /// Our PUSH was answered.
    PushAnswered {
        /// Peer node id.
        peer: String,
        /// Answer.
        result: PushResult,
    },
    /// A PUSH from `peer` was handled.
    PushHandled {
        /// Peer node id.
        peer: String,
        /// What we answered.
        result: PushResult,
    },
    /// A peer was turned away or dropped by policy.
    Refused {
        /// Peer node id.
        peer: String,
        /// Short reason.
        reason: String,
    },
    /// A ROSTER_HINT removed nodes from the allow-list.
    Revoked {
        /// Node ids removed.
        nodes: Vec<String>,
    },
}

/// Receives events.
pub type EventSink = Arc<dyn Fn(SyncEvent) + Send + Sync>;

/// What one stream achieved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The head the peer reported in its HELLO, if it holds a file.
    pub peer_head: Option<Head>,
    /// Set when we adopted a newer file.
    pub adopted: Option<Head>,
    /// Set when a fork was seen: `(rev, remote_adopted)`.
    pub fork: Option<(u64, bool)>,
    /// The answer to a PUSH we sent.
    pub push: Option<PushResult>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Sync,
    Push,
}

/// The engine. Cheap to clone-by-Arc; one per vault.
pub struct Engine {
    store: Arc<dyn VaultStore>,
    allow: AllowList,
    sink: EventSink,
    busy: Mutex<HashSet<(String, bool)>>,
    idle: Duration,
}

struct BusyGuard<'a> {
    set: &'a Mutex<HashSet<(String, bool)>>,
    key: (String, bool),
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.set.lock().remove(&self.key);
    }
}

fn head_of(store: &dyn VaultStore) -> Option<Head> {
    store.head()
}

impl Engine {
    /// A new engine over `store`, allowing exactly the nodes in `allow`.
    pub fn new(store: Arc<dyn VaultStore>, allow: AllowList, sink: EventSink) -> Self {
        Self {
            store,
            allow,
            sink,
            busy: Mutex::new(HashSet::new()),
            idle: IDLE_TIMEOUT,
        }
    }

    /// Override the idle timeout (tests).
    pub fn with_idle_timeout(mut self, d: Duration) -> Self {
        self.idle = d;
        self
    }

    /// The allow-list handle.
    pub fn allow_list(&self) -> &AllowList {
        &self.allow
    }

    /// Handle a stream the peer opened: HELLO, ANNOUNCE, serve FETCH/PUSH, until BYE.
    pub async fn serve<S>(&self, peer: &str, io: S) -> Result<Report>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.run(peer, io, Mode::Sync, false).await
    }

    /// Open the exchange: HELLO, ANNOUNCE and reconcile (fetch if the peer is ahead).
    pub async fn sync<S>(&self, peer: &str, io: S) -> Result<Report>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.run(peer, io, Mode::Sync, true).await
    }

    /// Like [`Engine::sync`], and also PUSH our head with `base` = the peer's HELLO revision
    /// when we are ahead (a network compare-and-swap).
    pub async fn push<S>(&self, peer: &str, io: S) -> Result<Report>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.run(peer, io, Mode::Push, true).await
    }

    /// Tell a peer that nodes were revoked (ROSTER_HINT). Sends HELLO, the hint and BYE, then
    /// waits for the peer to finish. A hint can only restrict, so the receiver needs no proof.
    pub async fn hint<S>(&self, peer: &str, mut io: S, rev: u64, revoked: Vec<String>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.allow.permits(peer) {
            return Err(self.deny(peer, &mut io, "denied").await);
        }
        // The hint stream announces nothing (rev 0, no hash), so the peer does not wait for an
        // ANNOUNCE or try to fetch from us; ordinary sync runs on its own streams.
        write_message(
            &mut io,
            &Message::Hello(Hello {
                psp: PSP_VERSION,
                vault: self.store.vault_id(),
                dev: self.store.device_id(),
                rev: 0,
                hash: String::new(),
                caps: vec![],
            }),
        )
        .await?;
        write_message(&mut io, &Message::RosterHint(RosterHint { rev, revoked })).await?;
        write_message(&mut io, &Message::Bye).await?;
        // Drain until the peer closes or says BYE.
        while let Some(m) = self.next(&mut io).await? {
            if m == Message::Bye {
                break;
            }
        }
        Ok(())
    }

    fn emit(&self, e: SyncEvent) {
        (self.sink)(e);
    }

    async fn deny<S: AsyncWrite + Unpin>(&self, peer: &str, io: &mut S, code: &str) -> Error {
        let _ = write_message(
            io,
            &Message::Err(ErrBody {
                code: code.into(),
                reason: code.into(),
            }),
        )
        .await;
        self.emit(SyncEvent::Refused {
            peer: peer.into(),
            reason: code.into(),
        });
        Error::Denied
    }

    async fn next<S: AsyncRead + Unpin>(&self, io: &mut S) -> Result<Option<Message>> {
        match tokio::time::timeout(self.idle, read_message(io)).await {
            Ok(r) => r,
            Err(_) => Err(Error::Timeout),
        }
    }

    async fn run<S>(&self, peer: &str, mut io: S, mode: Mode, initiator: bool) -> Result<Report>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // T1: only authenticated, un-revoked, user-approved nodes. Checked before any byte of
        // ours is sent, and again before every message below.
        if !self.allow.permits(peer) {
            return Err(self.deny(peer, &mut io, "denied").await);
        }
        let key = (peer.to_string(), initiator);
        if !self.busy.lock().insert(key.clone()) {
            return Err(self.deny(peer, &mut io, "busy").await);
        }
        let _guard = BusyGuard {
            set: &self.busy,
            key,
        };

        let mut report = Report::default();
        let local = head_of(&*self.store);
        write_message(
            &mut io,
            &Message::Hello(Hello {
                psp: PSP_VERSION,
                vault: self.store.vault_id(),
                dev: self.store.device_id(),
                rev: local.as_ref().map_or(0, |h| h.rev),
                hash: local.as_ref().map(|h| h.hash.clone()).unwrap_or_default(),
                caps: vec![],
            }),
        )
        .await?;
        let hello = loop {
            match self.next(&mut io).await? {
                Some(Message::Hello(h)) => break h,
                Some(Message::Unknown(_)) => continue,
                Some(Message::Err(e)) => {
                    return Err(Error::Protocol(format!("peer refused: {}", e.code)))
                }
                _ => return Err(Error::Protocol("expected HELLO first".into())),
            }
        };
        // R4: a different vault id is refused at HELLO.
        if hello.vault != self.store.vault_id() || hello.psp < 1 {
            return Err(self.deny(peer, &mut io, "vault-mismatch").await);
        }
        let peer_empty = hello.rev == 0 || hello.hash.is_empty();
        if !peer_empty {
            report.peer_head = Some(Head {
                rev: hello.rev,
                hash: hello.hash.clone(),
            });
        }

        let mut peer_announced = peer_empty;
        let mut pending_fetch: Option<u64> = None;
        let mut awaiting_ack = false;
        let mut sent_bye = false;
        let mut got_bye = false;

        if let Some(h) = &local {
            let size = self.store.current().map_or(0, |b| b.len() as u64);
            write_message(
                &mut io,
                &Message::Announce(Announce {
                    rev: h.rev,
                    hash: h.hash.clone(),
                    size,
                }),
            )
            .await?;
            if mode == Mode::Push && hello.rev < h.rev {
                if let Some(bytes) = self.store.current() {
                    let push = PushHeader {
                        base: hello.rev,
                        rev: h.rev,
                        hash: hash_hex(&bytes),
                        size: bytes.len() as u64,
                    };
                    write_message(&mut io, &Message::Push(push, bytes)).await?;
                    awaiting_ack = true;
                }
            }
        }

        loop {
            if !peer_announced || pending_fetch.is_some() || awaiting_ack {
                // not settled yet
            } else if !sent_bye {
                write_message(&mut io, &Message::Bye).await?;
                sent_bye = true;
            }
            if sent_bye && got_bye {
                break;
            }
            let Some(msg) = self.next(&mut io).await? else {
                if pending_fetch.is_some() || awaiting_ack {
                    return Err(Error::Protocol(
                        "stream closed before the exchange ended".into(),
                    ));
                }
                break;
            };
            if !self.allow.permits(peer) {
                return Err(self.deny(peer, &mut io, "revoked").await);
            }
            match msg {
                Message::Announce(a) => {
                    peer_announced = true;
                    let remote = Head {
                        rev: a.rev,
                        hash: a.hash,
                    };
                    let local = head_of(&*self.store);
                    if matches!(
                        decide(local.as_ref(), &remote),
                        Decision::Fetch | Decision::Fork
                    ) {
                        write_message(
                            &mut io,
                            &Message::Fetch(Fetch {
                                have: local.as_ref().map_or(-1, |h| h.rev as i64),
                                want: Want::Rev(remote.rev),
                            }),
                        )
                        .await?;
                        pending_fetch = Some(remote.rev);
                    }
                }
                Message::Fetch(f) => {
                    let local = head_of(&*self.store);
                    let bytes = self.store.current();
                    match (local, bytes) {
                        (Some(h), Some(bytes))
                            if match f.want {
                                Want::Latest => true,
                                Want::Rev(r) => r == h.rev,
                            } =>
                        {
                            let header = BlobHeader {
                                rev: h.rev,
                                hash: hash_hex(&bytes),
                                size: bytes.len() as u64,
                            };
                            write_message(&mut io, &Message::Blob(header, bytes)).await?;
                        }
                        (Some(h), _) => {
                            // Level-triggered: tell the peer what we really have.
                            write_message(
                                &mut io,
                                &Message::Announce(Announce {
                                    rev: h.rev,
                                    hash: h.hash,
                                    size: 0,
                                }),
                            )
                            .await?;
                        }
                        _ => {
                            return Err(self.deny(peer, &mut io, "empty").await);
                        }
                    }
                }
                Message::Blob(h, bytes) => {
                    if pending_fetch.take().is_none() {
                        continue; // unsolicited: ignore
                    }
                    if !self.store.validate(h.rev, &bytes) {
                        let _ = write_message(
                            &mut io,
                            &Message::Err(ErrBody {
                                code: "invalid".into(),
                                reason: "file rejected".into(),
                            }),
                        )
                        .await;
                        return Err(Error::Invalid("rejected by the vault engine".into()));
                    }
                    self.take_blob(peer, h, bytes, &mut report)?;
                }
                Message::Push(h, bytes) => {
                    let result = self.handle_push(peer, h, bytes);
                    let rev = head_of(&*self.store).map_or(0, |h| h.rev);
                    write_message(&mut io, &Message::PushAck(PushAck { result, rev })).await?;
                }
                Message::PushAck(a) => {
                    if awaiting_ack {
                        awaiting_ack = false;
                        report.push = Some(a.result);
                        self.emit(SyncEvent::PushAnswered {
                            peer: peer.into(),
                            result: a.result,
                        });
                    }
                }
                Message::RosterHint(hint) => {
                    // A hint can only restrict.
                    self.allow.revoke(hint.revoked.iter().map(String::as_str));
                    self.emit(SyncEvent::Revoked {
                        nodes: hint.revoked.clone(),
                    });
                    if hint.revoked.iter().any(|n| n.eq_ignore_ascii_case(peer)) {
                        return Err(self.deny(peer, &mut io, "revoked").await);
                    }
                }
                Message::Err(e) => {
                    return Err(Error::Protocol(format!("peer error: {}", e.code)));
                }
                Message::Bye => got_bye = true,
                Message::Hello(_) => {
                    return Err(Error::Protocol("second HELLO".into()));
                }
                Message::Unknown(_) => {}
            }
        }
        Ok(report)
    }

    fn take_blob(
        &self,
        peer: &str,
        h: BlobHeader,
        bytes: Vec<u8>,
        report: &mut Report,
    ) -> Result<()> {
        let local = head_of(&*self.store);
        let local_rev = local.as_ref().map_or(0, |l| l.rev);
        if local.is_none() || h.rev > local_rev {
            match self.store.apply(local_rev, h.rev, bytes) {
                ApplyOutcome::Applied => {
                    let head = Head {
                        rev: h.rev,
                        hash: h.hash,
                    };
                    report.adopted = Some(head.clone());
                    self.emit(SyncEvent::Adopted {
                        peer: peer.into(),
                        head,
                    });
                }
                // A local write won the race; the next announce reconciles again.
                ApplyOutcome::Stale { .. } => {}
                ApplyOutcome::Rejected => {
                    return Err(Error::Invalid("rejected by the vault engine".into()))
                }
            }
        } else if let Some(l) = local {
            if h.rev == l.rev && h.hash != l.hash {
                let remote = Head {
                    rev: h.rev,
                    hash: h.hash.clone(),
                };
                let out = self.store.resolve_fork(remote, bytes);
                report.fork = Some((h.rev, out.remote_adopted));
                self.emit(SyncEvent::Fork {
                    peer: peer.into(),
                    rev: h.rev,
                    local_hash: l.hash,
                    remote_hash: h.hash,
                    remote_adopted: out.remote_adopted,
                });
            }
            // A lower revision is never adopted.
        }
        Ok(())
    }

    fn handle_push(&self, peer: &str, h: PushHeader, bytes: Vec<u8>) -> PushResult {
        let result = self.push_inner(peer, &h, bytes);
        self.emit(SyncEvent::PushHandled {
            peer: peer.into(),
            result,
        });
        result
    }

    fn push_inner(&self, peer: &str, h: &PushHeader, bytes: Vec<u8>) -> PushResult {
        let local = head_of(&*self.store);
        match push_verdict(local.as_ref(), h.base, h.rev, &h.hash) {
            PushVerdict::Invalid => PushResult::Invalid,
            PushVerdict::Stale => PushResult::Stale,
            PushVerdict::AlreadyHave => PushResult::Ok,
            PushVerdict::Fork => {
                if !self.store.validate(h.rev, &bytes) {
                    return PushResult::Invalid;
                }
                let remote = Head {
                    rev: h.rev,
                    hash: h.hash.clone(),
                };
                let local_hash = local.map(|l| l.hash).unwrap_or_default();
                let out = self.store.resolve_fork(remote, bytes);
                self.emit(SyncEvent::Fork {
                    peer: peer.into(),
                    rev: h.rev,
                    local_hash,
                    remote_hash: h.hash.clone(),
                    remote_adopted: out.remote_adopted,
                });
                PushResult::Fork
            }
            PushVerdict::Apply => {
                if !self.store.validate(h.rev, &bytes) {
                    return PushResult::Invalid;
                }
                match self.store.apply(h.base, h.rev, bytes) {
                    ApplyOutcome::Applied => {
                        self.emit(SyncEvent::Adopted {
                            peer: peer.into(),
                            head: Head {
                                rev: h.rev,
                                hash: h.hash.clone(),
                            },
                        });
                        PushResult::Ok
                    }
                    ApplyOutcome::Stale { .. } => PushResult::Stale,
                    ApplyOutcome::Rejected => PushResult::Invalid,
                }
            }
        }
    }
}
