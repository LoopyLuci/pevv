//! The Transferd-backed transport (feature `overlay`): identity, pairing with a six-word check,
//! the roster-derived allow-list, and PSP/1 streams over overlay sessions.
//!
//! Where TransferDaemon lacks something the design needs (docs/TRANSPORT.md Appendix B), it is
//! wrapped here and marked `TODO(Un)`; the list is kept in docs/TRANSPORT.md (phase 0 notes).

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::broadcast;
use transferd_overlay::identity::{accept_invite, invite_nonce, key_fingerprint};
use transferd_overlay::{NodeIdentity, OverlayConfig, OverlayNode};

use crate::bridge::{service_name, wrap_stream, LoopbackBridge};
use crate::config::{clamp_ttl, TransportConfig, INVITE_TTL_DEFAULT};
use crate::engine::{Engine, EventSink, Report, SyncEvent};
use crate::error::{Error, Result};
use crate::policy::AllowList;
use crate::sas::{fingerprint_words, sas_words};
use crate::seal::{Protection, SeedFile, SeedSealer};
use crate::store::VaultStore;

const SEED_FILE: &str = "pevv-node-seed.sealed";
const STATE_FILE: &str = "overlay-state.json";
const AUDIT_FILE: &str = "overlay-audit.jsonl";

/// What the host UI is told about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// Sync activity (never carries vault bytes).
    Sync(SyncEvent),
    /// Someone used our invite. Show the words, ask the person, then call
    /// [`Transport::confirm_pairing`]. Nothing is sent to that node before approval.
    PairRequest {
        /// The node asking to join.
        node_id: String,
        /// The name it gave.
        name: String,
        /// The six words that must match the other screen.
        sas: Vec<String>,
    },
    /// A pairing was approved or declined.
    PairingResolved {
        /// The node.
        node_id: String,
        /// Whether it may now sync.
        approved: bool,
    },
}

/// Result of accepting an invite on the joining device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingInfo {
    /// The inviting node.
    pub node_id: String,
    /// The inviter's key fingerprint (hex).
    pub key_fingerprint: String,
    /// The six words to compare with the inviter's screen.
    pub sas: Vec<String>,
}

struct Pending {
    name: String,
    sas: Vec<String>,
}

/// The device transport. One per process; cheap to share.
pub struct Transport {
    node: Arc<OverlayNode>,
    engine: Arc<Engine>,
    allow: AllowList,
    cfg: TransportConfig,
    fingerprint: [u8; 32],
    protection: Protection,
    bridges: Mutex<HashMap<String, LoopbackBridge>>,
    pending: Mutex<HashMap<String, Pending>>,
    outstanding: Mutex<Option<([u8; 16], u64)>>,
    cancelled: Mutex<Vec<[u8; 16]>>,
    events: broadcast::Sender<TransportEvent>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

fn now() -> u64 {
    transferd_overlay::identity::now_secs()
}

async fn resolve_relay(spec: &str) -> Result<String> {
    if spec.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(spec.to_string());
    }
    let mut it = tokio::net::lookup_host(spec)
        .await
        .map_err(|e| Error::Config(format!("relay {spec}: {e}")))?;
    it.next()
        .map(|a| a.to_string())
        .ok_or_else(|| Error::Config(format!("relay {spec} did not resolve")))
}

impl Transport {
    /// Start the transport. Returns [`Error::Disabled`] unless `cfg.enabled`: the default
    /// configuration opens, creates and writes nothing.
    pub async fn start(
        cfg: TransportConfig,
        sealer: &dyn SeedSealer,
        store: Arc<dyn VaultStore>,
    ) -> Result<Arc<Self>> {
        if !cfg.enabled {
            return Err(Error::Disabled);
        }
        cfg.validate()?;
        std::fs::create_dir_all(&cfg.state_dir)?;

        let seed = SeedFile::new(cfg.state_dir.join(SEED_FILE)).load_or_create(sealer)?;
        let identity = NodeIdentity::from_seed(&seed, cfg.name.clone());
        drop(seed); // zeroised on drop; only the derived key lives on
        let fingerprint = key_fingerprint(&identity.hybrid_public_key());

        let mut relays = Vec::new();
        for r in &cfg.relays {
            relays.push(resolve_relay(r.trim()).await?);
        }
        let node = OverlayNode::start(OverlayConfig {
            relays,
            direct: cfg.direct.clone(),
            listen: cfg.listen,
            state_path: Some(cfg.state_dir.join(STATE_FILE)),
            audit_path: Some(cfg.state_dir.join(AUDIT_FILE)),
            punch: cfg.punch,
            ..OverlayConfig::local(identity)
        })
        .await
        .map_err(|e| Error::Overlay(e.to_string()))?;

        // The overlay restores exposures from its state file; they point at loopback ports of
        // a previous run that another process could now own. Drop every PEVV one.
        for s in node.services() {
            if s.name.starts_with(crate::bridge::SERVICE_BASE) {
                let _ = node.unexpose(&s.name);
            }
        }

        let (tx, _) = broadcast::channel(256);
        let allow = AllowList::new();
        let sink: EventSink = {
            let tx = tx.clone();
            Arc::new(move |e| {
                let _ = tx.send(TransportEvent::Sync(e));
            })
        };
        let engine = Arc::new(Engine::new(store, allow.clone(), sink));
        let t = Arc::new(Self {
            node,
            engine,
            allow,
            cfg,
            fingerprint,
            protection: sealer.protection(),
            bridges: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            outstanding: Mutex::new(None),
            cancelled: Mutex::new(Vec::new()),
            events: tx,
            tasks: Mutex::new(Vec::new()),
        });
        t.spawn_pairing_watcher();
        Ok(t)
    }

    /// This device's node id (64 hex).
    pub fn node_id(&self) -> String {
        self.node.node_id()
    }

    /// This device's key fingerprint (64 hex): what the roster stores as `node.fp`.
    pub fn key_fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// The fingerprint as eight words, for comparing two screens.
    pub fn fingerprint_words(&self) -> Vec<String> {
        fingerprint_words(&self.fingerprint)
    }

    /// How the seed is protected at rest. Show it; do not claim hardware.
    pub fn seed_protection(&self) -> Protection {
        self.protection
    }

    /// Subscribe to events.
    pub fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.events.subscribe()
    }

    /// The configuration in force.
    pub fn config(&self) -> &TransportConfig {
        &self.cfg
    }

    /// Create an invite (QR payload `tdov2:...`). At most one is outstanding: asking again
    /// before it expires or is cancelled is an error.
    pub fn invite_create(&self, ttl_secs: u64) -> Result<String> {
        let ttl = clamp_ttl(if ttl_secs == 0 {
            INVITE_TTL_DEFAULT
        } else {
            ttl_secs
        });
        let mut out = self.outstanding.lock();
        if let Some((_, exp)) = *out {
            if exp > now() {
                return Err(Error::Config(
                    "an invite is already outstanding; cancel it first".into(),
                ));
            }
        }
        let invite = self.node.invite_create(ttl);
        let nonce =
            invite_nonce(&invite).ok_or_else(|| Error::Overlay("invite has no nonce".into()))?;
        *out = Some((nonce, now() + ttl));
        Ok(invite)
    }

    /// Cancel the outstanding invite.
    ///
    /// TODO(U13): the overlay cannot remove a nonce; it stays valid at the overlay layer.
    /// Here it is neutralised: a node that uses it is refused at the PEVV layer (never
    /// allowed, so it gets no service), which is what protects the vault.
    pub fn cancel_invite(&self) {
        if let Some((nonce, _)) = self.outstanding.lock().take() {
            self.cancelled.lock().push(nonce);
        }
    }

    /// Join a vault holder: verify the invite, pair at the overlay level, trust the inviter
    /// (we scanned its invite ourselves), and return the words to compare with its screen.
    pub async fn invite_accept(&self, invite: &str, name: Option<String>) -> Result<PairingInfo> {
        let verified = accept_invite(invite).map_err(|e| Error::Overlay(e.to_string()))?;
        let nonce =
            invite_nonce(invite).ok_or_else(|| Error::Overlay("invite has no nonce".into()))?;
        self.node
            .invite_accept(invite, name)
            .map_err(|e| Error::Overlay(e.to_string()))?;
        let sas = sas_words(&verified.key_fingerprint, &self.node.node_id(), &nonce);
        self.allow.allow(&verified.node_id);
        self.ensure_bridge(&verified.node_id).await?;
        // Dial now: the first HELLO carries the nonce that tells the inviter we paired.
        self.node
            .ensure_session(&verified.node_id)
            .await
            .map_err(|e| Error::Overlay(e.to_string()))?;
        Ok(PairingInfo {
            node_id: verified.node_id,
            key_fingerprint: hex::encode(verified.key_fingerprint),
            sas,
        })
    }

    /// Pairing requests waiting for a person.
    pub fn pending_pairings(&self) -> Vec<(String, String, Vec<String>)> {
        self.pending
            .lock()
            .iter()
            .map(|(k, p)| (k.clone(), p.name.clone(), p.sas.clone()))
            .collect()
    }

    /// The person compared the words and decided. Approval is the only way a newly paired node
    /// gets onto the allow-list and the sync service. A decline ends its session and never
    /// exposes anything to it.
    ///
    /// TODO(U2): the overlay has no `unpair`; a declined node stays in its paired set and may
    /// re-establish a session (learning presence and addresses). It cannot reach the PEVV
    /// service, which is gated by the per-node ACL managed here.
    pub async fn confirm_pairing(&self, node_id: &str, approved: bool) -> Result<()> {
        let node_id = node_id.to_ascii_lowercase();
        if self.pending.lock().remove(&node_id).is_none() {
            return Err(Error::Config("no such pairing request".into()));
        }
        if approved {
            self.allow.allow(&node_id);
            self.ensure_bridge(&node_id).await?;
        } else {
            self.drop_peer(&node_id).await;
        }
        let _ = self
            .events
            .send(TransportEvent::PairingResolved { node_id, approved });
        Ok(())
    }

    /// Install the allow-list derived from the sealed roster
    /// (`{ entry.node.id : entry in roster, entry.id not in revokedDevices }`). Nodes that left
    /// the list lose their service and session at once; nodes that joined get a service.
    pub async fn set_allow(&self, nodes: Vec<String>) -> Result<()> {
        let want: Vec<String> = nodes.iter().map(|n| n.to_ascii_lowercase()).collect();
        let current = self.allow.list();
        for gone in current.iter().filter(|n| !want.contains(n)) {
            self.drop_peer(gone).await;
        }
        self.allow.set(want.clone());
        for n in &want {
            self.ensure_bridge(n).await?;
        }
        Ok(())
    }

    /// Revoke a device now: allow-list, service and session (section 4.5, steps 1 to 3),
    /// then a best-effort ROSTER_HINT to every other allowed peer.
    ///
    /// Does not and cannot change the vault key: that needs re-keying (doc question 7).
    pub async fn revoke(&self, node_id: &str, roster_rev: u64) -> Result<()> {
        let node_id = node_id.to_ascii_lowercase();
        self.drop_peer(&node_id).await;
        self.allow.revoke([node_id.as_str()]);
        for other in self.allow.list() {
            let hint = self.open_io(&other).await;
            if let Ok(io) = hint {
                let _ = self
                    .engine
                    .hint(&other, io, roster_rev, vec![node_id.clone()])
                    .await;
            }
        }
        Ok(())
    }

    async fn drop_peer(&self, node_id: &str) {
        self.bridges.lock().remove(node_id); // drops the listener task
        let _ = self
            .node
            .unexpose(&service_name(node_id).unwrap_or_default());
        self.allow.revoke([node_id]);
        // End a live session only; never dial a peer just to drop it.
        let live = self
            .node
            .peer_list()
            .iter()
            .any(|p| p["node_id"] == node_id && p["state"] == "up");
        if live {
            if let Ok(s) = self.node.ensure_session(node_id).await {
                s.shutdown().await;
            }
        }
    }

    async fn ensure_bridge(&self, node_id: &str) -> Result<()> {
        let node_id = node_id.to_ascii_lowercase();
        if self.bridges.lock().contains_key(&node_id) {
            return Ok(());
        }
        // The service a peer dials is named after the *peer*, so it can be told apart.
        let name = service_name(&node_id)?;
        let bridge = LoopbackBridge::start(self.engine.clone(), node_id.clone()).await?;
        self.node
            .expose(
                &name,
                bridge.addr,
                vec![node_id.clone()],
                "PEVV sync (ciphertext)",
            )
            .map_err(|e| Error::Overlay(e.to_string()))?;
        self.bridges.lock().insert(node_id, bridge);
        Ok(())
    }

    async fn open_io(&self, peer: &str) -> Result<tokio::io::DuplexStream> {
        if !self.allow.permits(peer) {
            return Err(Error::Denied);
        }
        let session = self
            .node
            .ensure_session(peer)
            .await
            .map_err(|e| Error::Overlay(e.to_string()))?;
        // We dial the service named after us.
        let service = service_name(&self.node.node_id())?;
        let stream = session
            .open(&service)
            .await
            .map_err(|e| Error::Overlay(e.to_string()))?;
        Ok(wrap_stream(session, stream))
    }

    /// Reconcile with `peer`: announce, fetch if it is ahead, serve its fetch if we are.
    pub async fn sync_with(&self, peer: &str) -> Result<Report> {
        let peer = peer.to_ascii_lowercase();
        let io = self.open_io(&peer).await?;
        self.engine.sync(&peer, io).await
    }

    /// Like [`Self::sync_with`], and push our head with a compare-and-swap on the peer's `rev`
    /// when we are ahead (call after a local write).
    pub async fn push_to(&self, peer: &str) -> Result<Report> {
        let peer = peer.to_ascii_lowercase();
        let io = self.open_io(&peer).await?;
        self.engine.push(&peer, io).await
    }

    /// Stop the transport: close bridges and tasks. The overlay node ends when dropped.
    pub fn shutdown(&self) {
        self.bridges.lock().clear();
        for t in self.tasks.lock().drain(..) {
            t.abort();
        }
    }

    fn spawn_pairing_watcher(self: &Arc<Self>) {
        let mut rx = self.node.events().subscribe();
        let me = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            while let Ok(ev) = rx.recv().await {
                let Some(me) = me.upgrade() else { break };
                if ev.kind != "peer.paired" || !ev.detail.ends_with("accepted our invite") {
                    continue;
                }
                if me.allow.permits(&ev.node_id) || me.pending.lock().contains_key(&ev.node_id) {
                    continue;
                }
                let name = ev
                    .detail
                    .trim_end_matches(" accepted our invite")
                    .to_string();
                tokio::spawn(async move { me.on_pair_request(ev.node_id, name).await });
            }
        });
        self.tasks.lock().push(task);
    }

    async fn on_pair_request(self: Arc<Self>, node_id: String, name: String) {
        let Some((nonce, _)) = *self.outstanding.lock() else {
            // No invite of ours is outstanding (cancelled or expired): never approve.
            let _ = self.events.send(TransportEvent::PairingResolved {
                node_id,
                approved: false,
            });
            return;
        };
        if self.cancelled.lock().contains(&nonce) {
            return;
        }
        *self.outstanding.lock() = None; // the invite is spent
        let sas = sas_words(&self.fingerprint, &node_id, &nonce);
        self.pending.lock().insert(
            node_id.clone(),
            Pending {
                name: name.clone(),
                sas: sas.clone(),
            },
        );
        let _ = self
            .events
            .send(TransportEvent::PairRequest { node_id, name, sas });
    }
}
