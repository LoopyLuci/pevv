//! Glue between the PSP engine (byte streams plus an authenticated peer id) and the Transferd
//! overlay (named services and `SessionHandle` streams).
//!
//! Outbound: [`open_stream`] opens `pevv-sync-1-<my id prefix>` on the peer and wraps the
//! overlay stream as an `AsyncRead + AsyncWrite`. No loopback socket is involved.
//!
//! Inbound: the overlay can only forward an exposed service to a local TCP address, and its
//! handler never learns the peer. TODO(U1): replace this with an in-process handler that
//! receives the authenticated peer id. Until then the peer is identified by the **listener**:
//! one loopback listener and one service per allowed peer, the service ACL naming exactly
//! that node id, so the overlay refuses everyone else before a byte is forwarded. The residual
//! weakness is that another process on the same machine can also connect to that loopback
//! port and would be treated as that peer; it can only speak PSP (ciphertext sync) and cannot
//! exceed what the peer may do, but this is why the desktop/Android integration must not ship
//! on this interim (docs/TRANSPORT.md section 3, Android: not acceptable).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use transferd_overlay::{SessionHandle, StreamId};

use crate::engine::Engine;
use crate::error::{Error, Result};

/// Base service name; the version is part of it so a PSP/2 can sit beside it.
pub const SERVICE_BASE: &str = "pevv-sync-1";
const CHUNK: usize = 32 * 1024;

/// The service a node *dials* on its peer: named after the dialler, so the acceptor can keep
/// one listener per peer.
pub fn service_name(dialler_node_id: &str) -> Result<String> {
    let id = dialler_node_id.trim().to_ascii_lowercase();
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Config("node id must be 64 hex characters".into()));
    }
    Ok(format!("{SERVICE_BASE}-{}", &id[..16]))
}

/// Wrap an overlay stream as a duplex byte stream.
pub fn wrap_stream(session: SessionHandle, stream: StreamId) -> DuplexStream {
    let (app, pump) = tokio::io::duplex(2 * CHUNK);
    let (mut from_app, mut to_app) = tokio::io::split(pump);
    let up = session.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        while let Ok(n) = from_app.read(&mut buf).await {
            if n == 0 || up.send(stream, buf[..n].to_vec(), false).await.is_err() {
                break;
            }
        }
        let _ = up.send(stream, Vec::new(), true).await;
    });
    tokio::spawn(async move {
        while let Ok(Some(bytes)) = session.recv(stream).await {
            if to_app.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = to_app.shutdown().await;
        session.close(stream).await;
    });
    app
}

/// A loopback listener serving one peer.
pub struct LoopbackBridge {
    /// Where the overlay forwards that peer's streams.
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl LoopbackBridge {
    /// Listen on 127.0.0.1 (ephemeral port) and run `engine.serve(peer, conn)` per connection.
    pub async fn start(engine: Arc<Engine>, peer: String) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((conn, from)) = listener.accept().await {
                if !from.ip().is_loopback() {
                    continue;
                }
                let engine = engine.clone();
                let peer = peer.clone();
                tokio::spawn(async move {
                    let _ = engine.serve(&peer, conn).await;
                });
            }
        });
        Ok(Self { addr, task })
    }
}

impl Drop for LoopbackBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}
