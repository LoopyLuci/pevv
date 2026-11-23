//! Run-time configuration. Off by default; there is no default relay (docs/TRANSPORT.md 8.2).

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::error::{Error, Result};

/// The most relays a device may be configured with.
pub const MAX_RELAYS: usize = 4;
/// Shortest and longest invite lifetime, in seconds (Transferd accepts 30 s to 24 h).
pub const INVITE_TTL_MIN: u64 = 30;
/// See [`INVITE_TTL_MIN`].
pub const INVITE_TTL_MAX: u64 = 24 * 3600;
/// PEVV's default invite lifetime (as `HANDOFF_TTL_MS` today).
pub const INVITE_TTL_DEFAULT: u64 = 180;

/// Transport settings.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Master switch. `false` (the default): [`crate::Transport::start`] refuses and nothing
    /// is opened, created or written.
    pub enabled: bool,
    /// Display name published in invites (the device name; never the vault name).
    pub name: String,
    /// Folder for the sealed seed, the overlay state and the audit trail.
    pub state_dir: PathBuf,
    /// Relays as `ip:port` or `host:port` (UDP). **Empty by default; user-configured only.**
    pub relays: Vec<String>,
    /// Addresses to publish for direct dialling (LAN, tailnet).
    pub direct: Vec<String>,
    /// Optional direct listener. `None` (default): no inbound port at all.
    pub listen: Option<SocketAddr>,
    /// Try hole punching to a peer reached over a relay.
    pub punch: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: String::new(),
            state_dir: PathBuf::new(),
            relays: Vec::new(),
            direct: Vec::new(),
            listen: None,
            punch: true,
        }
    }
}

impl TransportConfig {
    /// Check the settings without touching the network.
    pub fn validate(&self) -> Result<()> {
        if self.relays.len() > MAX_RELAYS {
            return Err(Error::Config(format!("at most {MAX_RELAYS} relays")));
        }
        for r in &self.relays {
            let r = r.trim();
            if r.starts_with("wss://") || r.starts_with("ws://") {
                // TODO(U11): the overlay at the pinned revision registers on UDP
                // relays only; a WebSocket relay entry cannot be honoured yet.
                return Err(Error::Config(
                    "WebSocket relays are not supported by the pinned Transferd overlay yet".into(),
                ));
            }
            if r.is_empty() || !r.contains(':') || r.contains(char::is_whitespace) {
                return Err(Error::Config(format!("relay `{r}` is not host:port")));
            }
        }
        if self.state_dir.as_os_str().is_empty() {
            return Err(Error::Config("state_dir is required".into()));
        }
        Ok(())
    }
}

/// Clamp an invite lifetime to what Transferd accepts.
pub fn clamp_ttl(secs: u64) -> u64 {
    secs.clamp(INVITE_TTL_MIN, INVITE_TTL_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_with_no_relay_and_no_listener() {
        let c = TransportConfig::default();
        assert!(!c.enabled);
        assert!(c.relays.is_empty());
        assert!(c.direct.is_empty());
        assert!(c.listen.is_none());
    }

    #[test]
    fn validation() {
        let mut c = TransportConfig {
            state_dir: "x".into(),
            ..Default::default()
        };
        assert!(c.validate().is_ok());
        c.relays = vec!["relay.example:5901".into()];
        assert!(c.validate().is_ok());
        c.relays = vec!["wss://relay.example".into()];
        assert!(c.validate().is_err());
        c.relays = vec!["nocolon".into()];
        assert!(c.validate().is_err());
        c.relays = vec!["a:1".into(); 5];
        assert!(c.validate().is_err());
        assert_eq!(clamp_ttl(1), 30);
        assert_eq!(clamp_ttl(10_000_000), 86_400);
    }
}
