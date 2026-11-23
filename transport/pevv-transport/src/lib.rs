//! `pevv-transport`: PEVV's device-to-device transport (docs/TRANSPORT.md).
//!
//! * [`psp`], [`policy`], [`engine`], [`store`]: PSP/1, the sync protocol, with compare-and-swap
//!   on `rev` and fork detection. Pure protocol code, no network. It carries the **sealed**
//!   vault file as opaque bytes and nothing else: no password, vault key or plaintext ever
//!   enters this crate.
//! * [`seal`]: wrapping the node seed at rest with the OS keystore (not hardware keys).
//! * [`sas`]: the six-word check shown on both screens when pairing.
//! * `transport` (feature `overlay`): the Transferd overlay carrying PSP between paired
//!   devices. **Off by default**: the default build contains no network code, and
//!   [`config::TransportConfig::enabled`] is `false` until the user turns it on. There is no
//!   default relay.
//! * `ffi` (feature `ffi`): UniFFI bindings for Android.

// The UniFFI scaffolding is generated code with a doc comment followed by a blank line.
#![cfg_attr(feature = "ffi", allow(clippy::empty_line_after_doc_comments))]

pub mod config;
pub mod engine;
pub mod error;
pub mod policy;
pub mod psp;
pub mod sas;
pub mod seal;
pub mod store;

#[cfg(feature = "overlay")]
mod bridge;
#[cfg(feature = "overlay")]
pub mod transport;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use config::TransportConfig;
pub use engine::{Engine, Report, SyncEvent};
pub use error::{Error, Result};
pub use policy::{AllowList, Head};
pub use psp::{Message, PushResult};
pub use store::{ApplyOutcome, ForkOutcome, MemoryStore, VaultStore};

#[cfg(feature = "overlay")]
pub use transport::{PairingInfo, Transport, TransportEvent};

// The generated scaffolding looks its types up at the crate root.
#[cfg(feature = "ffi")]
pub use ffi::*;

#[cfg(feature = "ffi")]
uniffi::include_scaffolding!("pevv_transport");
