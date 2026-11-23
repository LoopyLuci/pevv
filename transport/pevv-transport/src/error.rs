//! Errors of the transport. Messages never contain vault bytes, keys or seeds.

use thiserror::Error;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum Error {
    /// The transport is switched off (the default). Nothing was started.
    #[error("the device transport is disabled")]
    Disabled,
    /// A PSP/1 frame or message broke the protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A size limit was exceeded.
    #[error("too large: {0}")]
    TooLarge(&'static str),
    /// The peer is not allowed to use the sync service.
    #[error("peer not allowed")]
    Denied,
    /// The peer's file was rejected (hash, size or the app's own validation).
    #[error("invalid vault file: {0}")]
    Invalid(String),
    /// The peer did not make progress in time.
    #[error("timed out")]
    Timeout,
    /// Configuration is not acceptable.
    #[error("configuration: {0}")]
    Config(String),
    /// Sealing or unsealing the identity seed failed.
    #[error("seal: {0}")]
    Seal(String),
    /// A local I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The Transferd overlay refused or failed.
    #[error("overlay: {0}")]
    Overlay(String),
}

/// Crate result.
pub type Result<T> = std::result::Result<T, Error>;
