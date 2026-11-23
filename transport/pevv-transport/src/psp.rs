//! PSP/1, the PEVV sync protocol: message types and framing (docs/TRANSPORT.md section 6.1).
//!
//! Frame on a stream: `type u8 | flags u8 | len u32 BE | body`. Control bodies are UTF-8 JSON,
//! at most [`MAX_CONTROL`] bytes. BLOB and PUSH bodies are a JSON header (the frame `len`
//! covers the header only) followed by exactly `size` raw bytes of sealed vault file.
//! Unknown `type` values are skipped using `len`; unknown JSON fields are ignored.
//!
//! This module is pure: it works on byte slices and any `AsyncRead`/`AsyncWrite`, so the same
//! code serves the loopback bridge, tests and the golden vectors of phase 2.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// The protocol version this build speaks.
pub const PSP_VERSION: u32 = 1;
/// Largest JSON control body.
pub const MAX_CONTROL: usize = 16 * 1024;
/// Largest sealed vault file accepted or sent (doc: blob 400 KB).
pub const MAX_BLOB: usize = 400 * 1024;
/// Header: type, flags, 4-byte length.
pub const HEADER_LEN: usize = 6;

/// Frame type codes.
pub mod kind {
    /// First frame each way.
    pub const HELLO: u8 = 0x01;
    /// "I have this revision."
    pub const ANNOUNCE: u8 = 0x02;
    /// Ask for a revision.
    pub const FETCH: u8 = 0x03;
    /// The vault file.
    pub const BLOB: u8 = 0x04;
    /// "Replace your rev `base` with this."
    pub const PUSH: u8 = 0x05;
    /// Answer to PUSH.
    pub const PUSH_ACK: u8 = 0x06;
    /// Early revocation notice.
    pub const ROSTER_HINT: u8 = 0x07;
    /// Protocol or policy error; the stream closes after it.
    pub const ERR: u8 = 0x7e;
    /// Clean close.
    pub const BYE: u8 = 0x7f;
}

/// SHA-256 of a sealed vault file, lowercase hex (the `hash` of every message).
pub fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `want` in FETCH: a revision number or the latest one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Want {
    /// This exact revision.
    Rev(u64),
    /// Whatever the peer has newest.
    Latest,
}

impl Serialize for Want {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Want::Rev(r) => s.serialize_u64(*r),
            Want::Latest => s.serialize_str("latest"),
        }
    }
}

impl<'de> Deserialize<'de> for Want {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::String(s) if s == "latest" => Ok(Want::Latest),
            serde_json::Value::Number(n) => n
                .as_u64()
                .map(Want::Rev)
                .ok_or_else(|| serde::de::Error::custom("want must be a revision or \"latest\"")),
            _ => Err(serde::de::Error::custom(
                "want must be a revision or \"latest\"",
            )),
        }
    }
}

/// Result codes of PUSH_ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushResult {
    /// Applied (or already had exactly this file).
    Ok,
    /// The receiver is not at `base`: fetch and reconcile.
    Stale,
    /// Same revision, different hash.
    Fork,
    /// Hash, size or validation failed.
    Invalid,
    /// The sender may not push.
    Denied,
}

/// HELLO body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol version.
    pub psp: u32,
    /// Vault id.
    pub vault: String,
    /// PEVV device id (the roster id, not the node id).
    pub dev: String,
    /// Highest revision held (0 when none).
    pub rev: u64,
    /// SHA-256 of that file (empty when none).
    #[serde(default)]
    pub hash: String,
    /// Optional feature names.
    #[serde(default)]
    pub caps: Vec<String>,
}

/// ANNOUNCE body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announce {
    /// Revision.
    pub rev: u64,
    /// SHA-256 hex of the file.
    pub hash: String,
    /// Size in bytes.
    pub size: u64,
}

/// FETCH body. `have` is my revision, or -1 when I hold nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fetch {
    /// My revision (or -1).
    pub have: i64,
    /// What I want.
    pub want: Want,
}

/// BLOB header; `size` raw bytes follow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobHeader {
    /// Revision of the file.
    pub rev: u64,
    /// SHA-256 hex.
    pub hash: String,
    /// Byte length.
    pub size: u64,
}

/// PUSH header; `size` raw bytes follow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushHeader {
    /// The revision the sender believes the receiver is at.
    pub base: u64,
    /// Revision of the pushed file.
    pub rev: u64,
    /// SHA-256 hex.
    pub hash: String,
    /// Byte length.
    pub size: u64,
}

/// PUSH_ACK body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushAck {
    /// Outcome.
    pub result: PushResult,
    /// The receiver's revision after handling the push.
    pub rev: u64,
}

/// ROSTER_HINT body. A hint can only restrict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterHint {
    /// Revision of the roster the hint comes from.
    pub rev: u64,
    /// Node ids that were revoked.
    pub revoked: Vec<String>,
}

/// ERR body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrBody {
    /// Machine code.
    pub code: String,
    /// Human text (never secrets).
    pub reason: String,
}

/// One decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// HELLO.
    Hello(Hello),
    /// ANNOUNCE.
    Announce(Announce),
    /// FETCH.
    Fetch(Fetch),
    /// BLOB with its bytes.
    Blob(BlobHeader, Vec<u8>),
    /// PUSH with its bytes.
    Push(PushHeader, Vec<u8>),
    /// PUSH_ACK.
    PushAck(PushAck),
    /// ROSTER_HINT.
    RosterHint(RosterHint),
    /// ERR.
    Err(ErrBody),
    /// BYE.
    Bye,
    /// A type this version does not know; skipped, kept so callers can count them.
    Unknown(u8),
}

fn json<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(v).map_err(|e| Error::Protocol(e.to_string()))?;
    if body.len() > MAX_CONTROL {
        return Err(Error::TooLarge("control body"));
    }
    Ok(body)
}

fn frame(ty: u8, body: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len() + tail.len());
    out.push(ty);
    out.push(0); // flags: reserved, ignored on receive
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(tail);
    out
}

impl Message {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Message::Hello(b) => frame(kind::HELLO, &json(b)?, &[]),
            Message::Announce(b) => frame(kind::ANNOUNCE, &json(b)?, &[]),
            Message::Fetch(b) => frame(kind::FETCH, &json(b)?, &[]),
            Message::Blob(h, bytes) => {
                check_blob(h.size, h.hash.as_str(), bytes)?;
                frame(kind::BLOB, &json(h)?, bytes)
            }
            Message::Push(h, bytes) => {
                check_blob(h.size, h.hash.as_str(), bytes)?;
                frame(kind::PUSH, &json(h)?, bytes)
            }
            Message::PushAck(b) => frame(kind::PUSH_ACK, &json(b)?, &[]),
            Message::RosterHint(b) => frame(kind::ROSTER_HINT, &json(b)?, &[]),
            Message::Err(b) => frame(kind::ERR, &json(b)?, &[]),
            Message::Bye => frame(kind::BYE, b"{}", &[]),
            Message::Unknown(_) => return Err(Error::Protocol("cannot encode unknown".into())),
        })
    }

    /// Decode one whole frame from a byte slice; returns the message and the bytes consumed.
    /// Used by golden vectors and fuzzing; streams use [`read_message`].
    pub fn decode(buf: &[u8]) -> Result<(Message, usize)> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Protocol("short frame".into()));
        }
        let ty = buf[0];
        let len = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
        if len > MAX_CONTROL {
            return Err(Error::TooLarge("control body"));
        }
        let end = HEADER_LEN + len;
        if buf.len() < end {
            return Err(Error::Protocol("truncated frame".into()));
        }
        let body = &buf[HEADER_LEN..end];
        match ty {
            kind::BLOB | kind::PUSH => {
                let size = declared_size(ty, body)?;
                let total = end + size;
                if buf.len() < total {
                    return Err(Error::Protocol("truncated blob".into()));
                }
                Ok((parse(ty, body, Some(buf[end..total].to_vec()))?, total))
            }
            _ => Ok((parse(ty, body, None)?, end)),
        }
    }
}

fn check_blob(size: u64, hash: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_BLOB {
        return Err(Error::TooLarge("blob"));
    }
    if size != bytes.len() as u64 {
        return Err(Error::Invalid("size does not match the bytes".into()));
    }
    if hash != hash_hex(bytes) {
        return Err(Error::Invalid("hash does not match the bytes".into()));
    }
    Ok(())
}

fn declared_size(ty: u8, body: &[u8]) -> Result<usize> {
    let size = if ty == kind::BLOB {
        serde_json::from_slice::<BlobHeader>(body)
            .map_err(|e| Error::Protocol(e.to_string()))?
            .size
    } else {
        serde_json::from_slice::<PushHeader>(body)
            .map_err(|e| Error::Protocol(e.to_string()))?
            .size
    };
    if size > MAX_BLOB as u64 {
        return Err(Error::TooLarge("blob"));
    }
    Ok(size as usize)
}

fn parse(ty: u8, body: &[u8], tail: Option<Vec<u8>>) -> Result<Message> {
    fn de<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T> {
        serde_json::from_slice(b).map_err(|e| Error::Protocol(e.to_string()))
    }
    Ok(match ty {
        kind::HELLO => Message::Hello(de(body)?),
        kind::ANNOUNCE => Message::Announce(de(body)?),
        kind::FETCH => Message::Fetch(de(body)?),
        kind::BLOB => {
            let h: BlobHeader = de(body)?;
            let bytes = tail.unwrap_or_default();
            check_blob(h.size, &h.hash, &bytes)?;
            Message::Blob(h, bytes)
        }
        kind::PUSH => {
            let h: PushHeader = de(body)?;
            let bytes = tail.unwrap_or_default();
            check_blob(h.size, &h.hash, &bytes)?;
            Message::Push(h, bytes)
        }
        kind::PUSH_ACK => Message::PushAck(de(body)?),
        kind::ROSTER_HINT => Message::RosterHint(de(body)?),
        kind::ERR => Message::Err(de(body)?),
        kind::BYE => Message::Bye,
        other => Message::Unknown(other),
    })
}

/// Read one message from a stream. `Ok(None)` is a clean end of stream before a frame starts.
/// Hash and size of a blob are verified here, before anything is parsed further.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Message>> {
    let mut head = [0u8; HEADER_LEN];
    match r.read_exact(&mut head[..1]).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    r.read_exact(&mut head[1..]).await?;
    let ty = head[0];
    let len = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as usize;
    if len > MAX_CONTROL {
        return Err(Error::TooLarge("control body"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    let tail = if ty == kind::BLOB || ty == kind::PUSH {
        let size = declared_size(ty, &body)?;
        let mut bytes = vec![0u8; size];
        r.read_exact(&mut bytes).await?;
        Some(bytes)
    } else {
        None
    };
    parse(ty, &body, tail).map(Some)
}

/// Write one message and flush.
pub async fn write_message<W: AsyncWrite + Unpin>(w: &mut W, m: &Message) -> Result<()> {
    w.write_all(&m.encode()?).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(bytes: &[u8]) -> (BlobHeader, Vec<u8>) {
        (
            BlobHeader {
                rev: 3,
                hash: hash_hex(bytes),
                size: bytes.len() as u64,
            },
            bytes.to_vec(),
        )
    }

    #[test]
    fn every_message_round_trips() {
        let (bh, bb) = blob(b"sealed-vault-ciphertext");
        let msgs = vec![
            Message::Hello(Hello {
                psp: 1,
                vault: "v1".into(),
                dev: "d1".into(),
                rev: 2,
                hash: "ab".into(),
                caps: vec![],
            }),
            Message::Announce(Announce {
                rev: 2,
                hash: "ab".into(),
                size: 9,
            }),
            Message::Fetch(Fetch {
                have: -1,
                want: Want::Latest,
            }),
            Message::Fetch(Fetch {
                have: 4,
                want: Want::Rev(5),
            }),
            Message::Blob(bh.clone(), bb.clone()),
            Message::Push(
                PushHeader {
                    base: 2,
                    rev: 3,
                    hash: bh.hash.clone(),
                    size: bh.size,
                },
                bb,
            ),
            Message::PushAck(PushAck {
                result: PushResult::Fork,
                rev: 3,
            }),
            Message::RosterHint(RosterHint {
                rev: 7,
                revoked: vec!["aa".repeat(32)],
            }),
            Message::Err(ErrBody {
                code: "x".into(),
                reason: "y".into(),
            }),
            Message::Bye,
        ];
        for m in msgs {
            let wire = m.encode().unwrap();
            let (back, used) = Message::decode(&wire).unwrap();
            assert_eq!(back, m);
            assert_eq!(used, wire.len());
        }
    }

    #[test]
    fn framing_is_type_flags_len_be() {
        let wire = Message::Bye.encode().unwrap();
        assert_eq!(wire, [0x7f, 0, 0, 0, 0, 2, b'{', b'}']);
    }

    #[test]
    fn unknown_types_are_skipped_by_length_and_unknown_fields_ignored() {
        let mut wire = frame(0x55, b"whatever", &[]);
        let (m, used) = Message::decode(&wire).unwrap();
        assert_eq!(m, Message::Unknown(0x55));
        assert_eq!(used, wire.len());
        wire = frame(
            kind::ANNOUNCE,
            br#"{"rev":1,"hash":"h","size":2,"extra":true}"#,
            &[],
        );
        assert!(matches!(
            Message::decode(&wire).unwrap().0,
            Message::Announce(_)
        ));
    }

    #[test]
    fn oversize_and_mismatch_are_rejected() {
        let mut wire = vec![kind::HELLO, 0];
        wire.extend_from_slice(&((MAX_CONTROL as u32) + 1).to_be_bytes());
        assert!(matches!(Message::decode(&wire), Err(Error::TooLarge(_))));

        let (mut h, b) = blob(b"abc");
        h.hash = hash_hex(b"other");
        assert!(Message::Blob(h, b).encode().is_err());

        // A tampered blob on the wire fails the hash check before it is parsed further.
        let (h, b) = blob(b"abcdef");
        let mut wire = Message::Blob(h, b).encode().unwrap();
        let n = wire.len();
        wire[n - 1] ^= 1;
        assert!(matches!(Message::decode(&wire), Err(Error::Invalid(_))));

        let big = vec![0u8; MAX_BLOB + 1];
        let h = BlobHeader {
            rev: 1,
            hash: hash_hex(&big),
            size: big.len() as u64,
        };
        assert!(matches!(
            Message::Blob(h, big).encode(),
            Err(Error::TooLarge(_))
        ));
    }

    #[test]
    fn truncated_and_malformed_input_is_an_error_not_a_panic() {
        assert!(Message::decode(&[1, 0, 0]).is_err());
        assert!(Message::decode(&[kind::HELLO, 0, 0, 0, 0, 5, b'{']).is_err());
        assert!(Message::decode(&frame(kind::HELLO, b"not json", &[])).is_err());
        assert!(Message::decode(&frame(kind::FETCH, br#"{"have":1,"want":"nope"}"#, &[])).is_err());
    }

    #[tokio::test]
    async fn stream_reader_reads_back_to_back_frames_and_clean_eof() {
        let (h, b) = blob(b"payload");
        let mut wire = Message::Bye.encode().unwrap();
        wire.extend(Message::Blob(h.clone(), b.clone()).encode().unwrap());
        let mut r = &wire[..];
        assert_eq!(read_message(&mut r).await.unwrap(), Some(Message::Bye));
        assert_eq!(
            read_message(&mut r).await.unwrap(),
            Some(Message::Blob(h, b))
        );
        assert_eq!(read_message(&mut r).await.unwrap(), None);
    }
}
