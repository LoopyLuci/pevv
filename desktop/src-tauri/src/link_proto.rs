//! Wire format shared by the PEVV desktop app and `pevv-native-host`: Chrome native-messaging
//! framing, the HMAC that authenticates every message after pairing, and the fingerprint the
//! person compares while pairing. No Tauri, no I/O beyond `Read`/`Write`, so the host binary
//! (which `#[path]`-includes this file) stays small.
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const PROTO_VERSION: u64 = 1;
/// Chrome caps a host's message at 1 MB; we apply the same cap in both directions.
pub const MAX_FRAME: usize = 1024 * 1024;
pub const HOST_NAME: &str = "com.luciverse.pevv";
/// Domain separator mixed into every MAC and the pairing fingerprint.
const MAC_TAG: &str = "pevv-nm1";

/// Read one `4-byte little-endian length + body` frame. `Ok(None)` is a clean end of stream.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < head.len() {
        match r.read(&mut head[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes(head) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame larger than 1 MB"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame larger than 1 MB"));
    }
    // One write, so a frame is never interleaved with another thread's.
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf)?;
    w.flush()
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// Comparison whose time does not depend on where the inputs differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Who signed a message. Part of the MAC input, so a request can never be replayed as a reply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    Ext,
    App,
}

impl Dir {
    fn tag(self) -> &'static str {
        match self {
            Dir::Ext => "ext",
            Dir::App => "app",
        }
    }
}

/// What is signed: tag, direction, counter, message type and the body exactly as sent (a string,
/// so no canonical-JSON question can arise). Replies reuse the request's counter.
fn mac_input(dir: Dir, n: u64, kind: &str, body: &str) -> Vec<u8> {
    format!("{MAC_TAG}|{}|{n}|{}:{kind}|{body}", dir.tag(), kind.len()).into_bytes()
}

pub fn sign(secret: &[u8], dir: Dir, n: u64, kind: &str, body: &str) -> String {
    hex(&hmac_sha256(secret, &mac_input(dir, n, kind, body)))
}

pub fn verify(secret: &[u8], dir: Dir, n: u64, kind: &str, body: &str, mac_hex: &str) -> bool {
    let want = sign(secret, dir, n, kind, body);
    ct_eq(want.as_bytes(), mac_hex.to_ascii_lowercase().as_bytes())
}

/// Ten hex characters of SHA-256(tag | secret), as `XXXXX-XXXXX`. The extension shows the same
/// text, so the person can tell the pairing request they are approving is their own.
pub fn fingerprint(secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(format!("{MAC_TAG}|pair|").as_bytes());
    h.update(secret);
    let d = hex(&h.finalize()[..5]).to_ascii_uppercase();
    format!("{}-{}", &d[..5], &d[5..])
}

/// The id out of the `chrome-extension://<32 letters a-p>/` string Chrome passes as argv[1].
pub fn extension_id_of_origin(origin: &str) -> Option<String> {
    let id = origin.strip_prefix("chrome-extension://")?.strip_suffix('/')?;
    (id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))).then(|| id.to_string())
}

/// Extension ids that may link to the app (and that the host manifest lists in `allowed_origins`).
pub fn allowed_extension_ids() -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct File {
        ids: Vec<String>,
    }
    serde_json::from_str::<File>(include_str!("../extension-ids.json"))
        .map(|f| f.ids)
        .unwrap_or_default()
        .into_iter()
        .filter(|i| extension_id_of_origin(&format!("chrome-extension://{i}/")).is_some())
        .collect()
}

pub fn origin_allowed(origin: &str, ids: &[String]) -> Option<String> {
    let id = extension_id_of_origin(origin)?;
    ids.contains(&id).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_cap() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"a\":1}").unwrap();
        assert_eq!(&buf[..4], &[7, 0, 0, 0]);
        let mut r = io::Cursor::new(buf);
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"{\"a\":1}");
        assert!(read_frame(&mut r).unwrap().is_none());
        assert!(write_frame(&mut Vec::new(), &vec![0u8; MAX_FRAME + 1]).is_err());
        let too_big = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        assert_eq!(read_frame(&mut io::Cursor::new(too_big)).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let exact = [(MAX_FRAME as u32).to_le_bytes().to_vec(), vec![b'x'; MAX_FRAME]].concat();
        assert_eq!(read_frame(&mut io::Cursor::new(exact)).unwrap().unwrap().len(), MAX_FRAME);
    }

    #[test]
    fn truncated_frames_are_errors() {
        assert_eq!(read_frame(&mut io::Cursor::new(vec![1, 0])).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(read_frame(&mut io::Cursor::new(vec![5, 0, 0, 0, b'a'])).is_err());
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        assert_eq!(hex(&hmac_sha256(&[0x0b; 20], b"Hi There")), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        assert_eq!(hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn mac_binds_direction_counter_type_and_body() {
        let s = [7u8; 32];
        let body = "{\"origin\":\"https://a.test\"}";
        let mac = sign(&s, Dir::Ext, 5, "match", body);
        assert!(verify(&s, Dir::Ext, 5, "match", body, &mac));
        assert!(verify(&s, Dir::Ext, 5, "match", body, &mac.to_ascii_uppercase()));
        assert!(!verify(&s, Dir::App, 5, "match", body, &mac), "a request is not a reply");
        assert!(!verify(&s, Dir::Ext, 6, "match", body, &mac));
        assert!(!verify(&s, Dir::Ext, 5, "fill", body, &mac));
        assert!(!verify(&s, Dir::Ext, 5, "match", "{\"origin\":\"https://b.test\"}", &mac));
        assert!(!verify(&[8u8; 32], Dir::Ext, 5, "match", body, &mac));
        assert!(!verify(&s, Dir::Ext, 5, "match", body, ""));
        // Field separators in the body cannot shift into the type.
        assert_ne!(sign(&s, Dir::Ext, 1, "a", "b|c"), sign(&s, Dir::Ext, 1, "a|b", "c"));
    }

    #[test]
    fn fingerprint_is_stable_and_secret_dependent() {
        let f = fingerprint(&[1u8; 32]);
        assert_eq!(f, fingerprint(&[1u8; 32]));
        assert_ne!(f, fingerprint(&[2u8; 32]));
        assert_eq!(f.len(), 11);
        assert_eq!(f.as_bytes()[5], b'-');
        assert!(f.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()));
    }

    /// The same vectors are asserted in tests/unit/pevv.link.test.ts: the two implementations must agree.
    #[test]
    fn matches_the_extension_side_vectors() {
        let body = "{\"origin\":\"https://a.test\"}";
        assert_eq!(sign(&[9u8; 32], Dir::Ext, 5, "match", body), "1bac7ce604724d707159559384566f55f3352faa0cdcc99e344193dab97341b7");
        assert_eq!(sign(&[9u8; 32], Dir::App, 5, "match", body), "305759b490a220bee736ae1cd1337c8465b9835300362f2b6480262a074263cd");
        assert_eq!(fingerprint(&[1u8; 32]), "9D7A8-1A787");
    }

    #[test]
    fn origins() {
        let id = "a".repeat(32);
        assert_eq!(extension_id_of_origin(&format!("chrome-extension://{id}/")), Some(id.clone()));
        assert_eq!(extension_id_of_origin(&format!("chrome-extension://{id}")), None);
        assert_eq!(extension_id_of_origin(&format!("chrome-extension://{}/", "q".repeat(32))), None);
        assert_eq!(extension_id_of_origin("chrome-extension://abc/"), None);
        assert_eq!(extension_id_of_origin(&format!("https://{id}/")), None);
        assert_eq!(origin_allowed(&format!("chrome-extension://{id}/"), std::slice::from_ref(&id)), Some(id.clone()));
        assert_eq!(origin_allowed(&format!("chrome-extension://{id}/"), &["b".repeat(32)]), None);
        assert!(!allowed_extension_ids().is_empty());
    }
}
