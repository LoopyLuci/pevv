//! Windows passkey provider, the platform-neutral half (cargo feature `win-passkey-provider`).
//!
//! Windows hands a plugin authenticator a CTAP2 request as CBOR bytes. This file decodes it with
//! `ciborium`, sends the pieces to the vault window (only it holds the unlocked vault and the keys),
//! checks what comes back, and encodes the CTAP2 response. No Windows type appears here, so all of it
//! is tested on any OS; `provider_win.rs` is the COM and FFI shell around it.
//!
//! What is not confirmed (no Windows 11 machine was available when this was written): whether
//! Windows puts the CTAP command byte in front of the CBOR map (both are accepted), and whether it
//! expects a CTAP status byte in front of a response (none is written). See docs/PEVV_DESKTOP.md.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ciborium::value::Value;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The authenticator's AAGUID: fixed, generated once. `src/pevv/passkeyProvider.ts` has the same value
/// (a unit test compares the two files).
pub const AAGUID: &str = "661cf2bd-74e1-42fd-93d3-7e2ed09cf977";
/// The COM class id of the plugin authenticator. The MSIX manifest declares the same one
/// (a unit test compares them).
pub const CLSID: &str = "56b40049-0a16-42c3-bded-1de50937b256";
/// What Windows shows in its passkey dialog and under Settings > Accounts > Passkeys.
pub const NAME: &str = "PEVV";

/// Requests bigger than this are refused before parsing (a real request is a few hundred bytes).
pub const MAX_REQUEST: usize = 64 * 1024;
/// How long a request may wait for the person to unlock the vault.
pub const UNLOCK_WAIT: Duration = Duration::from_secs(120);

pub fn aaguid_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    let hex: Vec<u8> = AAGUID.bytes().filter(|b| *b != b'-').collect();
    for (i, o) in out.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&hex[i * 2..i * 2 + 2]).unwrap_or("00");
        *o = u8::from_str_radix(pair, 16).unwrap_or(0);
    }
    out
}

/* ───────────── errors ───────────── */

/// Why a request failed, as far as Windows (and so the website) is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    /// The person said no, or the request was cancelled.
    Cancelled,
    /// A passkey for this site and account already exists (the request's excludeList names it).
    Excluded,
    /// None of the requested algorithms is ES256.
    Unsupported,
    /// No matching passkey.
    NotFound,
    /// The request is malformed.
    Invalid,
    /// The vault stayed locked.
    Locked,
    Failed,
}

impl ProviderError {
    /// The HRESULT Windows maps to a W3C error name (see `WebAuthNGetErrorName` in webauthn.h):
    /// NTE_USER_CANCELLED, NTE_EXISTS, NTE_INVALID_PARAMETER, NTE_NOT_FOUND, ERROR_TIMEOUT, E_FAIL.
    pub fn hresult(self) -> i32 {
        (match self {
            ProviderError::Cancelled => 0x8009_0036u32,
            ProviderError::Excluded => 0x8009_000F,
            ProviderError::Unsupported => 0x8009_0027,
            ProviderError::NotFound => 0x8009_0011,
            ProviderError::Invalid => 0x8009_0027,
            ProviderError::Locked => 0x8007_05B4,
            ProviderError::Failed => 0x8000_4005,
        }) as i32
    }

    /// The webview's stable error code (`ProviderError` in passkeyProvider.ts) to this.
    pub fn from_code(code: &str) -> ProviderError {
        match code {
            "locked" => ProviderError::Locked,
            "declined" => ProviderError::Cancelled,
            "excluded" => ProviderError::Excluded,
            "no-credential" => ProviderError::NotFound,
            "bad-request" => ProviderError::Invalid,
            "cancelled" => ProviderError::Cancelled,
            _ => ProviderError::Failed,
        }
    }
}

/* ───────────── CBOR in ───────────── */

fn parse(bytes: &[u8]) -> Result<Value, ProviderError> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err(ProviderError::Invalid);
    }
    let mut rest = bytes;
    let v: Value = ciborium::de::from_reader(&mut rest).map_err(|_| ProviderError::Invalid)?;
    if !rest.is_empty() {
        return Err(ProviderError::Invalid);
    }
    Ok(v)
}

/// Windows may or may not prefix the CBOR map with the CTAP command byte. A CBOR map starts
/// 0xa0..=0xbf, which no command byte (0x01, 0x02) is, so both forms are told apart safely.
fn body(bytes: &[u8], command: u8) -> &[u8] {
    match bytes.first() {
        Some(b) if *b == command && !(0xa0..=0xbf).contains(b) => &bytes[1..],
        _ => bytes,
    }
}

fn int_key(v: &Value) -> Option<i128> {
    v.as_integer().map(i128::from)
}

fn field(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter().find(|(k, _)| int_key(k) == Some(key)).map(|(_, v)| v)
}

fn text_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v)
}

fn bytes_of(v: Option<&Value>) -> Option<Vec<u8>> {
    v.and_then(|v| v.as_bytes()).cloned()
}

fn text_of(v: Option<&Value>) -> Option<String> {
    v.and_then(|v| v.as_text()).map(str::to_string)
}

fn credential_ids(v: Option<&Value>) -> Result<Vec<Vec<u8>>, ProviderError> {
    let mut out = Vec::new();
    if let Some(list) = v {
        for d in list.as_array().ok_or(ProviderError::Invalid)? {
            let m = d.as_map().ok_or(ProviderError::Invalid)?;
            // Only public-key credentials; anything else cannot be ours and is skipped.
            if text_field(m, "type").and_then(|t| t.as_text()).is_some_and(|t| t != "public-key") {
                continue;
            }
            out.push(bytes_of(text_field(m, "id")).ok_or(ProviderError::Invalid)?);
        }
    }
    Ok(out)
}

fn uv_option(options: Option<&Value>) -> bool {
    options.and_then(|o| o.as_map()).and_then(|m| text_field(m, "uv")).and_then(|v| v.as_bool()).unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeRequest {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub client_data_hash: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: Option<String>,
    pub exclude: Vec<Vec<u8>>,
    pub require_uv: bool,
}

/// CTAP2 authenticatorMakeCredential: `{1: clientDataHash, 2: rp{id,name}, 3: user{id,name,displayName},
/// 4: pubKeyCredParams, 5: excludeList, 7: options}`.
pub fn decode_make(bytes: &[u8]) -> Result<MakeRequest, ProviderError> {
    let v = parse(body(bytes, 0x01))?;
    let m = v.as_map().ok_or(ProviderError::Invalid)?;
    let client_data_hash = bytes_of(field(m, 1)).ok_or(ProviderError::Invalid)?;
    if client_data_hash.len() != 32 {
        return Err(ProviderError::Invalid);
    }
    let rp = field(m, 2).and_then(|v| v.as_map()).ok_or(ProviderError::Invalid)?;
    let rp_id = text_of(text_field(rp, "id")).filter(|s| !s.is_empty()).ok_or(ProviderError::Invalid)?;
    let user = field(m, 3).and_then(|v| v.as_map()).ok_or(ProviderError::Invalid)?;
    let user_id = bytes_of(text_field(user, "id")).filter(|b| (1..=64).contains(&b.len())).ok_or(ProviderError::Invalid)?;
    let params = field(m, 4).and_then(|v| v.as_array()).ok_or(ProviderError::Invalid)?;
    let es256 = params.iter().any(|p| {
        p.as_map().is_some_and(|pm| {
            text_field(pm, "alg").and_then(int_key) == Some(-7) && !matches!(text_field(pm, "type").and_then(|t| t.as_text()), Some(t) if t != "public-key")
        })
    });
    if !es256 {
        return Err(ProviderError::Unsupported);
    }
    Ok(MakeRequest {
        rp_id,
        rp_name: text_of(text_field(rp, "name")),
        client_data_hash,
        user_id,
        user_name: text_of(text_field(user, "name")).unwrap_or_default(),
        user_display_name: text_of(text_field(user, "displayName")),
        exclude: credential_ids(field(m, 5))?,
        require_uv: uv_option(field(m, 7)),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow: Vec<Vec<u8>>,
    pub require_uv: bool,
}

/// CTAP2 authenticatorGetAssertion: `{1: rpId, 2: clientDataHash, 3: allowList, 5: options}`.
pub fn decode_get(bytes: &[u8]) -> Result<GetRequest, ProviderError> {
    let v = parse(body(bytes, 0x02))?;
    let m = v.as_map().ok_or(ProviderError::Invalid)?;
    let rp_id = text_of(field(m, 1)).filter(|s| !s.is_empty()).ok_or(ProviderError::Invalid)?;
    let client_data_hash = bytes_of(field(m, 2)).ok_or(ProviderError::Invalid)?;
    if client_data_hash.len() != 32 {
        return Err(ProviderError::Invalid);
    }
    Ok(GetRequest { rp_id, client_data_hash, allow: credential_ids(field(m, 3))?, require_uv: uv_option(field(m, 5)) })
}

/* ───────────── CBOR out ───────────── */

fn write(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // Writing into a Vec cannot fail.
    let _ = ciborium::ser::into_writer(v, &mut out);
    out
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn int(i: i64) -> Value {
    Value::Integer(i.into())
}

/// authenticatorMakeCredential response, attestation `none`: `{1: "none", 2: authData, 3: {}}`.
pub fn encode_make_response(auth_data: &[u8]) -> Vec<u8> {
    write(&Value::Map(vec![(int(1), text("none")), (int(2), Value::Bytes(auth_data.to_vec())), (int(3), Value::Map(vec![]))]))
}

/// authenticatorGetAssertion response: `{1: credential, 2: authData, 3: signature, 4: user}`.
pub fn encode_get_response(credential_id: &[u8], auth_data: &[u8], signature: &[u8], user_handle: &[u8], user_name: &str) -> Vec<u8> {
    let mut m = vec![
        (int(1), Value::Map(vec![(text("id"), Value::Bytes(credential_id.to_vec())), (text("type"), text("public-key"))])),
        (int(2), Value::Bytes(auth_data.to_vec())),
        (int(3), Value::Bytes(signature.to_vec())),
    ];
    if !user_handle.is_empty() {
        let mut u = vec![(text("id"), Value::Bytes(user_handle.to_vec()))];
        if !user_name.is_empty() {
            u.push((text("name"), text(user_name)));
        }
        m.push((int(4), Value::Map(u)));
    }
    write(&Value::Map(m))
}

/// The CTAP2 authenticatorGetInfo Windows keeps for this authenticator at registration:
/// versions, the AAGUID, `rk`/`up`/`uv` options, the internal transport and ES256.
pub fn authenticator_info() -> Vec<u8> {
    write(&Value::Map(vec![
        (int(1), Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")])),
        (int(3), Value::Bytes(aaguid_bytes().to_vec())),
        (int(4), Value::Map(vec![(text("rk"), Value::Bool(true)), (text("up"), Value::Bool(true)), (text("uv"), Value::Bool(true))])),
        (int(9), Value::Array(vec![text("internal")])),
        (int(10), Value::Array(vec![Value::Map(vec![(text("alg"), int(-7)), (text("type"), text("public-key"))])])),
    ]))
}

/* ───────────── the host (vault window) ───────────── */

/// What the broker needs from the app. The Tauri implementation is in `provider.rs`.
pub trait Host: Send + Sync {
    fn unlocked(&self) -> bool;
    /// Bring the PEVV window forward so the person can unlock.
    fn show_window(&self);
    /// Send one request to the vault window and wait for its answer. `Err` is the webview's error code,
    /// or `"cancelled"` once `cancel` is set.
    fn ask(&self, body: &Json, cancel: &AtomicBool) -> Result<Json, String>;
}

fn wait_unlocked(host: &dyn Host, cancel: &AtomicBool, wait: Duration, poll: Duration) -> Result<(), ProviderError> {
    if host.unlocked() {
        return Ok(());
    }
    host.show_window();
    let end = Instant::now() + wait;
    while Instant::now() < end {
        if cancel.load(Ordering::SeqCst) {
            return Err(ProviderError::Cancelled);
        }
        if host.unlocked() {
            return Ok(());
        }
        std::thread::sleep(poll);
    }
    Err(ProviderError::Locked)
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn unb64(v: &Json, key: &str) -> Result<Vec<u8>, ProviderError> {
    URL_SAFE_NO_PAD.decode(v.get(key).and_then(Json::as_str).ok_or(ProviderError::Failed)?).map_err(|_| ProviderError::Failed)
}

fn rp_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_AT: u8 = 0x40;

/// The shape of `make_credential` and `get_assertion`, so the COM layer can run either one.
pub type Handler = fn(&dyn Host, u64, &[u8], &AtomicBool, Duration, Duration) -> Result<Vec<u8>, ProviderError>;

/// MakeCredential, end to end: bytes in, CTAP2 response bytes out. `id` ties the question to the answer.
pub fn make_credential(host: &dyn Host, id: u64, encoded: &[u8], cancel: &AtomicBool, wait: Duration, poll: Duration) -> Result<Vec<u8>, ProviderError> {
    let req = decode_make(encoded)?;
    wait_unlocked(host, cancel, wait, poll)?;
    let reply = host
        .ask(
            &json!({
                "id": id, "op": "make", "rpId": req.rp_id, "rpName": req.rp_name, "clientDataHash": b64(&req.client_data_hash),
                "user": { "id": b64(&req.user_id), "name": req.user_name, "displayName": req.user_display_name },
                "excludeCredentialIds": req.exclude.iter().map(|c| b64(c)).collect::<Vec<_>>(),
                "requireUv": req.require_uv,
            }),
            cancel,
        )
        .map_err(|c| ProviderError::from_code(&c))?;
    let credential_id = unb64(&reply, "credentialId")?;
    let auth_data = unb64(&reply, "authData")?;
    // Trust nothing the page sends back: the data must be for this site, carry a new credential (flags AT)
    // and name exactly the credential id it claims. 37 = rpIdHash + flags + counter; then aaguid(16) + len(2).
    if auth_data.len() < 37 + 18 || auth_data[..32] != rp_hash(&req.rp_id) || auth_data[32] & (FLAG_UP | FLAG_AT) != (FLAG_UP | FLAG_AT) {
        return Err(ProviderError::Failed);
    }
    if auth_data[37..53] != aaguid_bytes() {
        return Err(ProviderError::Failed);
    }
    let id_len = ((auth_data[53] as usize) << 8) | auth_data[54] as usize;
    if id_len == 0 || auth_data.len() < 55 + id_len || auth_data[55..55 + id_len] != credential_id[..] {
        return Err(ProviderError::Failed);
    }
    Ok(encode_make_response(&auth_data))
}

/// GetAssertion, end to end.
pub fn get_assertion(host: &dyn Host, id: u64, encoded: &[u8], cancel: &AtomicBool, wait: Duration, poll: Duration) -> Result<Vec<u8>, ProviderError> {
    let req = decode_get(encoded)?;
    wait_unlocked(host, cancel, wait, poll)?;
    let reply = host
        .ask(
            &json!({
                "id": id, "op": "get", "rpId": req.rp_id, "clientDataHash": b64(&req.client_data_hash),
                "allowCredentialIds": req.allow.iter().map(|c| b64(c)).collect::<Vec<_>>(), "requireUv": req.require_uv,
            }),
            cancel,
        )
        .map_err(|c| ProviderError::from_code(&c))?;
    let credential_id = unb64(&reply, "credentialId")?;
    let auth_data = unb64(&reply, "authData")?;
    let signature = unb64(&reply, "signature")?;
    let user_handle = unb64(&reply, "userHandle").unwrap_or_default();
    // An assertion's authenticatorData is exactly 37 bytes (no attested data) and names this site.
    if auth_data.len() != 37 || auth_data[..32] != rp_hash(&req.rp_id) || auth_data[32] & FLAG_UP == 0 || auth_data[32] & FLAG_AT != 0 {
        return Err(ProviderError::Failed);
    }
    if signature.is_empty() || signature.len() > 72 || credential_id.is_empty() || credential_id.len() > 1023 {
        return Err(ProviderError::Failed);
    }
    if !req.allow.is_empty() && !req.allow.contains(&credential_id) {
        return Err(ProviderError::Failed);
    }
    let user_name = reply.get("userName").and_then(Json::as_str).unwrap_or("");
    Ok(encode_get_response(&credential_id, &auth_data, &signature, &user_handle, user_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn map(entries: Vec<(Value, Value)>) -> Value {
        Value::Map(entries)
    }

    fn make_body() -> Vec<u8> {
        write(&map(vec![
            (int(1), Value::Bytes(vec![7; 32])),
            (int(2), map(vec![(text("id"), text("example.com")), (text("name"), text("Example"))])),
            (int(3), map(vec![(text("id"), Value::Bytes(b"u1".to_vec())), (text("name"), text("ada")), (text("displayName"), text("Ada L."))])),
            (
                int(4),
                Value::Array(vec![
                    map(vec![(text("alg"), int(-257)), (text("type"), text("public-key"))]),
                    map(vec![(text("alg"), int(-7)), (text("type"), text("public-key"))]),
                ]),
            ),
            (int(5), Value::Array(vec![map(vec![(text("type"), text("public-key")), (text("id"), Value::Bytes(vec![1, 2, 3]))])])),
            (int(7), map(vec![(text("rk"), Value::Bool(true)), (text("uv"), Value::Bool(true))])),
        ]))
    }

    fn get_body() -> Vec<u8> {
        write(&map(vec![
            (int(1), text("example.com")),
            (int(2), Value::Bytes(vec![9; 32])),
            (int(3), Value::Array(vec![map(vec![(text("type"), text("public-key")), (text("id"), Value::Bytes(vec![4, 5]))])])),
            (int(5), map(vec![(text("up"), Value::Bool(true))])),
        ]))
    }

    #[test]
    fn the_aaguid_is_the_fixed_uuid() {
        assert_eq!(AAGUID, "661cf2bd-74e1-42fd-93d3-7e2ed09cf977");
        assert_eq!(aaguid_bytes(), [0x66, 0x1c, 0xf2, 0xbd, 0x74, 0xe1, 0x42, 0xfd, 0x93, 0xd3, 0x7e, 0x2e, 0xd0, 0x9c, 0xf9, 0x77]);
        // Version 4, variant 1 (RFC 4122).
        assert_eq!(aaguid_bytes()[6] >> 4, 4);
        assert_eq!(aaguid_bytes()[8] >> 6, 0b10);
    }

    #[test]
    fn the_msix_manifest_declares_this_class_and_nothing_stray() {
        let m = include_str!("../windows/msix/AppxManifest.xml");
        assert!(m.contains(&format!("Id=\"{CLSID}\"")), "the COM class id in the manifest must be CLSID");
        assert!(m.contains("windows.comServer"));
        assert!(m.contains("Executable=\"pevv-desktop.exe\""));
        assert!(m.contains("runFullTrust"));
        // Placeholders the build script fills.
        for p in ["@IDENTITY_NAME@", "@PUBLISHER@", "@VERSION@", "@PUBLISHER_DISPLAY_NAME@"] {
            assert!(m.contains(p), "{p}");
        }
        // No certificate material in a file that ships in a public repo.
        assert!(!m.to_lowercase().contains("thumbprint"));
    }

    #[test]
    fn decodes_make_credential() {
        let r = decode_make(&make_body()).unwrap();
        assert_eq!(r.rp_id, "example.com");
        assert_eq!(r.rp_name.as_deref(), Some("Example"));
        assert_eq!(r.client_data_hash, vec![7; 32]);
        assert_eq!(r.user_id, b"u1");
        assert_eq!(r.user_name, "ada");
        assert_eq!(r.user_display_name.as_deref(), Some("Ada L."));
        assert_eq!(r.exclude, vec![vec![1, 2, 3]]);
        assert!(r.require_uv);
    }

    #[test]
    fn a_leading_command_byte_is_accepted_but_not_required() {
        let mut with = vec![0x01];
        with.extend(make_body());
        assert_eq!(decode_make(&with).unwrap(), decode_make(&make_body()).unwrap());
        let mut with = vec![0x02];
        with.extend(get_body());
        assert_eq!(decode_get(&with).unwrap(), decode_get(&get_body()).unwrap());
    }

    #[test]
    fn make_credential_needs_es256_and_sane_fields() {
        let mut v: Value = ciborium::de::from_reader(&make_body()[..]).unwrap();
        // Only RS256 offered.
        if let Value::Map(m) = &mut v {
            m[3].1 = Value::Array(vec![map(vec![(text("alg"), int(-257)), (text("type"), text("public-key"))])]);
        }
        assert_eq!(decode_make(&write(&v)), Err(ProviderError::Unsupported));
        // Short client data hash.
        if let Value::Map(m) = &mut v {
            m[0].1 = Value::Bytes(vec![1; 31]);
        }
        assert_eq!(decode_make(&write(&v)), Err(ProviderError::Invalid));
        // Not a map, empty, truncated, trailing bytes, oversized.
        assert_eq!(decode_make(&write(&int(1))), Err(ProviderError::Invalid));
        assert_eq!(decode_make(&[]), Err(ProviderError::Invalid));
        assert_eq!(decode_make(&make_body()[..10]), Err(ProviderError::Invalid));
        let mut trailing = make_body();
        trailing.push(0);
        assert_eq!(decode_make(&trailing), Err(ProviderError::Invalid));
        assert_eq!(decode_make(&vec![0xa0; MAX_REQUEST + 1]), Err(ProviderError::Invalid));
    }

    #[test]
    fn decodes_get_assertion() {
        let r = decode_get(&get_body()).unwrap();
        assert_eq!(r, GetRequest { rp_id: "example.com".into(), client_data_hash: vec![9; 32], allow: vec![vec![4, 5]], require_uv: false });
        assert_eq!(decode_get(&write(&map(vec![(int(1), text("")), (int(2), Value::Bytes(vec![9; 32]))]))), Err(ProviderError::Invalid));
        // No allowList is a discoverable-credential request: fine.
        let r = decode_get(&write(&map(vec![(int(1), text("a.com")), (int(2), Value::Bytes(vec![9; 32]))]))).unwrap();
        assert!(r.allow.is_empty());
    }

    #[test]
    fn make_response_is_the_none_attestation_object() {
        let out = encode_make_response(&[1, 2, 3]);
        // a3 01 64 "none" 02 43 010203 03 a0
        assert_eq!(out, [0xa3, 0x01, 0x64, b'n', b'o', b'n', b'e', 0x02, 0x43, 1, 2, 3, 0x03, 0xa0]);
    }

    #[test]
    fn get_response_has_credential_authdata_signature_and_user() {
        let out = encode_get_response(&[0xaa], &[1, 2], &[3], &[0xbb], "ada");
        let v: Value = ciborium::de::from_reader(&out[..]).unwrap();
        let m = v.as_map().unwrap();
        let cred = field(m, 1).unwrap().as_map().unwrap();
        assert_eq!(text_field(cred, "id").unwrap().as_bytes().unwrap(), &vec![0xaa]);
        assert_eq!(text_field(cred, "type").unwrap().as_text(), Some("public-key"));
        assert_eq!(field(m, 2).unwrap().as_bytes().unwrap(), &vec![1, 2]);
        assert_eq!(field(m, 3).unwrap().as_bytes().unwrap(), &vec![3]);
        let user = field(m, 4).unwrap().as_map().unwrap();
        assert_eq!(text_field(user, "id").unwrap().as_bytes().unwrap(), &vec![0xbb]);
        assert_eq!(text_field(user, "name").unwrap().as_text(), Some("ada"));
        // Keys are ascending integers (CTAP2 canonical order).
        let keys: Vec<i128> = m.iter().filter_map(|(k, _)| int_key(k)).collect();
        assert_eq!(keys, vec![1, 2, 3, 4]);
        // No user handle, no user entity.
        let v: Value = ciborium::de::from_reader(&encode_get_response(&[1], &[1], &[1], &[], "")[..]).unwrap();
        assert!(field(v.as_map().unwrap(), 4).is_none());
    }

    #[test]
    fn authenticator_info_names_the_aaguid_and_es256() {
        let v: Value = ciborium::de::from_reader(&authenticator_info()[..]).unwrap();
        let m = v.as_map().unwrap();
        assert_eq!(field(m, 3).unwrap().as_bytes().unwrap(), &aaguid_bytes().to_vec());
        assert!(field(m, 1).unwrap().as_array().unwrap().iter().any(|s| s.as_text() == Some("FIDO_2_1")));
        let alg = field(m, 10).unwrap().as_array().unwrap()[0].as_map().unwrap();
        assert_eq!(text_field(alg, "alg").and_then(int_key), Some(-7));
        let opts = field(m, 4).unwrap().as_map().unwrap();
        assert_eq!(text_field(opts, "rk").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn errors_map_to_the_hresults_windows_turns_into_dom_errors() {
        assert_eq!(ProviderError::Cancelled.hresult() as u32, 0x8009_0036);
        assert_eq!(ProviderError::Excluded.hresult() as u32, 0x8009_000F);
        assert_eq!(ProviderError::NotFound.hresult() as u32, 0x8009_0011);
        assert_eq!(ProviderError::Invalid.hresult() as u32, 0x8009_0027);
        assert_eq!(ProviderError::Locked.hresult() as u32, 0x8007_05B4);
        assert_eq!(ProviderError::from_code("declined"), ProviderError::Cancelled);
        assert_eq!(ProviderError::from_code("excluded"), ProviderError::Excluded);
        assert_eq!(ProviderError::from_code("no-credential"), ProviderError::NotFound);
        assert_eq!(ProviderError::from_code("whatever"), ProviderError::Failed);
    }

    /// A fake vault window.
    struct Fake {
        unlocked: AtomicBool,
        shown: AtomicBool,
        unlock_after_polls: Mutex<Option<u32>>,
        seen: Mutex<Vec<Json>>,
        reply: Mutex<Result<Json, String>>,
    }

    impl Fake {
        fn new(unlocked: bool, reply: Result<Json, String>) -> Fake {
            Fake {
                unlocked: AtomicBool::new(unlocked),
                shown: AtomicBool::new(false),
                unlock_after_polls: Mutex::new(None),
                seen: Mutex::new(vec![]),
                reply: Mutex::new(reply),
            }
        }
    }

    impl Host for Fake {
        fn unlocked(&self) -> bool {
            let mut n = self.unlock_after_polls.lock().unwrap();
            if let Some(left) = n.as_mut() {
                if *left == 0 {
                    self.unlocked.store(true, Ordering::SeqCst);
                } else {
                    *left -= 1;
                }
            }
            self.unlocked.load(Ordering::SeqCst)
        }
        fn show_window(&self) {
            self.shown.store(true, Ordering::SeqCst);
        }
        fn ask(&self, body: &Json, _cancel: &AtomicBool) -> Result<Json, String> {
            self.seen.lock().unwrap().push(body.clone());
            self.reply.lock().unwrap().clone()
        }
    }

    const FAST: Duration = Duration::from_millis(1);

    fn good_make_auth(rp: &str, cred: &[u8]) -> Vec<u8> {
        let mut ad = rp_hash(rp).to_vec();
        ad.extend([FLAG_UP | FLAG_AT, 0, 0, 0, 0]);
        ad.extend(aaguid_bytes());
        ad.extend([(cred.len() >> 8) as u8, cred.len() as u8]);
        ad.extend(cred);
        ad.extend([0xa5, 1, 2]);
        ad
    }

    #[test]
    fn make_credential_round_trips_through_the_host_and_checks_the_answer() {
        let cred = vec![0x42; 32];
        let host = Fake::new(true, Ok(json!({ "credentialId": b64(&cred), "authData": b64(&good_make_auth("example.com", &cred)) })));
        let out = make_credential(&host, 5, &make_body(), &AtomicBool::new(false), FAST, FAST).unwrap();
        let sent = host.seen.lock().unwrap()[0].clone();
        assert_eq!(sent["op"], "make");
        assert_eq!(sent["id"], 5);
        assert_eq!(sent["rpId"], "example.com");
        assert_eq!(sent["user"]["name"], "ada");
        assert_eq!(sent["excludeCredentialIds"], json!([b64(&[1, 2, 3])]));
        assert_eq!(sent["clientDataHash"], b64(&[7; 32]));
        assert_eq!(out[..3], [0xa3, 0x01, 0x64]);
        // The vault never held it: no key travels in the request.
        assert!(!sent.to_string().contains("rivate"));
    }

    #[test]
    fn a_wrong_answer_from_the_page_is_refused() {
        let cred = vec![0x42; 32];
        let bad = |ad: Vec<u8>, id: &[u8]| Fake::new(true, Ok(json!({ "credentialId": b64(id), "authData": b64(&ad) })));
        let run = |h: &Fake| make_credential(h, 1, &make_body(), &AtomicBool::new(false), FAST, FAST);
        // Right data, wrong credential id.
        assert_eq!(run(&bad(good_make_auth("example.com", &cred), &[9; 32])), Err(ProviderError::Failed));
        // Data for another site.
        assert_eq!(run(&bad(good_make_auth("evil.test", &cred), &cred)), Err(ProviderError::Failed));
        // Not a registration (no AT flag) and truncated.
        let mut no_at = good_make_auth("example.com", &cred);
        no_at[32] = FLAG_UP;
        assert_eq!(run(&bad(no_at, &cred)), Err(ProviderError::Failed));
        assert_eq!(run(&bad(vec![0; 40], &cred)), Err(ProviderError::Failed));
        // Someone else's AAGUID.
        let mut other = good_make_auth("example.com", &cred);
        other[37] ^= 1;
        assert_eq!(run(&bad(other, &cred)), Err(ProviderError::Failed));
        // The webview's refusal comes through as the matching error.
        assert_eq!(run(&Fake::new(true, Err("declined".into()))), Err(ProviderError::Cancelled));
        assert_eq!(run(&Fake::new(true, Err("excluded".into()))), Err(ProviderError::Excluded));
    }

    #[test]
    fn a_locked_vault_brings_the_window_forward_and_waits() {
        let cred = vec![0x42; 32];
        let host = Fake::new(false, Ok(json!({ "credentialId": b64(&cred), "authData": b64(&good_make_auth("example.com", &cred)) })));
        *host.unlock_after_polls.lock().unwrap() = Some(3);
        assert!(make_credential(&host, 1, &make_body(), &AtomicBool::new(false), Duration::from_secs(5), FAST).is_ok());
        assert!(host.shown.load(Ordering::SeqCst));
        // Never unlocked: Locked, and nothing was asked of the webview.
        let host = Fake::new(false, Err("x".into()));
        assert_eq!(make_credential(&host, 1, &make_body(), &AtomicBool::new(false), Duration::from_millis(20), FAST), Err(ProviderError::Locked));
        assert!(host.seen.lock().unwrap().is_empty());
        // Cancelled while waiting.
        let host = Fake::new(false, Err("x".into()));
        assert_eq!(make_credential(&host, 1, &make_body(), &AtomicBool::new(true), Duration::from_secs(5), FAST), Err(ProviderError::Cancelled));
    }

    #[test]
    fn a_bad_request_never_wakes_the_window() {
        let host = Fake::new(false, Err("x".into()));
        assert_eq!(make_credential(&host, 1, &[0xff], &AtomicBool::new(false), FAST, FAST), Err(ProviderError::Invalid));
        assert!(!host.shown.load(Ordering::SeqCst));
    }

    fn good_get_auth(rp: &str, flags: u8) -> Vec<u8> {
        let mut ad = rp_hash(rp).to_vec();
        ad.extend([flags, 0, 0, 0, 3]);
        ad
    }

    #[test]
    fn get_assertion_round_trip_and_checks() {
        let reply = |ad: Vec<u8>, sig: &[u8], id: &[u8]| {
            Fake::new(true, Ok(json!({ "credentialId": b64(id), "authData": b64(&ad), "signature": b64(sig), "userHandle": b64(b"u1"), "userName": "ada" })))
        };
        let run = |h: &Fake| get_assertion(h, 8, &get_body(), &AtomicBool::new(false), FAST, FAST);
        let h = reply(good_get_auth("example.com", FLAG_UP | 0x04), &[0x30, 1, 2], &[4, 5]);
        let out = run(&h).unwrap();
        let sent = h.seen.lock().unwrap()[0].clone();
        assert_eq!(sent["op"], "get");
        assert_eq!(sent["allowCredentialIds"], json!([b64(&[4, 5])]));
        let v: Value = ciborium::de::from_reader(&out[..]).unwrap();
        assert_eq!(field(v.as_map().unwrap(), 3).unwrap().as_bytes().unwrap(), &vec![0x30, 1, 2]);
        // A credential outside the allow list, another site, registration data, no signature: all refused.
        assert_eq!(run(&reply(good_get_auth("example.com", FLAG_UP), &[1], &[9, 9])), Err(ProviderError::Failed));
        assert_eq!(run(&reply(good_get_auth("evil.test", FLAG_UP), &[1], &[4, 5])), Err(ProviderError::Failed));
        assert_eq!(run(&reply(good_get_auth("example.com", FLAG_UP | FLAG_AT), &[1], &[4, 5])), Err(ProviderError::Failed));
        assert_eq!(run(&reply(good_get_auth("example.com", 0), &[1], &[4, 5])), Err(ProviderError::Failed));
        assert_eq!(run(&reply(good_get_auth("example.com", FLAG_UP), &[], &[4, 5])), Err(ProviderError::Failed));
        assert_eq!(run(&reply(vec![0; 38], &[1], &[4, 5])), Err(ProviderError::Failed));
        assert_eq!(run(&Fake::new(true, Err("no-credential".into()))), Err(ProviderError::NotFound));
    }
}
