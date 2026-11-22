//! Native passkey / security-key unlock.
//!
//! The vault's PRF slots were enrolled in the PEVV web app, so the secret each
//! authenticator returns is bound to that site's rpId (the host name it is served from). This module asks the OS
//! (Windows `webauthn.dll`) or the key itself over USB HID (Linux CTAP2
//! `hmac-secret`) for the same secret, with the same rpId and the same PRF
//! salts, and hands it to the page. The page feeds it to the existing
//! `unlockWithPrf`; nothing about the vault format changes.
//!
//! The rpId is a constant compiled into the app and never read from the page, so
//! the command cannot be used to ask a key for an assertion for any other site.
//! The hardware paths (`passkey_win`, `passkey_linux`) have not been run against a
//! real authenticator; everything in this file is unit tested.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The web app's WebAuthn rpId (`location.hostname` where the passkeys were enrolled).
/// Set at build time with `PEVV_RP_ID=pevv.example.com` (docs/CLIENT_DESKTOP.md). When it is not set
/// there is no site to borrow passkeys from, so native passkey unlock reports itself unavailable.
pub const RP_ID: &str = match option_env!("PEVV_RP_ID") {
    Some(v) => v,
    None => "",
};

const NOT_CONFIGURED: &str = "Native passkeys need PEVV_RP_ID set when the app is built (the host name of your PEVV web app). Use your master password.";

const MAX_CREDENTIALS: usize = 16;
const MAX_INPUT: usize = 1024;

/// Page-facing error: a stable `code` for the UI and a message for people.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PasskeyError {
    pub code: &'static str,
    pub message: String,
}

impl PasskeyError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    /// Credential id, base64url.
    pub id: String,
    /// PRF `first` input for this credential, base64url (the vault slot's salt).
    pub salt1: Option<String>,
    pub salt2: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrfRequest {
    pub credentials: Vec<CredentialRequest>,
    /// WebAuthn challenge, base64url (the page checks it comes back in clientDataJSON).
    pub challenge: String,
    #[serde(default)]
    pub require_uv: bool,
    /// Linux only: the key's PIN, after a `pin-required` answer.
    #[serde(default)]
    pub pin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrfResponse {
    pub credential_id: String,
    pub prf1: Option<String>,
    pub prf2: Option<String>,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Support {
    pub available: bool,
    pub rp_id: &'static str,
    pub platform: &'static str,
    /// Why it is unavailable, when it is.
    pub reason: Option<String>,
    /// The key asks for a PIN through the app (Linux) rather than through the OS dialog.
    pub app_pin: bool,
}

/// One credential, decoded and with its PRF inputs already turned into hmac-secret salts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: Vec<u8>,
    pub salt1: Option<[u8; 32]>,
    pub salt2: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct Prepared {
    pub candidates: Vec<Candidate>,
    /// The exact bytes whose SHA-256 is the clientDataHash the authenticator signs.
    pub client_data: Vec<u8>,
    pub client_data_json: String,
    pub require_uv: bool,
}

/// How browsers map a WebAuthn PRF input to the CTAP `hmac-secret` salt:
/// `SHA-256("WebAuthn PRF" || 0x00 || input)`.
pub fn prf_salt(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0u8]);
    h.update(input);
    h.finalize().into()
}

/// The clientDataJSON a browser would build for `navigator.credentials.get`.
/// The origin is the site's, so the page's local assertion check passes unchanged.
pub fn client_data_json(challenge_b64url: &str) -> String {
    format!(r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://{RP_ID}","crossOrigin":false}}"#)
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(field: &str, s: &str) -> Result<Vec<u8>, PasskeyError> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|_| PasskeyError::new("bad-request", format!("{field} is not base64url")))
}

/// Validate the page's request and derive the salts. Pure, so it is tested without hardware.
pub fn prepare(req: &PrfRequest) -> Result<Prepared, PasskeyError> {
    if req.credentials.is_empty() {
        return Err(PasskeyError::new("bad-request", "no credentials to ask for"));
    }
    if req.credentials.len() > MAX_CREDENTIALS {
        return Err(PasskeyError::new("bad-request", "too many credentials"));
    }
    let challenge = unb64("challenge", &req.challenge)?;
    if !(16..=128).contains(&challenge.len()) {
        return Err(PasskeyError::new("bad-request", "challenge must be 16 to 128 bytes"));
    }
    let mut candidates = Vec::with_capacity(req.credentials.len());
    for c in &req.credentials {
        let id = unb64("credential id", &c.id)?;
        if id.is_empty() || id.len() > 1023 {
            return Err(PasskeyError::new("bad-request", "credential id has a bad length"));
        }
        let salt = |field: &str, v: &Option<String>| -> Result<Option<[u8; 32]>, PasskeyError> {
            match v {
                None => Ok(None),
                Some(s) => {
                    let raw = unb64(field, s)?;
                    if raw.is_empty() || raw.len() > MAX_INPUT {
                        return Err(PasskeyError::new("bad-request", format!("{field} has a bad length")));
                    }
                    Ok(Some(prf_salt(&raw)))
                }
            }
        };
        let salt1 = salt("salt1", &c.salt1)?;
        let salt2 = salt("salt2", &c.salt2)?;
        if salt2.is_some() && salt1.is_none() {
            return Err(PasskeyError::new("bad-request", "salt2 needs salt1"));
        }
        candidates.push(Candidate { id, salt1, salt2 });
    }
    let json = client_data_json(&req.challenge);
    Ok(Prepared { candidates, client_data: json.clone().into_bytes(), client_data_json: json, require_uv: req.require_uv })
}

/// What a CTAP error string from the library means for us.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum CtapKind {
    /// This key does not hold that credential: try the next one.
    NoCredentials,
    PinInvalid,
    PinBlocked,
    Cancelled,
    Other,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn classify(err: &str) -> CtapKind {
    let e = err.to_ascii_uppercase();
    if e.contains("NO_CREDENTIALS") || e.contains("0X2E") {
        CtapKind::NoCredentials
    } else if e.contains("PIN_INVALID") || e.contains("0X31") || e.contains("PIN_AUTH_INVALID") || e.contains("0X33") {
        CtapKind::PinInvalid
    } else if e.contains("PIN_BLOCKED") || e.contains("0X32") || e.contains("PIN_AUTH_BLOCKED") || e.contains("0X34") {
        CtapKind::PinBlocked
    } else if e.contains("KEEPALIVE_CANCEL")
        || e.contains("0X2D")
        || e.contains("OPERATION_DENIED")
        || e.contains("0X27")
        || e.contains("ACTION_TIMEOUT")
        || e.contains("0X3A")
        || e.contains("USER_ACTION_TIMEOUT")
    {
        CtapKind::Cancelled
    } else {
        CtapKind::Other
    }
}

#[cfg(windows)]
pub fn support() -> Support {
    let v = crate::passkey_win::api_version();
    let ok = v >= crate::passkey_win::MIN_API_VERSION && !RP_ID.is_empty();
    Support {
        available: ok,
        rp_id: RP_ID,
        platform: "windows",
        reason: (!ok).then(|| {
            if RP_ID.is_empty() {
                NOT_CONFIGURED.to_string()
            } else {
                format!(
                    "This Windows has WebAuthn API version {v}; passkey unlock needs version {} (Windows 11 22H2 or newer). Use your master password.",
                    crate::passkey_win::MIN_API_VERSION
                )
            }
        }),
        app_pin: false,
    }
}

#[cfg(target_os = "linux")]
pub fn support() -> Support {
    let ok = !RP_ID.is_empty();
    Support { available: ok, rp_id: RP_ID, platform: "linux", reason: (!ok).then(|| NOT_CONFIGURED.to_string()), app_pin: true }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn support() -> Support {
    Support { available: false, rp_id: RP_ID, platform: "other", reason: Some("Native passkeys are not supported on this system.".into()), app_pin: false }
}

#[cfg(windows)]
pub fn run(hwnd: *mut core::ffi::c_void, prep: &Prepared, _pin: Option<&str>) -> Result<PrfResponse, PasskeyError> {
    crate::passkey_win::assert(hwnd, prep)
}

#[cfg(target_os = "linux")]
pub fn run(_hwnd: *mut core::ffi::c_void, prep: &Prepared, pin: Option<&str>) -> Result<PrfResponse, PasskeyError> {
    crate::passkey_linux::assert(prep, pin)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn run(_hwnd: *mut core::ffi::c_void, _prep: &Prepared, _pin: Option<&str>) -> Result<PrfResponse, PasskeyError> {
    Err(PasskeyError::new("unsupported", "Native passkeys are not supported on this system."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn prf_salt_fixed_vectors() {
        // Computed independently with node:crypto over "WebAuthn PRF\0" || input.
        assert_eq!(hex(&prf_salt(b"")), "6a7e64b2aa34c92736143a062fa149aff1bd8bb3f7ee6f346885481f9414a3d3");
        assert_eq!(hex(&prf_salt(b"hello")), "0548f3025671e73beab092b1ac870ddd33a0d925e193eca79ba8358919b73cdc");
        let ramp: Vec<u8> = (0u8..32).collect();
        assert_eq!(hex(&prf_salt(&ramp)), "dc1f4f3b3d759586245d5de7e2e115d2a056a2df27109db7cef9b4b3a89bb106");
    }

    #[test]
    fn client_data_has_the_fixed_origin_and_challenge() {
        let c = b64(&[7u8; 32]);
        let json = client_data_json(&c);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "webauthn.get");
        assert_eq!(v["challenge"], c);
        assert_eq!(v["origin"], format!("https://{RP_ID}"));
        assert_eq!(v["crossOrigin"], false);
    }

    fn req(creds: Vec<CredentialRequest>, challenge: &str) -> PrfRequest {
        PrfRequest { credentials: creds, challenge: challenge.to_string(), require_uv: true, pin: None }
    }

    fn cred(id: &[u8], s1: Option<&[u8]>) -> CredentialRequest {
        CredentialRequest { id: b64(id), salt1: s1.map(b64), salt2: None }
    }

    #[test]
    fn prepare_decodes_ids_and_hashes_salts() {
        let chal = b64(&[1u8; 32]);
        let p = prepare(&req(vec![cred(&[9u8; 20], Some(b"hello")), cred(&[8u8; 20], None)], &chal)).unwrap();
        assert_eq!(p.candidates.len(), 2);
        assert_eq!(p.candidates[0].id, vec![9u8; 20]);
        assert_eq!(p.candidates[0].salt1, Some(prf_salt(b"hello")));
        assert_eq!(p.candidates[1].salt1, None);
        assert!(p.require_uv);
        assert_eq!(p.client_data, client_data_json(&chal).into_bytes());
    }

    #[test]
    fn prepare_rejects_bad_requests() {
        let chal = b64(&[1u8; 32]);
        assert_eq!(prepare(&req(vec![], &chal)).unwrap_err().code, "bad-request");
        assert_eq!(prepare(&req(vec![cred(&[1], None)], &b64(&[1u8; 4]))).unwrap_err().code, "bad-request");
        assert_eq!(prepare(&req(vec![cred(&[], None)], &chal)).unwrap_err().code, "bad-request");
        assert_eq!(prepare(&req(vec![cred(&[1], Some(b""))], &chal)).unwrap_err().code, "bad-request");
        let too_many: Vec<_> = (0..17).map(|i| cred(&[i as u8 + 1], None)).collect();
        assert_eq!(prepare(&req(too_many, &chal)).unwrap_err().code, "bad-request");
        let mut c = cred(&[1], None);
        c.salt2 = Some(b64(b"x"));
        assert_eq!(prepare(&req(vec![c], &chal)).unwrap_err().code, "bad-request");
        let mut c = cred(&[1], None);
        c.id = "not base64 !!".into();
        assert_eq!(prepare(&req(vec![c], &chal)).unwrap_err().code, "bad-request");
    }

    #[test]
    fn ctap_errors_are_classified() {
        assert_eq!(classify("0x2E CTAP2_ERR_NO_CREDENTIALS"), CtapKind::NoCredentials);
        assert_eq!(classify("0x31 CTAP2_ERR_PIN_INVALID PIN Invalid."), CtapKind::PinInvalid);
        assert_eq!(classify("0x34 CTAP2_ERR_PIN_AUTH_BLOCKED"), CtapKind::PinBlocked);
        assert_eq!(classify("0x2D CTAP2_ERR_KEEPALIVE_CANCEL"), CtapKind::Cancelled);
        assert_eq!(classify("something else"), CtapKind::Other);
    }

    #[test]
    fn request_json_has_no_rp_id_field() {
        // The page cannot choose the relying party: an rpId in the request is ignored, not honoured.
        let j = serde_json::json!({
            "rpId": "evil.example", "credentials": [{ "id": b64(&[1u8; 16]), "salt1": b64(b"s") }], "challenge": b64(&[2u8; 32])
        });
        let r: PrfRequest = serde_json::from_value(j).unwrap();
        let p = prepare(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&p.client_data_json).unwrap();
        assert_eq!(v["origin"], format!("https://{RP_ID}"));
    }
}
