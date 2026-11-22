//! Linux: talk CTAP2 to USB FIDO2 keys directly over hidraw (`ctap-hid-fido2`) and ask for
//! `hmac-secret`, which is what a browser's PRF maps to (salt = `passkey::prf_salt`).
//! UNTESTED against real hardware. Needs read/write access to the key's `/dev/hidraw*`
//! node: install a udev rule (see docs/PEVV_DESKTOP.md) or a distro's `libfido2` /
//! `fido2-udev` package.
//!
//! PIN: when the key has a PIN set, the command answers `pin-required` and the page asks
//! for it and retries with `pin`. A key with a PIN is always used with user verification,
//! because browsers enrol and evaluate PRF with UV and the key derives a different
//! secret with and without it.

use crate::passkey::{b64, classify, Candidate, CtapKind, PasskeyError, Prepared, PrfResponse, RP_ID};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::{Assertion, Extension};
use ctap_hid_fido2::fidokey::get_assertion::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::fidokey::FidoKeyHid;
use ctap_hid_fido2::{get_fidokey_devices, FidoKeyHidFactory, LibCfg};

pub fn assert(prep: &Prepared, pin: Option<&str>) -> Result<PrfResponse, PasskeyError> {
    let devices = get_fidokey_devices();
    if devices.is_empty() {
        return Err(PasskeyError::new("no-device", "No security key found. Plug it in (and check the udev rule), or use your master password."));
    }
    let cfg = LibCfg { enable_keep_alive_msg: false, ..LibCfg::init() };
    let mut last_err: Option<PasskeyError> = None;
    for info in devices {
        let key = match FidoKeyHidFactory::create_by_params(std::slice::from_ref(&info.param), &cfg) {
            Ok(k) => k,
            Err(e) => {
                last_err = Some(PasskeyError::new("failed", format!("Could not open the security key: {e}")));
                continue;
            }
        };
        let has_pin = matches!(key.enable_info_option(&InfoOption::ClientPin), Ok(Some(true)));
        if has_pin && pin.is_none() {
            return Err(PasskeyError::new("pin-required", "Enter your security key PIN."));
        }
        for cand in &prep.candidates {
            match try_credential(&key, prep, cand, if has_pin { pin } else { None }) {
                Ok(Some(r)) => return Ok(r),
                Ok(None) => {}
                Err(e) if e.code == "no-credential" => {}
                Err(e) => return Err(e),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| PasskeyError::new("no-device", "None of the connected security keys holds this vault's passkey.")))
}

fn try_credential(key: &FidoKeyHid, prep: &Prepared, cand: &Candidate, pin: Option<&str>) -> Result<Option<PrfResponse>, PasskeyError> {
    let mut exts = Vec::new();
    match (cand.salt1, cand.salt2) {
        (Some(a), Some(b)) => exts.push(Extension::HmacSecret2(Some((a, b)))),
        (Some(a), None) => exts.push(Extension::HmacSecret(Some(a))),
        _ => {}
    }
    // The crate hashes this once to get clientDataHash, so pass the clientDataJSON bytes themselves.
    let mut b = GetAssertionArgsBuilder::new(RP_ID, &prep.client_data).credential_id(&cand.id);
    b = match pin {
        Some(p) => b.pin(p),
        None => b.without_pin_and_uv(),
    };
    if !exts.is_empty() {
        b = b.extensions(&exts);
    }
    let args = b.build();
    let assertions = match key.get_assertion_with_args(&args) {
        Ok(a) => a,
        Err(e) => {
            return match classify(&format!("{e:#}")) {
                CtapKind::NoCredentials => Err(PasskeyError::new("no-credential", "")),
                CtapKind::PinInvalid => Err(PasskeyError::new("pin-invalid", "That PIN is not correct.")),
                CtapKind::PinBlocked => Err(PasskeyError::new("failed", "The security key's PIN is blocked. Unplug it and plug it in again, or reset it.")),
                CtapKind::Cancelled => Err(PasskeyError::new("cancelled", "The request was cancelled or timed out.")),
                CtapKind::Other => Err(PasskeyError::new("failed", format!("The security key refused the request: {e:#}"))),
            };
        }
    };
    let Some(a) = assertions.into_iter().next() else { return Ok(None) };
    Ok(Some(response(prep, cand, &a)))
}

fn response(prep: &Prepared, cand: &Candidate, a: &Assertion) -> PrfResponse {
    let (mut prf1, mut prf2) = (None, None);
    for e in &a.extensions {
        match e {
            Extension::HmacSecret(Some(o)) => prf1 = Some(b64(o)),
            Extension::HmacSecret2(Some((o1, o2))) => {
                prf1 = Some(b64(o1));
                prf2 = Some(b64(o2));
            }
            _ => {}
        }
    }
    // With a one-entry allowList the key may leave the credential id out of its answer.
    let id = if a.credential_id.is_empty() { cand.id.clone() } else { a.credential_id.clone() };
    PrfResponse {
        credential_id: b64(&id),
        prf1,
        prf2,
        authenticator_data: b64(&a.auth_data),
        client_data_json: prep.client_data_json.clone(),
        signature: b64(&a.signature),
    }
}
