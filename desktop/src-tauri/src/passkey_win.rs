//! Windows: `webauthn.dll` (the same API Chrome and Edge call). Windows shows its own
//! security-key / Windows Hello dialog, parented to the PEVV window, and handles PIN
//! entry. UNTESTED against real hardware: it compiles and the request building is
//! reviewed, but no authenticator has been touched with it.
//!
//! PRF on Windows: `pHmacSecretSaltValues` + `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`
//! on the get-assertion options (struct version 6, WebAuthn API version 6). The salts are the
//! hashed PRF inputs (see `passkey::prf_salt`), exactly what Chromium passes.

use crate::passkey::{b64, PasskeyError, Prepared, PrfResponse};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::*;

/// Get-assertion options v6 carry the hmac-secret salts.
pub const MIN_API_VERSION: u32 = WEBAUTHN_API_VERSION_6;

const NTE_USER_CANCELLED: u32 = 0x8009_0036;
const NTE_NOT_FOUND: u32 = 0x8009_0011;
const NTE_INVALID_PARAMETER: u32 = 0x8009_0027;
const NTE_DEVICE_NOT_FOUND: u32 = 0x8009_000F;
const HRESULT_TIMEOUT: u32 = 0x8007_05B4;

pub fn api_version() -> u32 {
    // SAFETY: no arguments; webauthn.dll is a system library.
    unsafe { WebAuthNGetApiVersionNumber() }
}

/// HRESULT from webauthn.dll to a stable code.
pub fn map_hresult(hr: u32) -> (&'static str, &'static str) {
    match hr {
        NTE_USER_CANCELLED | HRESULT_TIMEOUT => ("cancelled", "The request was cancelled or timed out."),
        NTE_NOT_FOUND | NTE_DEVICE_NOT_FOUND => {
            ("no-device", "No matching passkey or security key was found. Plug in the key you enrolled, or use your master password.")
        }
        NTE_INVALID_PARAMETER => ("failed", "Windows rejected the request (invalid parameter)."),
        _ => ("failed", "Windows could not complete the passkey request."),
    }
}

pub fn assert(hwnd: *mut core::ffi::c_void, prep: &Prepared) -> Result<PrfResponse, PasskeyError> {
    let ver = api_version();
    if ver < MIN_API_VERSION {
        return Err(PasskeyError::new(
            "unsupported",
            format!("This Windows has WebAuthn API version {ver}; passkey unlock needs {MIN_API_VERSION}. Use your master password."),
        ));
    }

    // Everything the API points at must outlive the call: keep it all in locals.
    let mut ids: Vec<Vec<u8>> = prep.candidates.iter().map(|c| c.id.clone()).collect();
    let mut cred_ex: Vec<WEBAUTHN_CREDENTIAL_EX> = ids
        .iter_mut()
        .map(|id| WEBAUTHN_CREDENTIAL_EX {
            dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
            cbId: id.len() as u32,
            pbId: id.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            dwTransports: 0,
        })
        .collect();
    let mut cred_ptrs: Vec<*mut WEBAUTHN_CREDENTIAL_EX> = cred_ex.iter_mut().map(|c| c as *mut _).collect();
    let mut allow = WEBAUTHN_CREDENTIAL_LIST { cCredentials: cred_ptrs.len() as u32, ppCredentials: cred_ptrs.as_mut_ptr() };

    // Per-credential salts (each passkey has its own random PRF input).
    let mut salt_bufs: Vec<([u8; 32], Option<[u8; 32]>)> = Vec::new();
    let mut salt_owner: Vec<usize> = Vec::new();
    for (i, c) in prep.candidates.iter().enumerate() {
        if let Some(s1) = c.salt1 {
            salt_bufs.push((s1, c.salt2));
            salt_owner.push(i);
        }
    }
    let mut salts: Vec<WEBAUTHN_HMAC_SECRET_SALT> = salt_bufs
        .iter_mut()
        .map(|(s1, s2)| WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 32,
            pbFirst: s1.as_mut_ptr(),
            cbSecond: if s2.is_some() { 32 } else { 0 },
            pbSecond: s2.as_mut().map_or(core::ptr::null_mut(), |s| s.as_mut_ptr()),
        })
        .collect();
    let mut per_cred: Vec<WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT> = salt_owner
        .iter()
        .zip(salts.iter_mut())
        .map(|(&i, s)| WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT { cbCredID: ids[i].len() as u32, pbCredID: ids[i].as_mut_ptr(), pHmacSecretSalt: s as *mut _ })
        .collect();
    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: core::ptr::null_mut(),
        cCredWithHmacSecretSaltList: per_cred.len() as u32,
        pCredWithHmacSecretSaltList: if per_cred.is_empty() { core::ptr::null_mut() } else { per_cred.as_mut_ptr() },
    };

    let mut client_data = prep.client_data.clone();
    let cd = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: client_data.len() as u32,
        pbClientDataJSON: client_data.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };

    let mut opts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
        dwTimeoutMilliseconds: 120_000,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        dwUserVerificationRequirement: if prep.require_uv {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED
        },
        pAllowCredentialList: &mut allow,
        ..Default::default()
    };
    if !per_cred.is_empty() {
        opts.dwFlags |= WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG;
        opts.pHmacSecretSaltValues = &mut salt_values;
    }

    let rp: Vec<u16> = crate::passkey::RP_ID.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: every pointer in `opts`, `cd` and the salt tables points into a local that lives
    // to the end of this function; the returned assertion is freed below.
    let result = unsafe { WebAuthNAuthenticatorGetAssertion(HWND(hwnd), PCWSTR(rp.as_ptr()), &cd, Some(&opts)) };
    let ptr = match result {
        Ok(p) if !p.is_null() => p,
        Ok(_) => return Err(PasskeyError::new("failed", "Windows returned no assertion.")),
        Err(e) => {
            let (code, msg) = map_hresult(e.code().0 as u32);
            return Err(PasskeyError::new(code, msg));
        }
    };

    // SAFETY: `ptr` is a valid WEBAUTHN_ASSERTION until WebAuthNFreeAssertion; copied out before freeing.
    let out = unsafe {
        let a = &*ptr;
        let slice = |p: *mut u8, n: u32| if p.is_null() || n == 0 { Vec::new() } else { std::slice::from_raw_parts(p, n as usize).to_vec() };
        let (prf1, prf2) = if a.pHmacSecret.is_null() {
            (None, None)
        } else {
            let h = &*a.pHmacSecret;
            let first = slice(h.pbFirst, h.cbFirst);
            let second = slice(h.pbSecond, h.cbSecond);
            ((!first.is_empty()).then(|| b64(&first)), (!second.is_empty()).then(|| b64(&second)))
        };
        PrfResponse {
            credential_id: b64(&slice(a.Credential.pbId, a.Credential.cbId)),
            prf1,
            prf2,
            authenticator_data: b64(&slice(a.pbAuthenticatorData, a.cbAuthenticatorData)),
            client_data_json: prep.client_data_json.clone(),
            signature: b64(&slice(a.pbSignature, a.cbSignature)),
        }
    };
    // SAFETY: allocated by WebAuthNAuthenticatorGetAssertion.
    unsafe { WebAuthNFreeAssertion(ptr) };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hresults_map_to_codes() {
        assert_eq!(map_hresult(NTE_USER_CANCELLED).0, "cancelled");
        assert_eq!(map_hresult(NTE_NOT_FOUND).0, "no-device");
        assert_eq!(map_hresult(0x1234_5678).0, "failed");
    }

    #[test]
    fn api_version_is_readable() {
        // Needs webauthn.dll only; asks for no authenticator.
        let _ = api_version();
    }
}
