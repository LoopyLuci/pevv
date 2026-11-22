//! Windows 11 plugin authenticator, the OS-facing half: registration with the passkey API and the COM
//! class Windows calls for MakeCredential / GetAssertion. Cargo feature `win-passkey-provider`.
//!
//! Hand-declared FFI. The `windows` crate in use (0.61) has no bindings for `webauthnplugin.h` or
//! `pluginauthenticator.idl`, and the Windows SDK 10.0.26100 import library `webauthn.lib` does not
//! export the final names, so the functions are looked up at run time and the structs below are copied
//! from the headers in that SDK (`webauthnplugin.h`, `pluginauthenticator.idl`; the same headers are
//! public at github.com/microsoft/webauthn). Nothing here has run on a Windows 11 machine.
//!
//! Where the exports live is itself unsettled: the Microsoft reference page lists `WebAuthnPlugin.dll`,
//! shipping code loads them from `webauthn.dll`. Both are tried, `webauthn.dll` first.
//!
//! Not done: Windows signs every request with a key it returns from the registration call
//! (`pbOpSignPubKey`) and a careful plugin verifies that signature. This one does not; the COM class is
//! only reachable by processes that can activate it, and every request still needs the vault unlocked
//! and a click in the PEVV window. Listed as a decision in docs/PEVV_DESKTOP.md.

// COM method names are the interface's own (MakeCredential, ...), not Rust's.
#![allow(non_snake_case)]

use crate::provider::CredMeta;
use crate::provider_core::{self, Host, CLSID, NAME};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use windows::core::{implement, interface, Interface, BOOL, GUID, HRESULT, PCSTR, PCWSTR};
use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, HMODULE, S_OK};
use windows::Win32::System::Com::{
    CoInitializeEx, CoRegisterClassObject, CoTaskMemAlloc, IClassFactory, IClassFactory_Impl, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, REGCLS_MULTIPLEUSE,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};

/// The logo shown next to "PEVV" in Windows' passkey dialog (SVG 1.1, base64 on the wire).
const LOGO_SVG: &str = include_str!("../windows/pevv-passkey-logo.svg");

fn guid(s: &str) -> GUID {
    GUID::from_u128(u128::from_str_radix(&s.replace('-', ""), 16).unwrap_or(0))
}

fn clsid() -> GUID {
    guid(CLSID)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/* ───────────── structs from webauthnplugin.h and pluginauthenticator.idl ───────────── */

/// `WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS`. `rclsid` is a `REFCLSID`, a pointer in C.
#[repr(C)]
struct AddOptions {
    authenticator_name: PCWSTR,
    clsid: *const GUID,
    plugin_rp_id: PCWSTR,
    light_logo_svg: PCWSTR,
    dark_logo_svg: PCWSTR,
    cb_authenticator_info: u32,
    authenticator_info: *const u8,
    supported_rp_ids: u32,
    supported_rp_id_list: *const PCWSTR,
}

/// `WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE`.
#[repr(C)]
struct AddResponse {
    cb_op_sign_pub_key: u32,
    op_sign_pub_key: *mut u8,
}

/// `WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS`.
#[repr(C)]
struct CredentialDetails {
    cb_credential_id: u32,
    credential_id: *const u8,
    rp_id: PCWSTR,
    rp_name: PCWSTR,
    cb_user_id: u32,
    user_id: *const u8,
    user_name: PCWSTR,
    user_display_name: PCWSTR,
}

/// `WEBAUTHN_PLUGIN_OPERATION_REQUEST` (pluginauthenticator.idl; MIDL lays it out as C does).
#[repr(C)]
pub struct OperationRequest {
    hwnd: isize,
    transaction_id: GUID,
    cb_request_signature: u32,
    request_signature: *const u8,
    /// `WEBAUTHN_PLUGIN_REQUEST_TYPE`: 1 = CTAP2 CBOR.
    request_type: u32,
    cb_encoded_request: u32,
    encoded_request: *const u8,
}

/// `WEBAUTHN_PLUGIN_OPERATION_RESPONSE`: a CoTaskMemAlloc'd buffer the caller frees.
#[repr(C)]
pub struct OperationResponse {
    cb_encoded_response: u32,
    encoded_response: *mut u8,
}

/// `WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST`.
#[repr(C)]
pub struct CancelRequest {
    transaction_id: GUID,
    cb_request_signature: u32,
    request_signature: *const u8,
}

const REQUEST_TYPE_CTAP2_CBOR: u32 = 1;
/// `PLUGIN_LOCK_STATUS`: PluginLocked = 0, PluginUnlocked = 1.
const PLUGIN_LOCKED: u32 = 0;
const PLUGIN_UNLOCKED: u32 = 1;

/// `IPluginAuthenticator` (final, version 1.0 of the interface; the experimental one from the Insider
/// builds, e6466e9a-b2f3-47c5-b88d-89bc14a8d998 with three methods, is not implemented).
#[interface("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
pub unsafe trait IPluginAuthenticator: windows::core::IUnknown {
    fn MakeCredential(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT;
    fn GetAssertion(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT;
    fn CancelOperation(&self, request: *const CancelRequest) -> HRESULT;
    fn GetLockStatus(&self, lock_status: *mut u32) -> HRESULT;
}

/* ───────────── looking the functions up ───────────── */

fn resolve(name: &str) -> Option<*const c_void> {
    let cname = std::ffi::CString::new(name).ok()?;
    for dll in ["webauthn.dll", "WebAuthnPlugin.dll"] {
        let w = wide(dll);
        // System folder only: never a DLL next to the exe or on PATH.
        let Ok(module) = (unsafe { LoadLibraryExW(PCWSTR(w.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }) else { continue };
        let module: HMODULE = module;
        if let Some(f) = unsafe { GetProcAddress(module, PCSTR(cname.as_ptr().cast())) } {
            return Some(f as *const c_void);
        }
    }
    None
}

type AddFn = unsafe extern "system" fn(*const AddOptions, *mut *mut AddResponse) -> HRESULT;
type FreeAddFn = unsafe extern "system" fn(*mut AddResponse);
type RemoveFn = unsafe extern "system" fn(*const GUID) -> HRESULT;
type StateFn = unsafe extern "system" fn(*const GUID, *mut i32) -> HRESULT;
type AddCredsFn = unsafe extern "system" fn(*const GUID, u32, *const CredentialDetails) -> HRESULT;

/// Are the registration functions there? (Without them this Windows has no plugin API.)
pub fn api_present() -> bool {
    resolve("WebAuthNPluginAddAuthenticator").is_some() && resolve("WebAuthNPluginGetAuthenticatorState").is_some()
}

fn hr(r: HRESULT, what: &str) -> Result<(), String> {
    if r.is_ok() {
        Ok(())
    } else {
        Err(format!("{what} failed (0x{:08X})", r.0 as u32))
    }
}

/// (registered, enabled) from `WebAuthNPluginGetAuthenticatorState`: `AuthenticatorState_Disabled = 0`,
/// `AuthenticatorState_Enabled = 1`. An error means Windows does not know the CLSID (not registered).
pub fn state() -> (Option<bool>, Option<bool>) {
    let Some(f) = resolve("WebAuthNPluginGetAuthenticatorState") else { return (None, None) };
    let f: StateFn = unsafe { std::mem::transmute(f) };
    let id = clsid();
    let mut st = 0i32;
    let r = unsafe { f(&id, &mut st) };
    if r.is_ok() {
        (Some(true), Some(st == 1))
    } else if r.0 as u32 == 0x8009_0011 {
        // NTE_NOT_FOUND
        (Some(false), None)
    } else {
        (None, None)
    }
}

/// Register "PEVV" with Windows. It then appears under Settings > Accounts > Passkeys > Advanced
/// options, where the person switches it on. Registering again just updates it.
pub fn register() -> Result<(), String> {
    let add = resolve("WebAuthNPluginAddAuthenticator").ok_or("This Windows has no passkey plugin API.")?;
    let add: AddFn = unsafe { std::mem::transmute(add) };
    let free = resolve("WebAuthNPluginFreeAddAuthenticatorResponse").map(|f| unsafe { std::mem::transmute::<*const c_void, FreeAddFn>(f) });
    let name = wide(NAME);
    let logo = wide(&STANDARD.encode(LOGO_SVG));
    let info = provider_core::authenticator_info();
    let id = clsid();
    let opts = AddOptions {
        authenticator_name: PCWSTR(name.as_ptr()),
        clsid: &id,
        plugin_rp_id: PCWSTR::null(),
        light_logo_svg: PCWSTR(logo.as_ptr()),
        dark_logo_svg: PCWSTR(logo.as_ptr()),
        cb_authenticator_info: info.len() as u32,
        authenticator_info: info.as_ptr(),
        supported_rp_ids: 0,
        supported_rp_id_list: std::ptr::null(),
    };
    let mut resp: *mut AddResponse = std::ptr::null_mut();
    let r = unsafe { add(&opts, &mut resp) };
    if let Some(free) = free {
        if !resp.is_null() {
            unsafe { free(resp) };
        }
    }
    hr(r, "Registering with Windows")
}

pub fn unregister() -> Result<(), String> {
    let f = resolve("WebAuthNPluginRemoveAuthenticator").ok_or("This Windows has no passkey plugin API.")?;
    let f: RemoveFn = unsafe { std::mem::transmute(f) };
    let id = clsid();
    hr(unsafe { f(&id) }, "Removing from Windows")
}

/// Replace the account metadata Windows keeps for PEVV (names and ids only, never keys).
pub fn sync(list: &[CredMeta]) -> Result<(), String> {
    let remove_all = resolve("WebAuthNPluginAuthenticatorRemoveAllCredentials").ok_or("This Windows cannot list PEVV accounts.")?;
    let remove_all: RemoveFn = unsafe { std::mem::transmute(remove_all) };
    let id = clsid();
    // Not found just means there was nothing to remove.
    let r = unsafe { remove_all(&id) };
    if !r.is_ok() && r.0 as u32 != 0x8009_0011 {
        return hr(r, "Clearing the account list");
    }
    if list.is_empty() {
        return Ok(());
    }
    let add = resolve("WebAuthNPluginAuthenticatorAddCredentials").ok_or("This Windows cannot list PEVV accounts.")?;
    let add: AddCredsFn = unsafe { std::mem::transmute(add) };
    // Own every buffer until the call returns.
    struct Owned {
        cred: Vec<u8>,
        user: Vec<u8>,
        rp_id: Vec<u16>,
        rp_name: Vec<u16>,
        user_name: Vec<u16>,
        display: Vec<u16>,
    }
    let owned: Vec<Owned> = list
        .iter()
        .filter_map(|c| {
            Some(Owned {
                cred: URL_SAFE_NO_PAD.decode(&c.credential_id).ok()?,
                user: URL_SAFE_NO_PAD.decode(&c.user_handle).ok()?,
                rp_id: wide(&c.rp_id),
                rp_name: wide(&c.rp_name),
                user_name: wide(&c.user_name),
                display: wide(&c.user_display_name),
            })
        })
        .collect();
    let details: Vec<CredentialDetails> = owned
        .iter()
        .map(|o| CredentialDetails {
            cb_credential_id: o.cred.len() as u32,
            credential_id: o.cred.as_ptr(),
            rp_id: PCWSTR(o.rp_id.as_ptr()),
            rp_name: PCWSTR(o.rp_name.as_ptr()),
            cb_user_id: o.user.len() as u32,
            user_id: o.user.as_ptr(),
            user_name: PCWSTR(o.user_name.as_ptr()),
            user_display_name: PCWSTR(o.display.as_ptr()),
        })
        .collect();
    if details.is_empty() {
        return Ok(());
    }
    hr(unsafe { add(&id, details.len() as u32, details.as_ptr()) }, "Updating the account list")
}

/* ───────────── the COM class ───────────── */

type Cancels = Arc<Mutex<HashMap<u128, Arc<AtomicBool>>>>;

/// What the class factory needs to build one authenticator object. `next_id` numbers the requests.
pub struct Service {
    pub host: Arc<dyn Host>,
    pub next_id: Box<dyn Fn() -> u64 + Send + Sync>,
}

#[implement(IPluginAuthenticator)]
struct Authenticator {
    service: Arc<Service>,
    cancels: Cancels,
}

/// Run `f` for one request: register its cancel flag under the transaction id, copy the encoded request
/// out of Windows' buffer, and write the response (or the HRESULT of the failure).
unsafe fn run(this: &Authenticator, request: *const OperationRequest, response: *mut OperationResponse, f: provider_core::Handler) -> HRESULT {
    if request.is_null() || response.is_null() {
        return E_INVALIDARG;
    }
    let req = unsafe { &*request };
    unsafe { *response = OperationResponse { cb_encoded_response: 0, encoded_response: std::ptr::null_mut() } };
    if req.request_type != REQUEST_TYPE_CTAP2_CBOR || req.encoded_request.is_null() || req.cb_encoded_request as usize > provider_core::MAX_REQUEST {
        return E_INVALIDARG;
    }
    let encoded = unsafe { std::slice::from_raw_parts(req.encoded_request, req.cb_encoded_request as usize) }.to_vec();
    let key = req.transaction_id.to_u128();
    let cancel = Arc::new(AtomicBool::new(false));
    if let Ok(mut c) = this.cancels.lock() {
        c.insert(key, cancel.clone());
    }
    let out = f(&*this.service.host, (this.service.next_id)(), &encoded, &cancel, provider_core::UNLOCK_WAIT, std::time::Duration::from_millis(250));
    if let Ok(mut c) = this.cancels.lock() {
        c.remove(&key);
    }
    match out {
        Ok(bytes) => {
            // The caller frees this with CoTaskMemFree.
            let buf = unsafe { CoTaskMemAlloc(bytes.len().max(1)) }.cast::<u8>();
            if buf.is_null() {
                return E_FAIL;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
                *response = OperationResponse { cb_encoded_response: bytes.len() as u32, encoded_response: buf };
            }
            S_OK
        }
        Err(e) => HRESULT(e.hresult()),
    }
}

impl IPluginAuthenticator_Impl for Authenticator_Impl {
    unsafe fn MakeCredential(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT {
        unsafe { run(self, request, response, provider_core::make_credential) }
    }

    unsafe fn GetAssertion(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT {
        unsafe { run(self, request, response, provider_core::get_assertion) }
    }

    unsafe fn CancelOperation(&self, request: *const CancelRequest) -> HRESULT {
        if request.is_null() {
            return E_INVALIDARG;
        }
        let key = unsafe { (*request).transaction_id }.to_u128();
        if let Some(flag) = self.cancels.lock().ok().and_then(|c| c.get(&key).cloned()) {
            flag.store(true, Ordering::SeqCst);
        }
        // Cancelling something already finished is not an error.
        S_OK
    }

    unsafe fn GetLockStatus(&self, lock_status: *mut u32) -> HRESULT {
        if lock_status.is_null() {
            return E_INVALIDARG;
        }
        unsafe { *lock_status = if self.service.host.unlocked() { PLUGIN_UNLOCKED } else { PLUGIN_LOCKED } };
        S_OK
    }
}

#[implement(IClassFactory)]
struct Factory {
    service: Arc<Service>,
    cancels: Cancels,
}

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(&self, outer: windows::core::Ref<'_, windows::core::IUnknown>, iid: *const GUID, object: *mut *mut c_void) -> windows::core::Result<()> {
        if !outer.is_null() {
            return Err(windows::Win32::Foundation::CLASS_E_NOAGGREGATION.into());
        }
        let obj: IPluginAuthenticator = Authenticator { service: self.service.clone(), cancels: self.cancels.clone() }.into();
        unsafe { obj.query(iid, object).ok() }
    }

    fn LockServer(&self, _lock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

/// Register the class factory so Windows can reach the running app. Windows starts the app (with the
/// arguments from the MSIX manifest) if it is not running when a request comes in. A dedicated MTA
/// thread, so requests are served on RPC threads and never wait for the UI thread.
pub fn serve(service: Arc<Service>) {
    let _ = std::thread::Builder::new().name("pevv-passkey-com".into()).spawn(move || {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
        let factory: IClassFactory = Factory { service, cancels: Arc::new(Mutex::new(HashMap::new())) }.into();
        let id = clsid();
        if unsafe { CoRegisterClassObject(&id, &factory, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE) }.is_err() {
            return;
        }
        // The registration lives as long as this thread (and the factory it holds).
        loop {
            std::thread::park();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    /// The structs must match the C layout Windows uses (x64). Offsets computed from the headers.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn operation_request_matches_the_midl_layout() {
        assert_eq!(offset_of!(OperationRequest, hwnd), 0);
        assert_eq!(offset_of!(OperationRequest, transaction_id), 8);
        assert_eq!(offset_of!(OperationRequest, cb_request_signature), 24);
        assert_eq!(offset_of!(OperationRequest, request_signature), 32);
        assert_eq!(offset_of!(OperationRequest, request_type), 40);
        assert_eq!(offset_of!(OperationRequest, cb_encoded_request), 44);
        assert_eq!(offset_of!(OperationRequest, encoded_request), 48);
        assert_eq!(size_of::<OperationRequest>(), 56);
        assert_eq!(size_of::<OperationResponse>(), 16);
        assert_eq!(offset_of!(CancelRequest, request_signature), 24);
        assert_eq!(size_of::<CancelRequest>(), 32);
        assert_eq!(align_of::<OperationRequest>(), 8);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn registration_structs_match_the_header_layout() {
        assert_eq!(offset_of!(AddOptions, clsid), 8);
        assert_eq!(offset_of!(AddOptions, dark_logo_svg), 32);
        assert_eq!(offset_of!(AddOptions, cb_authenticator_info), 40);
        assert_eq!(offset_of!(AddOptions, authenticator_info), 48);
        assert_eq!(offset_of!(AddOptions, supported_rp_ids), 56);
        assert_eq!(offset_of!(AddOptions, supported_rp_id_list), 64);
        assert_eq!(size_of::<AddOptions>(), 72);
        assert_eq!(size_of::<AddResponse>(), 16);
        assert_eq!(offset_of!(CredentialDetails, rp_id), 16);
        assert_eq!(offset_of!(CredentialDetails, cb_user_id), 32);
        assert_eq!(offset_of!(CredentialDetails, user_id), 40);
        assert_eq!(size_of::<CredentialDetails>(), 64);
    }

    #[test]
    fn the_interface_ids_are_the_published_ones() {
        assert_eq!(IPluginAuthenticator::IID, guid("d26bcf6f-b54c-43ff-9f06-d5bf148625f7"));
        assert_eq!(clsid(), guid("56b40049-0a16-42c3-bded-1de50937b256"));
    }

    #[test]
    fn the_logo_is_an_svg() {
        assert!(LOGO_SVG.contains("<svg") && LOGO_SVG.contains("version=\"1.1\""));
        let b = STANDARD.encode(LOGO_SVG);
        assert!(b.len() < 4096);
    }

    #[test]
    fn a_missing_function_is_reported_not_called() {
        assert!(resolve("PevvNoSuchFunction").is_none());
    }
}
