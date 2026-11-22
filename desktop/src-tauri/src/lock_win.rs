//! Windows lock signals: a hidden top-level window on its own thread that
//! receives WTS session notifications (workstation lock, remote/console
//! disconnect) and power broadcasts (suspend). A hidden window rather than a
//! message-only one, because only top-level windows get WM_POWERBROADCAST.

use std::sync::{Arc, OnceLock};
use windows::core::w;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW, TranslateMessage, CS_HREDRAW, MSG, WINDOW_EX_STYLE, WM_POWERBROADCAST,
    WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED,
};

pub type Notify = Arc<dyn Fn() + Send + Sync + 'static>;

static NOTIFY: OnceLock<Notify> = OnceLock::new();

/// `wParam` of WM_WTSSESSION_CHANGE that should lock the vault.
pub fn session_change_locks(w: usize) -> bool {
    // WTS_CONSOLE_DISCONNECT 2, WTS_REMOTE_DISCONNECT 4, WTS_SESSION_LOCK 7
    matches!(w, 2 | 4 | 7)
}

/// `wParam` of WM_POWERBROADCAST that should lock the vault.
pub fn power_event_locks(w: usize) -> bool {
    // PBT_APMSUSPEND 4
    w == 4
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let lock = match msg {
        WM_WTSSESSION_CHANGE => session_change_locks(wparam.0),
        WM_POWERBROADCAST => power_event_locks(wparam.0),
        _ => false,
    };
    if lock {
        if let Some(n) = NOTIFY.get() {
            n();
        }
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

pub fn start(on_lock: Notify) {
    if NOTIFY.set(on_lock).is_err() {
        return;
    }
    std::thread::spawn(|| unsafe {
        let Ok(hinst) = GetModuleHandleW(None) else { return };
        let class = w!("PevvLockWatcher");
        let wc = WNDCLASSW { style: CS_HREDRAW, lpfnWndProc: Some(wndproc), hInstance: hinst.into(), lpszClassName: class, ..Default::default() };
        if RegisterClassW(&wc) == 0 {
            return;
        }
        let Ok(hwnd) = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!(""), WS_OVERLAPPED, 0, 0, 0, 0, None, None, Some(hinst.into()), None) else {
            return;
        };
        let _ = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_on_lock_and_disconnect_not_on_unlock() {
        assert!(session_change_locks(7));
        assert!(session_change_locks(2));
        assert!(session_change_locks(4));
        assert!(!session_change_locks(8)); // unlock
        assert!(!session_change_locks(1)); // console connect
    }

    #[test]
    fn locks_on_suspend_only() {
        assert!(power_event_locks(4));
        assert!(!power_event_locks(7)); // resume suspend
        assert!(!power_event_locks(18)); // resume automatic
    }
}
