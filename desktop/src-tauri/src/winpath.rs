//! Put the install folder (where `pevv.exe` lives) on the current user's PATH, and take it off
//! again on uninstall. The installer hook runs `pevv-desktop.exe --add-path` / `--remove-path`.
//!
//! The editing of the PATH text is pure and tested; the registry part (HKCU\Environment\Path,
//! kept as REG_EXPAND_SZ so `%VARS%` entries survive) is thin and Windows-only. A new terminal
//! picks the change up; programs already running do not.

/// The entries of a PATH value, split on `;` (empty ones dropped).
fn entries(path: &str) -> Vec<&str> {
    path.split(';').filter(|e| !e.trim().is_empty()).collect()
}

fn same(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches(['\\', '/']).to_ascii_lowercase();
    norm(a) == norm(b)
}

/// `Some(new value)` if `dir` was not on `path` yet (it goes last), `None` if nothing changes.
pub fn add_dir(path: &str, dir: &str) -> Option<String> {
    let dir = dir.trim().trim_end_matches(['\\', '/']);
    if dir.is_empty() || entries(path).iter().any(|e| same(e, dir)) {
        return None;
    }
    let mut all = entries(path);
    all.push(dir);
    Some(all.join(";"))
}

/// `Some(new value)` if `dir` was on `path`, `None` if it was not there.
pub fn remove_dir(path: &str, dir: &str) -> Option<String> {
    let before = entries(path);
    let after: Vec<&str> = before.iter().copied().filter(|e| !same(e, dir)).collect();
    (after.len() != before.len()).then(|| after.join(";"))
}

/// `--add-path` / `--remove-path`, run by the installer. Returns false for a flag that is not ours.
pub fn run_cli(flag: &str) -> bool {
    let add = match flag {
        "--add-path" => true,
        "--remove-path" => false,
        _ => return false,
    };
    let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_string_lossy().into_owned())) else { return true };
    // If the current value cannot be read, leave it alone: writing a guess would erase the user's PATH.
    let Some(current) = imp::read_user_path() else { return true };
    let next = if add { add_dir(&current, &dir) } else { remove_dir(&current, &dir) };
    if let Some(next) = next {
        let _ = imp::write_user_path(&next);
    }
    true
}

#[cfg(windows)]
mod imp {
    use std::io;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, LPARAM, WPARAM};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, RRF_NOEXPAND,
        RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
    };
    use windows::Win32::UI::WindowsAndMessaging::{SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn read_user_path() -> Option<String> {
        let (key, name) = (wide("Environment"), wide("Path"));
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
        // SAFETY: standard two-step registry read; the buffer is sized by the first call.
        unsafe {
            let mut bytes = 0u32;
            let rc = RegGetValueW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), PCWSTR(name.as_ptr()), flags, None, None, Some(&mut bytes));
            if rc == ERROR_FILE_NOT_FOUND {
                return Some(String::new());
            }
            if rc != ERROR_SUCCESS {
                return None;
            }
            let mut buf = vec![0u16; (bytes as usize).div_ceil(2) + 1];
            let mut bytes = (buf.len() * 2) as u32;
            let rc = RegGetValueW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), PCWSTR(name.as_ptr()), flags, None, Some(buf.as_mut_ptr().cast()), Some(&mut bytes));
            if rc != ERROR_SUCCESS {
                return None;
            }
            let n = (bytes as usize / 2).saturating_sub(1);
            Some(String::from_utf16_lossy(&buf[..n]))
        }
    }

    pub fn write_user_path(value: &str) -> io::Result<()> {
        let (key, name) = (wide("Environment"), wide("Path"));
        let data: Vec<u8> = wide(value).iter().flat_map(|c| c.to_le_bytes()).collect();
        // SAFETY: plain registry write; the key handle is closed before returning.
        unsafe {
            let mut h = HKEY::default();
            let rc = RegCreateKeyExW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), None, PCWSTR::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut h, None);
            if rc != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(rc.0 as i32));
            }
            let rc = RegSetValueExW(h, PCWSTR(name.as_ptr()), None, REG_EXPAND_SZ, Some(&data));
            let _ = RegCloseKey(h);
            if rc != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(rc.0 as i32));
            }
            // Tell running programs (Explorer, new terminals) that the environment changed.
            let env = wide("Environment");
            let _ = SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, WPARAM(0), LPARAM(env.as_ptr() as isize), SMTO_ABORTIFHUNG, 2000, None);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn read_user_path() -> Option<String> {
        None
    }

    pub fn write_user_path(_: &str) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_the_folder_once_at_the_end() {
        let p = "C:\\Windows;C:\\Tools;%USERPROFILE%\\bin";
        assert_eq!(add_dir(p, "C:\\Users\\a\\AppData\\Local\\PEVV").unwrap(), "C:\\Windows;C:\\Tools;%USERPROFILE%\\bin;C:\\Users\\a\\AppData\\Local\\PEVV");
        assert_eq!(add_dir("", "C:\\X\\").unwrap(), "C:\\X");
        assert_eq!(add_dir(";;C:\\a;", "D:\\b").unwrap(), "C:\\a;D:\\b", "empty entries are tidied");
    }

    #[test]
    fn does_not_add_a_folder_that_is_already_there() {
        assert_eq!(add_dir("C:\\A;C:\\PEVV\\", "c:\\pevv"), None, "case and trailing slash do not matter");
        assert_eq!(add_dir("C:\\A", ""), None);
    }

    #[test]
    fn removes_only_that_folder() {
        assert_eq!(remove_dir("C:\\A;C:\\PEVV;C:\\B", "c:\\pevv\\").unwrap(), "C:\\A;C:\\B");
        assert_eq!(remove_dir("C:\\PEVV", "C:\\PEVV").unwrap(), "");
        assert_eq!(remove_dir("C:\\A;C:\\B", "C:\\PEVV"), None);
        assert_eq!(remove_dir("C:\\PEVV2;C:\\A", "C:\\PEVV"), None, "a longer name is a different folder");
    }

    #[test]
    fn other_flags_are_not_ours() {
        assert!(!run_cli("--register-link"));
        assert!(!run_cli("--frobnicate"));
    }
}
