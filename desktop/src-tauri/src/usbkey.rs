//! USB key file: list removable volumes, write the `.pevvkey` file, read it back.
//!
//! The file content is made by the page (the 32-byte secret never comes from Rust) and is
//! opaque here apart from a size limit. The slot in the vault is bound to that content
//! only, not to the drive. The commands only touch a directory that this module itself
//! listed as a removable volume a moment ago, so the page cannot ask for an arbitrary path.

use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const KEY_FILE_NAME: &str = ".pevvkey";
const MAX_FILE: u64 = 4096;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    pub path: String,
    pub label: String,
    pub has_key_file: bool,
}

/// Mount points under `/run/media/<user>/` or `/media/` from the text of `/proc/mounts`.
/// Returns `(mount point, label)`; the label is the last path component.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_mounts(text: &str, user: &str) -> Vec<(String, String)> {
    let user_root = format!("/run/media/{user}/");
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(dev), Some(mnt)) = (it.next(), it.next()) else { continue };
        if !dev.starts_with("/dev/") {
            continue;
        }
        let mnt = unescape_mount(mnt);
        let under = |root: &str| mnt.len() > root.len() && mnt.starts_with(root);
        if !(under(&user_root) || under("/media/")) {
            continue;
        }
        let label = mnt.rsplit('/').next().unwrap_or("").to_string();
        if !out.iter().any(|(m, _)| *m == mnt) {
            out.push((mnt, label));
        }
    }
    out
}

/// `/proc/mounts` writes space, tab, newline and backslash as `\040`, `\011`, `\012`, `\134`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(windows)]
fn removable_roots() -> Vec<(String, String)> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW};
    const DRIVE_REMOVABLE: u32 = 2;
    // SAFETY: plain queries over drive letters; buffers are local and sized.
    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let root = format!("{}:\\", (b'A' + i as u8) as char);
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        if unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) } != DRIVE_REMOVABLE {
            continue;
        }
        let mut name = [0u16; 261];
        let ok = unsafe { GetVolumeInformationW(PCWSTR(wide.as_ptr()), Some(&mut name), None, None, None, None) }.is_ok();
        if !ok {
            continue; // an empty card reader slot
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(0);
        let label = String::from_utf16_lossy(&name[..end]);
        out.push((root.clone(), if label.is_empty() { root } else { label }));
    }
    out
}

#[cfg(target_os = "linux")]
fn removable_roots() -> Vec<(String, String)> {
    let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
    match std::fs::read_to_string("/proc/mounts") {
        Ok(t) => parse_mounts(&t, &user),
        Err(_) => Vec::new(),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn removable_roots() -> Vec<(String, String)> {
    Vec::new()
}

pub fn list_volumes() -> Vec<Volume> {
    removable_roots()
        .into_iter()
        .map(|(path, label)| {
            let has_key_file = Path::new(&path).join(KEY_FILE_NAME).is_file();
            Volume { path, label, has_key_file }
        })
        .collect()
}

/// A directory the page may use: one of the volumes listed right now.
pub fn resolve_volume(path: &str) -> Result<PathBuf, String> {
    if list_volumes().iter().any(|v| v.path == path) {
        Ok(PathBuf::from(path))
    } else {
        Err("that drive is not a connected removable drive".into())
    }
}

/// Write the key file (0600 where the file system has modes) and read it back.
/// Refuses to overwrite an existing key file: replacing one silently would strand the vault slot made for it.
pub fn write_key_file(dir: &Path, content: &str) -> Result<(), String> {
    if content.is_empty() || content.len() as u64 > MAX_FILE {
        return Err("key file content has a bad size".into());
    }
    let target = dir.join(KEY_FILE_NAME);
    if target.exists() {
        return Err("exists".into());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&target).map_err(|e| format!("could not create the key file: {e}"))?;
    f.write_all(content.as_bytes()).map_err(|e| format!("could not write the key file: {e}"))?;
    f.sync_all().map_err(|e| format!("could not flush the key file: {e}"))?;
    drop(f);
    let back = read_key_file(dir)?;
    if back != content {
        let _ = std::fs::remove_file(&target);
        return Err("the drive did not keep what was written; the key file was removed".into());
    }
    Ok(())
}

pub fn read_key_file(dir: &Path) -> Result<String, String> {
    let target = dir.join(KEY_FILE_NAME);
    let meta = std::fs::metadata(&target).map_err(|_| "no key file on that drive".to_string())?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err("that is not a PEVV key file".into());
    }
    std::fs::read_to_string(&target).map_err(|e| format!("could not read the key file: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounts_parse_removable_locations_only() {
        let t = "\
/dev/nvme0n1p2 / ext4 rw 0 0
/dev/sda1 /run/media/ana/MY\\040STICK vfat rw 0 0
/dev/sdb1 /media/usb0 exfat rw 0 0
/dev/sdc1 /run/media/other/THEIRS vfat rw 0 0
tmpfs /run/user/1000 tmpfs rw 0 0
/dev/sda1 /run/media/ana/MY\\040STICK vfat rw 0 0
/dev/sdd1 /media ext4 rw 0 0
";
        let v = parse_mounts(t, "ana");
        assert_eq!(v, vec![("/run/media/ana/MY STICK".to_string(), "MY STICK".to_string()), ("/media/usb0".to_string(), "usb0".to_string())]);
    }

    #[test]
    fn write_then_read_back_and_refuse_overwrite() {
        let d = tempfile::tempdir().unwrap();
        write_key_file(d.path(), "{\"secret\":\"abc\"}").unwrap();
        assert_eq!(read_key_file(d.path()).unwrap(), "{\"secret\":\"abc\"}");
        assert_eq!(write_key_file(d.path(), "other").unwrap_err(), "exists");
        assert_eq!(read_key_file(d.path()).unwrap(), "{\"secret\":\"abc\"}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.path().join(KEY_FILE_NAME)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn rejects_empty_oversized_and_missing() {
        let d = tempfile::tempdir().unwrap();
        assert!(write_key_file(d.path(), "").is_err());
        assert!(write_key_file(d.path(), &"x".repeat(5000)).is_err());
        assert!(read_key_file(d.path()).is_err());
        std::fs::write(d.path().join(KEY_FILE_NAME), "x".repeat(5000)).unwrap();
        assert!(read_key_file(d.path()).is_err());
    }

    #[test]
    fn arbitrary_paths_are_not_volumes() {
        assert!(resolve_volume("C:\\Windows").is_err());
        assert!(resolve_volume("/etc").is_err());
        assert!(resolve_volume("").is_err());
    }

    #[test]
    fn listing_does_not_panic() {
        let _ = list_volumes();
    }
}
