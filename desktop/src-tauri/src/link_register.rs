//! Registering `pevv-native-host` with the browsers: the host manifest (JSON) and where each
//! browser looks for it. All writes go through `Sink`, so tests run against a recording sink and
//! never touch the real registry or a real browser profile.
//!
//! Windows: one manifest file in the app data folder; each browser's
//! `HKCU\Software\<vendor>\NativeMessagingHosts\com.luciverse.pevv` default value points to it.
//! Linux: one manifest file per browser under `~/.config/<browser>/NativeMessagingHosts/`.
//! No admin rights, nothing outside the user's own profile. Flatpak / snap browsers use their
//! own folders and are not covered.

use crate::link_proto::{extension_id_of_origin, HOST_NAME};
use std::io;
use std::path::{Path, PathBuf};

pub struct Browser {
    pub name: &'static str,
    /// Registry key under HKCU (without the host name), Windows.
    pub reg_key: &'static str,
    /// Folder under `~/.config` (Linux).
    pub config_dir: &'static str,
}

pub const BROWSERS: &[Browser] = &[
    Browser { name: "Chrome", reg_key: r"Google\Chrome\NativeMessagingHosts", config_dir: "google-chrome" },
    Browser { name: "Edge", reg_key: r"Microsoft\Edge\NativeMessagingHosts", config_dir: "microsoft-edge" },
    Browser { name: "Brave", reg_key: r"BraveSoftware\Brave-Browser\NativeMessagingHosts", config_dir: "BraveSoftware/Brave-Browser" },
    // Chromium has no registry key of its own that PEVV registers; Linux only.
    Browser { name: "Chromium", reg_key: "", config_dir: "chromium" },
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Os {
    Windows,
    Linux,
}

pub const fn current_os() -> Os {
    if cfg!(windows) {
        Os::Windows
    } else {
        Os::Linux
    }
}

/// Where things go for one run.
pub struct Layout {
    pub os: Os,
    /// Windows: the manifest file lives here (the app's data folder).
    pub data_dir: PathBuf,
    /// Linux: `~/.config`.
    pub config_home: PathBuf,
    /// Windows: registry prefix under HKCU, normally `Software`. Tests use a throwaway subtree.
    pub reg_root: String,
}

/// The JSON a browser reads. `allowed_origins` is what keeps any other extension from launching the host.
pub fn host_manifest(host_exe: &Path, ids: &[String]) -> serde_json::Value {
    let origins: Vec<String> =
        ids.iter().filter(|i| extension_id_of_origin(&format!("chrome-extension://{i}/")).is_some()).map(|i| format!("chrome-extension://{i}/")).collect();
    serde_json::json!({
        "name": HOST_NAME,
        "description": "PEVV desktop app link",
        "path": host_exe.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": origins,
    })
}

pub trait Sink {
    fn write_file(&mut self, path: &Path, content: &str) -> io::Result<()>;
    fn remove_file(&mut self, path: &Path) -> io::Result<()>;
    fn reg_set_default(&mut self, subkey: &str, value: &str) -> io::Result<()>;
    fn reg_delete_tree(&mut self, subkey: &str) -> io::Result<()>;
}

fn win_manifest_path(l: &Layout) -> PathBuf {
    l.data_dir.join("native-messaging").join(format!("{HOST_NAME}.json"))
}

fn linux_manifest_path(l: &Layout, b: &Browser) -> PathBuf {
    l.config_home.join(b.config_dir).join("NativeMessagingHosts").join(format!("{HOST_NAME}.json"))
}

fn reg_subkey(l: &Layout, b: &Browser) -> String {
    format!(r"{}\{}\{HOST_NAME}", l.reg_root, b.reg_key)
}

/// Write the manifest(s) and registry entries. Returns the browsers registered. A browser that
/// is not installed is harmless to register for, and the Linux folders are created on purpose:
/// a browser installed later finds the host without a second run.
pub fn register(sink: &mut dyn Sink, l: &Layout, host_exe: &Path, ids: &[String]) -> io::Result<Vec<&'static str>> {
    let text = serde_json::to_string_pretty(&host_manifest(host_exe, ids)).map_err(io::Error::other)?;
    let mut done = Vec::new();
    match l.os {
        Os::Windows => {
            let file = win_manifest_path(l);
            sink.write_file(&file, &text)?;
            for b in BROWSERS.iter().filter(|b| !b.reg_key.is_empty()) {
                sink.reg_set_default(&reg_subkey(l, b), &file.to_string_lossy())?;
                done.push(b.name);
            }
        }
        Os::Linux => {
            for b in BROWSERS {
                sink.write_file(&linux_manifest_path(l, b), &text)?;
                done.push(b.name);
            }
        }
    }
    Ok(done)
}

pub fn unregister(sink: &mut dyn Sink, l: &Layout) -> io::Result<()> {
    match l.os {
        Os::Windows => {
            for b in BROWSERS.iter().filter(|b| !b.reg_key.is_empty()) {
                sink.reg_delete_tree(&reg_subkey(l, b))?;
            }
            sink.remove_file(&win_manifest_path(l))?;
        }
        Os::Linux => {
            for b in BROWSERS {
                sink.remove_file(&linux_manifest_path(l, b))?;
            }
        }
    }
    Ok(())
}

/// Browsers whose registration currently points at `host_exe` with our id list. Reads the same
/// places `register` writes.
pub fn registered(l: &Layout, host_exe: &Path, ids: &[String]) -> Vec<&'static str> {
    let want = host_manifest(host_exe, ids);
    let same = |p: &Path| std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()).is_some_and(|v| v == want);
    match l.os {
        Os::Windows => {
            let file = win_manifest_path(l);
            if !same(&file) {
                return Vec::new();
            }
            BROWSERS
                .iter()
                .filter(|b| !b.reg_key.is_empty())
                .filter(|b| imp::reg_get_default(&reg_subkey(l, b)).is_some_and(|v| Path::new(&v) == file))
                .map(|b| b.name)
                .collect()
        }
        Os::Linux => BROWSERS.iter().filter(|b| same(&linux_manifest_path(l, b))).map(|b| b.name).collect(),
    }
}

/// The real thing: files on disk, HKCU on Windows.
pub struct RealSink;

impl Sink for RealSink {
    fn write_file(&mut self, path: &Path, content: &str) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, content)?;
        std::fs::rename(&tmp, path)
    }

    fn remove_file(&mut self, path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    fn reg_set_default(&mut self, subkey: &str, value: &str) -> io::Result<()> {
        imp::reg_set_default(subkey, value)
    }

    fn reg_delete_tree(&mut self, subkey: &str) -> io::Result<()> {
        imp::reg_delete_tree(subkey)
    }
}

#[cfg(windows)]
mod imp {
    use std::io;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
        RRF_RT_REG_SZ,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn reg_set_default(subkey: &str, value: &str) -> io::Result<()> {
        let key = wide(subkey);
        let data: Vec<u8> = wide(value).iter().flat_map(|c| c.to_le_bytes()).collect();
        unsafe {
            let mut h = HKEY::default();
            let rc = RegCreateKeyExW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), None, PCWSTR::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut h, None);
            if rc != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(rc.0 as i32));
            }
            let rc = RegSetValueExW(h, PCWSTR::null(), None, REG_SZ, Some(&data));
            let _ = RegCloseKey(h);
            if rc != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(rc.0 as i32));
            }
        }
        Ok(())
    }

    pub fn reg_get_default(subkey: &str) -> Option<String> {
        let key = wide(subkey);
        let mut buf = vec![0u16; 1024];
        let mut bytes = (buf.len() * 2) as u32;
        let rc = unsafe {
            RegGetValueW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), PCWSTR::null(), RRF_RT_REG_SZ, None, Some(buf.as_mut_ptr().cast()), Some(&mut bytes))
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let n = (bytes as usize / 2).saturating_sub(1);
        Some(String::from_utf16_lossy(&buf[..n]))
    }

    pub fn reg_delete_tree(subkey: &str) -> io::Result<()> {
        let key = wide(subkey);
        let rc = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr())) };
        if rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc.0 as i32))
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;

    pub fn reg_set_default(_: &str, _: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no registry here"))
    }

    pub fn reg_get_default(_: &str) -> Option<String> {
        None
    }

    pub fn reg_delete_tree(_: &str) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Rec {
        files: Vec<(PathBuf, String)>,
        removed: Vec<PathBuf>,
        reg: Vec<(String, String)>,
        reg_deleted: Vec<String>,
    }

    impl Sink for Rec {
        fn write_file(&mut self, p: &Path, c: &str) -> io::Result<()> {
            self.files.push((p.to_path_buf(), c.to_string()));
            Ok(())
        }
        fn remove_file(&mut self, p: &Path) -> io::Result<()> {
            self.removed.push(p.to_path_buf());
            Ok(())
        }
        fn reg_set_default(&mut self, k: &str, v: &str) -> io::Result<()> {
            self.reg.push((k.to_string(), v.to_string()));
            Ok(())
        }
        fn reg_delete_tree(&mut self, k: &str) -> io::Result<()> {
            self.reg_deleted.push(k.to_string());
            Ok(())
        }
    }

    const ID: &str = "dolmkecfaekonkkgpjpamipjleindand";

    fn layout(os: Os) -> Layout {
        Layout { os, data_dir: PathBuf::from("DATA"), config_home: PathBuf::from("CFG"), reg_root: "Software".into() }
    }

    #[test]
    fn manifest_lists_only_valid_ids_and_the_host_path() {
        let m = host_manifest(Path::new("HOST/pevv-native-host"), &[ID.into(), "not-an-id".into(), "../x".into()]);
        assert_eq!(m["name"], "com.luciverse.pevv");
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["path"], "HOST/pevv-native-host");
        assert_eq!(m["allowed_origins"], serde_json::json!([format!("chrome-extension://{ID}/")]));
        assert!(m.get("allowed_extensions").is_none());
    }

    #[test]
    fn windows_registers_chrome_edge_brave_under_hkcu_pointing_at_one_manifest() {
        let mut s = Rec::default();
        let done = register(&mut s, &layout(Os::Windows), Path::new("HOST.exe"), &[ID.into()]).unwrap();
        assert_eq!(done, vec!["Chrome", "Edge", "Brave"]);
        assert_eq!(s.files.len(), 1);
        let file = s.files[0].0.to_string_lossy().into_owned();
        assert!(file.ends_with("com.luciverse.pevv.json"));
        let keys: Vec<&str> = s.reg.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                r"Software\Google\Chrome\NativeMessagingHosts\com.luciverse.pevv",
                r"Software\Microsoft\Edge\NativeMessagingHosts\com.luciverse.pevv",
                r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.luciverse.pevv",
            ]
        );
        assert!(s.reg.iter().all(|(_, v)| *v == file));
    }

    #[test]
    fn linux_writes_one_manifest_per_browser() {
        let mut s = Rec::default();
        let done = register(&mut s, &layout(Os::Linux), Path::new("/usr/bin/pevv-native-host"), &[ID.into()]).unwrap();
        assert_eq!(done, vec!["Chrome", "Edge", "Brave", "Chromium"]);
        let paths: Vec<String> = s.files.iter().map(|(p, _)| p.to_string_lossy().replace('\\', "/")).collect();
        assert_eq!(
            paths,
            vec![
                "CFG/google-chrome/NativeMessagingHosts/com.luciverse.pevv.json",
                "CFG/microsoft-edge/NativeMessagingHosts/com.luciverse.pevv.json",
                "CFG/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.luciverse.pevv.json",
                "CFG/chromium/NativeMessagingHosts/com.luciverse.pevv.json",
            ]
        );
        assert!(s.reg.is_empty());
        let v: serde_json::Value = serde_json::from_str(&s.files[0].1).unwrap();
        assert_eq!(v["path"], "/usr/bin/pevv-native-host");
    }

    #[test]
    fn unregister_undoes_exactly_what_register_wrote() {
        for os in [Os::Windows, Os::Linux] {
            let mut w = Rec::default();
            register(&mut w, &layout(os), Path::new("H"), &[ID.into()]).unwrap();
            let mut u = Rec::default();
            unregister(&mut u, &layout(os)).unwrap();
            let wrote: Vec<&PathBuf> = w.files.iter().map(|(p, _)| p).collect();
            let gone: Vec<&PathBuf> = u.removed.iter().collect();
            assert_eq!(wrote, gone);
            let set: Vec<&String> = w.reg.iter().map(|(k, _)| k).collect();
            assert_eq!(set, u.reg_deleted.iter().collect::<Vec<_>>());
        }
    }

    /// The real files and, on Windows, the real registry API, but under a throwaway tree
    /// (`Software\Luciverse-PevvTest-<pid>`) and a temp folder. The browsers' own keys are never touched.
    #[test]
    fn real_sink_round_trip_in_a_throwaway_location() {
        let dir = tempfile::tempdir().unwrap();
        let l = Layout {
            os: current_os(),
            data_dir: dir.path().join("data"),
            config_home: dir.path().join("cfg"),
            reg_root: format!(r"Software\Luciverse-PevvTest-{}", std::process::id()),
        };
        let host = dir.path().join("pevv-native-host");
        let ids = vec![ID.to_string()];
        assert!(registered(&l, &host, &ids).is_empty());
        let mut sink = RealSink;
        let done = register(&mut sink, &l, &host, &ids).unwrap();
        assert!(!done.is_empty());
        assert_eq!(registered(&l, &host, &ids), done);
        assert!(registered(&l, &dir.path().join("moved"), &ids).is_empty(), "a stale path is not 'registered'");
        unregister(&mut sink, &l).unwrap();
        assert!(registered(&l, &host, &ids).is_empty());
        #[cfg(windows)]
        imp::reg_delete_tree(&l.reg_root).unwrap();
    }
}
