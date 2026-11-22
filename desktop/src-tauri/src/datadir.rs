//! Where the app keeps its files. One place decides it, so every store (vault, backups, settings,
//! browser link, `pevv` approvals, auto-type, presence) and the webview profile follow it.
//!
//! `PEVV_DATA_DIR` (an absolute folder; a relative one is made absolute against the working
//! folder) replaces the OS app-data folder. It is read once at startup. For testing and a portable
//! copy: the app then touches nothing of an installed PEVV (no window-state file, its own
//! webview profile, its own browser-link registry subtree).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const ENV: &str = "PEVV_DATA_DIR";

static OVERRIDE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The override from the environment, read the first time and kept.
pub fn override_dir() -> Option<&'static Path> {
    OVERRIDE.get_or_init(|| parse_override(std::env::var_os(ENV))).as_deref()
}

fn parse_override(v: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let p = PathBuf::from(v.filter(|v| !v.is_empty())?);
    if p.is_absolute() {
        return Some(p);
    }
    Some(std::env::current_dir().map(|c| c.join(&p)).unwrap_or(p))
}

/// The folder for `base` (the OS app-data folder) unless an override is given.
pub fn resolve(over: Option<&Path>, base: PathBuf) -> PathBuf {
    match over {
        Some(d) => d.to_path_buf(),
        None => base.join(if cfg!(windows) { "PEVV" } else { "pevv" }),
    }
}

/// The app data folder: the override if set, else `base` plus the app's folder name.
pub fn data_dir(base: impl FnOnce() -> PathBuf) -> PathBuf {
    match override_dir() {
        Some(d) => d.to_path_buf(),
        None => resolve(None, base()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_replaces_the_app_data_folder() {
        let over = std::env::temp_dir().join("pevv-datadir-test");
        assert_eq!(resolve(Some(&over), PathBuf::from("BASE")), over);
        let d = resolve(None, PathBuf::from("BASE"));
        assert!(d.starts_with("BASE"));
    }

    #[test]
    fn empty_means_unset_and_relative_becomes_absolute() {
        assert_eq!(parse_override(None), None);
        assert_eq!(parse_override(Some("".into())), None);
        assert!(parse_override(Some("some/rel".into())).unwrap().is_absolute());
    }

    #[test]
    fn stores_write_only_under_the_folder_they_are_given() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("portable");
        let store = crate::vault_store::VaultStore::new(dir.clone());
        let v1 = r#"{"format":"luciverse.pevv","id":"a","rev":1}"#;
        let v2 = r#"{"format":"luciverse.pevv","id":"b","rev":1}"#;
        store.write(v1, None).unwrap();
        store.write(v2, None).unwrap();
        let mut stack = vec![dir.clone()];
        let mut files = 0;
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                assert!(e.path().starts_with(&dir));
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    files += 1;
                }
            }
        }
        assert!(files >= 2, "vault and a backup");
        let siblings: Vec<_> = std::fs::read_dir(t.path()).unwrap().flatten().collect();
        assert_eq!(siblings.len(), 1, "nothing was written beside the folder");
    }

    #[test]
    fn ipc_and_instance_names_do_not_depend_on_the_data_folder() {
        // The pipe name is built from the user's SID only (link_ipc), the single-instance lock from the app identifier.
        let src = include_str!("link_ipc.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        assert!(!body.contains("datadir") && !body.contains("PEVV_DATA_DIR"));
    }
}
