//! The vault file on disk. It holds the ciphertext `VaultFile` JSON only: this
//! code never sees a password, a key or plaintext, and only reads three header
//! fields (`format`, `id`, `rev`) to refuse a stale or foreign write.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VAULT_FORMAT: &str = "luciverse.pevv";
pub const FILE_NAME: &str = "vault.json";
pub const BACKUP_DIR: &str = "backups";
pub const BACKUPS_KEPT: usize = 5;
/// A new backup is cut at most this often, so five of them reach back further than the last five edits.
pub const BACKUP_EVERY: Duration = Duration::from_secs(10 * 60);
/// A real vault is a few hundred KB; this only stops a runaway write.
pub const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(tag = "code", rename_all = "kebab-case")]
pub enum StoreError {
    /// The file on disk has a higher revision of the same vault.
    RevConflict {
        current_rev: u64,
        message: String,
    },
    /// Not a PEVV vault file, or too large.
    Invalid {
        message: String,
    },
    Io {
        message: String,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::RevConflict { message, .. } | StoreError::Invalid { message } | StoreError::Io { message } => f.write_str(message),
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io { message: e.to_string() }
    }
}

#[derive(Debug, Deserialize)]
struct Header {
    format: String,
    id: String,
    rev: u64,
}

fn header(json: &str) -> Result<Header, StoreError> {
    if json.len() > MAX_BYTES {
        return Err(StoreError::Invalid { message: "vault file too large".into() });
    }
    let h: Header = serde_json::from_str(json).map_err(|e| StoreError::Invalid { message: format!("not a vault file: {e}") })?;
    if h.format != VAULT_FORMAT {
        return Err(StoreError::Invalid { message: "not a PEVV vault file".into() });
    }
    Ok(h)
}

fn hash_of(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn conflict(next: u64, floor: u64) -> StoreError {
    StoreError::RevConflict { current_rev: floor, message: format!("vault revision {next} is older than {floor}") }
}

#[derive(Default)]
struct State {
    last_backup: Option<SystemTime>,
    /// Hash of the last content this process wrote, so the file watcher can skip its own writes.
    last_written: Option<u64>,
}

pub struct VaultStore {
    dir: PathBuf,
    keep: usize,
    backup_every: Duration,
    state: Mutex<State>,
}

impl VaultStore {
    pub fn new(dir: PathBuf) -> Self {
        Self::with_policy(dir, BACKUPS_KEPT, BACKUP_EVERY)
    }

    pub fn with_policy(dir: PathBuf, keep: usize, backup_every: Duration) -> Self {
        Self { dir, keep, backup_every, state: Mutex::new(State::default()) }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    fn backup_dir(&self) -> PathBuf {
        self.dir.join(BACKUP_DIR)
    }

    pub fn read(&self) -> Result<Option<String>, StoreError> {
        match fs::read_to_string(self.path()) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// True when `content` is exactly what this process last wrote (a watcher echo, not another instance).
    pub fn is_own_write(&self, content: &str) -> bool {
        self.state.lock().map(|s| s.last_written == Some(hash_of(content))).unwrap_or(false)
    }

    /// Write `json` atomically. Returns the revision written.
    ///
    /// Refused when its revision is lower than the file already on disk (same
    /// vault id) or lower than `expected_rev`, the revision the caller last saw
    /// on disk. A different vault id replaces the file; the old one is backed up first.
    pub fn write(&self, json: &str, expected_rev: Option<u64>) -> Result<u64, StoreError> {
        let next = header(json)?;
        let mut st = self.state.lock().map_err(|_| StoreError::Io { message: "store lock poisoned".into() })?;
        fs::create_dir_all(&self.dir)?;
        restrict_dir(&self.dir);

        let mut floor = expected_rev.unwrap_or(0);
        if let Some(cur_raw) = self.read()? {
            if cur_raw == json {
                st.last_written = Some(hash_of(json));
                return Ok(next.rev);
            }
            let mut force_backup = false;
            match header(&cur_raw) {
                Ok(cur) if cur.id == next.id => floor = floor.max(cur.rev),
                // A different vault (or an unreadable file): keep the old one as a backup.
                _ => force_backup = true,
            }
            if next.rev < floor {
                return Err(conflict(next.rev, floor));
            }
            self.maybe_backup(&mut st, &cur_raw, force_backup)?;
        } else if next.rev < floor {
            return Err(conflict(next.rev, floor));
        }

        atomic_write(&self.path(), json.as_bytes())?;
        st.last_written = Some(hash_of(json));
        Ok(next.rev)
    }

    /// Remove the live file after keeping a backup of it (a vault reset in the UI).
    pub fn clear(&self) -> Result<(), StoreError> {
        let mut st = self.state.lock().map_err(|_| StoreError::Io { message: "store lock poisoned".into() })?;
        if let Some(cur) = self.read()? {
            self.maybe_backup(&mut st, &cur, true)?;
            fs::remove_file(self.path())?;
        }
        st.last_written = None;
        Ok(())
    }

    fn maybe_backup(&self, st: &mut State, current: &str, force: bool) -> Result<(), StoreError> {
        if self.keep == 0 {
            return Ok(());
        }
        let now = SystemTime::now();
        let due = match st.last_backup {
            Some(t) => now.duration_since(t).map(|d| d >= self.backup_every).unwrap_or(true),
            None => true,
        };
        if !(force || due) {
            return Ok(());
        }
        let dir = self.backup_dir();
        fs::create_dir_all(&dir)?;
        restrict_dir(&dir);
        let rev = header(current).map(|h| h.rev).unwrap_or(0);
        let ms = now.duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        // Fixed-width timestamp first, so a name sort is a time sort.
        let name = format!("vault-{ms:015}-r{rev}.json");
        atomic_write(&dir.join(name), current.as_bytes())?;
        st.last_backup = Some(now);
        self.prune(&dir)
    }

    fn prune(&self, dir: &Path) -> Result<(), StoreError> {
        let mut names = self.backups()?;
        while names.len() > self.keep {
            let old = names.remove(0);
            fs::remove_file(dir.join(old))?;
        }
        Ok(())
    }

    /// Backup file names, oldest first.
    pub fn backups(&self) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        match fs::read_dir(self.backup_dir()) {
            Ok(rd) => {
                for e in rd {
                    let n = e?.file_name().to_string_lossy().into_owned();
                    if n.starts_with("vault-") && n.ends_with(".json") {
                        out.push(n);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        out.sort();
        Ok(out)
    }
}

/// Temp file in the same directory, flushed to disk, then renamed over the target.
fn atomic_write(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".{}.{}.tmp", target.file_name().and_then(|n| n.to_str()).unwrap_or("vault"), std::process::id()));
    let res = (|| {
        let mut f = open_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, target)?;
        sync_dir(dir);
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

#[cfg(unix)]
fn open_private(p: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(p)
}

#[cfg(not(unix))]
fn open_private(p: &Path) -> std::io::Result<File> {
    // Windows: the file inherits the per-user ACL of %APPDATA%.
    OpenOptions::new().write(true).create(true).truncate(true).open(p)
}

#[cfg(unix)]
fn restrict_dir(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_p: &Path) {}

#[cfg(unix)]
fn sync_dir(p: &Path) {
    if let Ok(d) = File::open(p) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(id: &str, rev: u64) -> String {
        format!(r#"{{"format":"{VAULT_FORMAT}","v":1,"id":"{id}","rev":{rev},"slots":[],"entries":[]}}"#)
    }

    fn store(keep: usize, every: Duration) -> (tempfile::TempDir, VaultStore) {
        let t = tempfile::tempdir().unwrap();
        let s = VaultStore::with_policy(t.path().join("PEVV"), keep, every);
        (t, s)
    }

    #[test]
    fn reads_nothing_then_what_was_written() {
        let (_t, s) = store(5, Duration::ZERO);
        assert_eq!(s.read().unwrap(), None);
        assert_eq!(s.write(&vault("a", 1), None).unwrap(), 1);
        assert_eq!(s.read().unwrap().unwrap(), vault("a", 1));
    }

    #[test]
    fn write_is_atomic_and_leaves_no_temp_file() {
        let (_t, s) = store(5, Duration::ZERO);
        s.write(&vault("a", 1), None).unwrap();
        s.write(&vault("a", 2), None).unwrap();
        let names: Vec<_> = fs::read_dir(s.dir()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
        assert!(names.contains(&FILE_NAME.to_string()));
    }

    #[test]
    fn a_failed_write_keeps_the_old_file() {
        let (_t, s) = store(5, Duration::ZERO);
        s.write(&vault("a", 3), None).unwrap();
        assert!(s.write("{ nope", None).is_err());
        assert!(matches!(s.write(&vault("a", 2), None), Err(StoreError::RevConflict { current_rev: 3, .. })));
        assert_eq!(s.read().unwrap().unwrap(), vault("a", 3));
    }

    #[test]
    fn rejects_lower_rev_of_same_vault_but_accepts_equal_and_higher() {
        let (_t, s) = store(5, Duration::ZERO);
        s.write(&vault("a", 5), None).unwrap();
        assert!(matches!(s.write(&vault("a", 4), None), Err(StoreError::RevConflict { current_rev: 5, .. })));
        s.write(&vault("a", 5), None).unwrap();
        s.write(&vault("a", 6), None).unwrap();
    }

    #[test]
    fn expected_rev_is_a_floor() {
        let (_t, s) = store(5, Duration::ZERO);
        assert!(matches!(s.write(&vault("a", 2), Some(7)), Err(StoreError::RevConflict { current_rev: 7, .. })));
        assert_eq!(s.read().unwrap(), None);
        s.write(&vault("a", 7), Some(7)).unwrap();
    }

    #[test]
    fn a_different_vault_replaces_the_file_and_is_backed_up() {
        let (_t, s) = store(5, Duration::from_secs(3600));
        s.write(&vault("a", 9), None).unwrap();
        s.write(&vault("b", 1), None).unwrap();
        assert_eq!(s.read().unwrap().unwrap(), vault("b", 1));
        let b = s.backups().unwrap();
        assert_eq!(b.len(), 1);
        assert!(b[0].ends_with("-r9.json"));
    }

    #[test]
    fn refuses_foreign_json() {
        let (_t, s) = store(5, Duration::ZERO);
        assert!(matches!(s.write(r#"{"format":"other","id":"a","rev":1}"#, None), Err(StoreError::Invalid { .. })));
        assert!(matches!(s.write(r#"{"x":1}"#, None), Err(StoreError::Invalid { .. })));
        assert_eq!(s.read().unwrap(), None);
    }

    #[test]
    fn keeps_only_the_last_five_backups() {
        let (_t, s) = store(5, Duration::ZERO);
        for r in 1..=12 {
            s.write(&vault("a", r), None).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        // Each write from rev 2 on backs up the file it replaces, so revs 1..=11 were backed up; 7..=11 remain.
        let b = s.backups().unwrap();
        assert_eq!(b.len(), 5);
        assert!(b[0].ends_with("-r7.json"), "{b:?}");
        assert!(b[4].ends_with("-r11.json"), "{b:?}");
    }

    #[test]
    fn backups_are_rate_limited() {
        let (_t, s) = store(5, Duration::from_secs(3600));
        for r in 1..=6 {
            s.write(&vault("a", r), None).unwrap();
        }
        assert_eq!(s.backups().unwrap().len(), 1);
    }

    #[test]
    fn clear_backs_up_then_removes() {
        let (_t, s) = store(5, Duration::from_secs(3600));
        s.write(&vault("a", 2), None).unwrap();
        s.clear().unwrap();
        assert_eq!(s.read().unwrap(), None);
        assert_eq!(s.backups().unwrap().len(), 1);
        s.clear().unwrap();
        // A fresh vault can start again at any rev.
        s.write(&vault("a", 1), None).unwrap();
    }

    #[test]
    fn recognises_its_own_write() {
        let (_t, s) = store(5, Duration::ZERO);
        s.write(&vault("a", 1), None).unwrap();
        assert!(s.is_own_write(&vault("a", 1)));
        assert!(!s.is_own_write(&vault("a", 2)));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, s) = store(5, Duration::ZERO);
        s.write(&vault("a", 1), None).unwrap();
        s.write(&vault("a", 2), None).unwrap();
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(s.path()), 0o600);
        assert_eq!(mode(s.dir().join(BACKUP_DIR)), 0o700);
        assert_eq!(mode(s.dir().to_path_buf()), 0o700);
        let b = s.backups().unwrap();
        assert_eq!(mode(s.dir().join(BACKUP_DIR).join(&b[0])), 0o600);
    }
}
