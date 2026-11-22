//! Copy a secret, then clear it later only if the clipboard still holds it.
//! On Windows the copy is kept out of clipboard history, the cloud clipboard
//! and clipboard monitors (`ExcludeClipboardContentFromMonitorProcessing`,
//! `CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard`), through arboard.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MIN_CLEAR_SECS: u64 = 5;
pub const MAX_CLEAR_SECS: u64 = 300;
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// What the clearing logic needs from a clipboard.
pub trait Backend: Send + Sync + 'static {
    fn set_secret(&self, text: &str) -> Result<(), String>;
    fn get_text(&self) -> Option<String>;
    fn clear(&self) -> Result<(), String>;
}

/// Seconds to wait before clearing. `0` means never; anything else is kept within a sane range.
pub fn clamp_secs(secs: u64) -> Option<u64> {
    if secs == 0 {
        None
    } else {
        Some(secs.clamp(MIN_CLEAR_SECS, MAX_CLEAR_SECS))
    }
}

/// Clear only when the clipboard still holds exactly what we put there. An empty or
/// unreadable clipboard (a non-text copy now owns it) is left alone.
pub fn should_clear(current: Option<&str>, copied: &str) -> bool {
    current == Some(copied)
}

pub struct SecretClipboard<B: Backend> {
    backend: Arc<B>,
    /// Bumped on every copy: an older timer sees a newer generation and does nothing.
    generation: Arc<AtomicU64>,
}

impl<B: Backend> SecretClipboard<B> {
    pub fn new(backend: B) -> Self {
        Self { backend: Arc::new(backend), generation: Arc::new(AtomicU64::new(0)) }
    }

    /// Copy `text`; `clear_after` is the delay (None = leave it). Returns once the copy is done.
    pub fn copy(&self, text: &str, clear_after: Option<Duration>) -> Result<(), String> {
        if text.len() > MAX_SECRET_BYTES {
            return Err("secret too large".into());
        }
        self.backend.set_secret(text)?;
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(wait) = clear_after {
            let backend = Arc::clone(&self.backend);
            let generation = Arc::clone(&self.generation);
            let copied = text.to_owned();
            std::thread::spawn(move || {
                std::thread::sleep(wait);
                if generation.load(Ordering::SeqCst) != gen {
                    return;
                }
                if should_clear(backend.get_text().as_deref(), &copied) {
                    let _ = backend.clear();
                }
            });
        }
        Ok(())
    }
}

/// The real clipboard.
pub struct System {
    inner: Mutex<Option<arboard::Clipboard>>,
}

impl System {
    pub fn new() -> Self {
        Self { inner: Mutex::new(None) }
    }

    fn with<T>(&self, f: impl FnOnce(&mut arboard::Clipboard) -> Result<T, arboard::Error>) -> Result<T, String> {
        let mut g = self.inner.lock().map_err(|_| "clipboard lock poisoned".to_string())?;
        if g.is_none() {
            *g = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        f(g.as_mut().expect("just set")).map_err(|e| e.to_string())
    }
}

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for System {
    fn set_secret(&self, text: &str) -> Result<(), String> {
        self.with(|c| {
            #[cfg(windows)]
            {
                use arboard::SetExtWindows;
                c.set().exclude_from_history().exclude_from_cloud().text(text.to_owned())
            }
            #[cfg(not(windows))]
            {
                c.set_text(text.to_owned())
            }
        })
    }

    fn get_text(&self) -> Option<String> {
        self.with(|c| c.get_text()).ok()
    }

    fn clear(&self) -> Result<(), String> {
        self.with(|c| c.clear())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        content: Mutex<Option<String>>,
        cleared: AtomicU64,
    }

    impl Backend for Arc<Fake> {
        fn set_secret(&self, text: &str) -> Result<(), String> {
            *self.content.lock().unwrap() = Some(text.to_owned());
            Ok(())
        }
        fn get_text(&self) -> Option<String> {
            self.content.lock().unwrap().clone()
        }
        fn clear(&self) -> Result<(), String> {
            *self.content.lock().unwrap() = None;
            self.cleared.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    const SHORT: Duration = Duration::from_millis(60);
    const LONG: Duration = Duration::from_millis(250);

    #[test]
    fn clamps_the_delay() {
        assert_eq!(clamp_secs(0), None);
        assert_eq!(clamp_secs(1), Some(5));
        assert_eq!(clamp_secs(30), Some(30));
        assert_eq!(clamp_secs(99_999), Some(300));
    }

    #[test]
    fn clears_only_when_unchanged() {
        assert!(should_clear(Some("pw"), "pw"));
        assert!(!should_clear(Some("other"), "pw"));
        assert!(!should_clear(None, "pw"));
    }

    #[test]
    fn clears_after_the_delay() {
        let f = Arc::new(Fake::default());
        let c = SecretClipboard::new(f.clone());
        c.copy("hunter2", Some(SHORT)).unwrap();
        assert_eq!(f.get_text().as_deref(), Some("hunter2"));
        std::thread::sleep(LONG);
        assert_eq!(f.get_text(), None);
        assert_eq!(f.cleared.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn leaves_a_clipboard_the_user_changed() {
        let f = Arc::new(Fake::default());
        let c = SecretClipboard::new(f.clone());
        c.copy("hunter2", Some(SHORT)).unwrap();
        *f.content.lock().unwrap() = Some("something else".into());
        std::thread::sleep(LONG);
        assert_eq!(f.get_text().as_deref(), Some("something else"));
        assert_eq!(f.cleared.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_newer_copy_cancels_the_older_timer() {
        let f = Arc::new(Fake::default());
        let c = SecretClipboard::new(f.clone());
        c.copy("same", Some(SHORT)).unwrap();
        // Same text copied again later: the first timer must not clear it early.
        std::thread::sleep(Duration::from_millis(30));
        c.copy("same", Some(Duration::from_millis(400))).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(f.get_text().as_deref(), Some("same"));
    }

    #[test]
    fn never_clears_when_no_delay() {
        let f = Arc::new(Fake::default());
        let c = SecretClipboard::new(f.clone());
        c.copy("x", None).unwrap();
        std::thread::sleep(LONG);
        assert_eq!(f.get_text().as_deref(), Some("x"));
    }

    #[test]
    fn refuses_a_huge_secret() {
        let f = Arc::new(Fake::default());
        let c = SecretClipboard::new(f.clone());
        assert!(c.copy(&"a".repeat(MAX_SECRET_BYTES + 1), None).is_err());
        assert_eq!(f.get_text(), None);
    }
}
