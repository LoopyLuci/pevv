//! Sealing the 64-byte node seed at rest (docs/TRANSPORT.md section 4.3).
//!
//! The seed is **not** held in hardware. Transferd's own `KeyStore` is a RAM store and neither
//! Android Keystore, TPM nor Secure Enclave can do ML-DSA. What PEVV does instead is have the
//! OS wrap the seed at rest: [`DpapiSealer`] on Windows (user scope), a Keystore callback on
//! Android (implemented in Kotlin, see `SeedSealer` in the UniFFI interface). Where no OS
//! facility is available, [`FileSealer`] stores the seed in an owner-only file and
//! says so through [`Protection::FilePermissionsOnly`], so the UI can tell the user.
//!
//! TODO(linux-secret-service): Secret Service (GNOME Keyring / KWallet) through the `keyring`
//! crate is planned (doc 4.3) and not implemented here; Linux uses [`FileSealer`] meanwhile.

use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// How strongly a sealer protects the stored seed. Honest labels only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Wrapped by an OS facility bound to the user (DPAPI, Android Keystore, Secret Service).
    OsKeystore,
    /// Stored as-is in an owner-only file. Protects against other users, not against code
    /// running as this user or offline disk access.
    FilePermissionsOnly,
}

/// Wraps and unwraps the seed. Implemented per platform.
pub trait SeedSealer: Send + Sync {
    /// Wrap the seed for storage.
    fn seal(&self, seed: &[u8; 64]) -> Result<Vec<u8>>;
    /// Unwrap a stored seed.
    fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<[u8; 64]>>;
    /// How strong the wrapping is.
    fn protection(&self) -> Protection;
}

/// Owner-only file, no wrapping. See the module note.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileSealer;

const FILE_MAGIC: &[u8; 4] = b"PSF1";

impl SeedSealer for FileSealer {
    fn seal(&self, seed: &[u8; 64]) -> Result<Vec<u8>> {
        let mut v = FILE_MAGIC.to_vec();
        v.extend_from_slice(seed);
        Ok(v)
    }
    fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
        if sealed.len() != 68 || &sealed[..4] != FILE_MAGIC {
            return Err(Error::Seal("not a plain seed file".into()));
        }
        let mut out = Zeroizing::new([0u8; 64]);
        out.copy_from_slice(&sealed[4..]);
        Ok(out)
    }
    fn protection(&self) -> Protection {
        Protection::FilePermissionsOnly
    }
}

/// Windows DPAPI, current-user scope (`CryptProtectData`).
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct DpapiSealer;

#[cfg(windows)]
mod dpapi {
    use super::*;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    // Not a secret: a domain separator so another DPAPI user of this account cannot unwrap
    // the blob by accident.
    const ENTROPY: &[u8] = b"pevv-transport-seed-v1";

    fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: b.len() as u32,
            pbData: b.as_ptr() as *mut u8,
        }
    }

    fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        // SAFETY: on success DPAPI returns a LocalAlloc'd buffer of `cbData` bytes, which we
        // copy and then free exactly once.
        unsafe {
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
            LocalFree(out.pbData as _);
            Zeroizing::new(v)
        }
    }

    impl SeedSealer for DpapiSealer {
        fn seal(&self, seed: &[u8; 64]) -> Result<Vec<u8>> {
            let input = blob(seed);
            let entropy = blob(ENTROPY);
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // SAFETY: all pointers refer to live locals; `out` is filled by the API.
            let ok = unsafe {
                CryptProtectData(
                    &input,
                    std::ptr::null(),
                    &entropy,
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err(Error::Seal("DPAPI refused to protect the seed".into()));
            }
            Ok(take(out).to_vec())
        }

        fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
            let input = blob(sealed);
            let entropy = blob(ENTROPY);
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // SAFETY: as above.
            let ok = unsafe {
                CryptUnprotectData(
                    &input,
                    std::ptr::null_mut(),
                    &entropy,
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err(Error::Seal(
                    "DPAPI could not unwrap the seed (another user or machine?)".into(),
                ));
            }
            let plain = take(out);
            if plain.len() != 64 {
                return Err(Error::Seal("unwrapped seed has the wrong length".into()));
            }
            let mut seed = Zeroizing::new([0u8; 64]);
            seed.copy_from_slice(&plain);
            Ok(seed)
        }

        fn protection(&self) -> Protection {
            Protection::OsKeystore
        }
    }
}

/// The best sealer this build has for the host OS: DPAPI on Windows, otherwise the owner-only
/// file. Android supplies its own through the FFI.
pub fn default_sealer() -> Box<dyn SeedSealer> {
    #[cfg(windows)]
    {
        Box::new(DpapiSealer)
    }
    #[cfg(not(windows))]
    {
        Box::new(FileSealer)
    }
}

/// The sealed seed on disk.
pub struct SeedFile {
    path: PathBuf,
}

impl SeedFile {
    /// A seed file at `path` (nothing is read or created yet).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Whether a sealed seed exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Read and unwrap the seed, or create a new random one and store it wrapped. A seed that
    /// exists but cannot be unwrapped is an **error**, never silently replaced: replacing it
    /// changes the node id and needs a re-pair, which the user must choose ([`Self::create_new`]).
    pub fn load_or_create(&self, sealer: &dyn SeedSealer) -> Result<Zeroizing<[u8; 64]>> {
        match std::fs::read(&self.path) {
            Ok(sealed) => sealer.unseal(&sealed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.create_new(sealer),
            Err(e) => Err(e.into()),
        }
    }

    /// Generate a new seed and overwrite the file (new identity: re-pair afterwards).
    pub fn create_new(&self, sealer: &dyn SeedSealer) -> Result<Zeroizing<[u8; 64]>> {
        let mut seed = Zeroizing::new([0u8; 64]);
        rand::rngs::OsRng.fill_bytes(&mut seed[..]);
        write_private(&self.path, &sealer.seal(&seed)?)?;
        Ok(seed)
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_sealer_round_trips_and_says_what_it_is() {
        let s = FileSealer;
        let seed = [7u8; 64];
        let sealed = s.seal(&seed).unwrap();
        assert_eq!(&s.unseal(&sealed).unwrap()[..], &seed[..]);
        assert_eq!(s.protection(), Protection::FilePermissionsOnly);
        assert!(s.unseal(b"junk").is_err());
    }

    #[test]
    fn seed_file_is_created_once_then_reloaded_and_never_silently_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let f = SeedFile::new(dir.path().join("seed.sealed"));
        let sealer = default_sealer();
        let a = f.load_or_create(&*sealer).unwrap();
        let b = f.load_or_create(&*sealer).unwrap();
        assert_eq!(&a[..], &b[..]);
        // The file on disk is not the raw seed.
        let on_disk = std::fs::read(dir.path().join("seed.sealed")).unwrap();
        assert!(
            !on_disk.windows(64).any(|w| w == &a[..])
                || sealer.protection() == Protection::FilePermissionsOnly
        );
        // Corrupt it: loading is an error, not a fresh identity.
        std::fs::write(dir.path().join("seed.sealed"), b"corrupt").unwrap();
        assert!(f.load_or_create(&*sealer).is_err());
        let c = f.create_new(&*sealer).unwrap();
        assert_ne!(&a[..], &c[..]);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_wraps_the_seed_for_real() {
        let s = DpapiSealer;
        let seed = [42u8; 64];
        let sealed = s.seal(&seed).unwrap();
        assert!(!sealed.windows(64).any(|w| w == seed));
        assert_eq!(&s.unseal(&sealed).unwrap()[..], &seed[..]);
        let mut bad = sealed.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(s.unseal(&bad).is_err());
        assert_eq!(s.protection(), Protection::OsKeystore);
    }
}
