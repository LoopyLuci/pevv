//! Local IPC between `pevv-native-host` and the desktop app.
//!
//! Windows: a named pipe whose DACL grants access to the current user's SID only, that refuses
//! remote clients, and whose first instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE (so a
//! program that squatted the name first makes the app fail loudly instead of being talked to).
//! The pipe name contains the user's SID, so two accounts on one machine never share a name.
//!
//! Linux: a Unix socket under `$XDG_RUNTIME_DIR` (a 0700 directory, the socket 0600), and every
//! accepted connection's peer uid (SO_PEERCRED) must be ours.
//!
//! Shared by the app (server side) and the host (client side), hence the blanket `allow`.
#![allow(dead_code)]

use std::io::{self, Read, Write};

/// A connected, byte-stream conversation.
pub struct Conn(imp::Stream);

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

pub use imp::{default_endpoint, Listener};

impl Conn {
    /// The process id of the program on the other end, from the OS (not from anything it sent).
    /// Only meaningful on the server side of the connection.
    pub fn peer_pid(&self) -> io::Result<u32> {
        imp::peer_pid(&self.0)
    }
}

/// Connect to the app. `endpoint` is a pipe name (Windows) or a socket path (Linux).
pub fn connect(endpoint: &str) -> io::Result<Conn> {
    imp::connect(endpoint).map(Conn)
}

impl Listener {
    /// Wait for the next client. Clients that fail the peer check are dropped, not returned.
    pub fn accept(&mut self) -> io::Result<Conn> {
        self.accept_stream().map(Conn)
    }
}

#[cfg(windows)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::io::FromRawHandle;
    use std::time::{Duration, Instant};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, INVALID_HANDLE_VALUE};
    use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub type Stream = File;

    const ERROR_PIPE_BUSY: i32 = 231;
    const ERROR_FILE_NOT_FOUND: i32 = 2;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn werr(e: windows::core::Error) -> io::Error {
        io::Error::from_raw_os_error(e.code().0 & 0xFFFF)
    }

    /// The current user's SID as `S-1-5-21-…`.
    pub fn current_sid() -> io::Result<String> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(werr)?;
            let mut len = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
            // u64 elements so the TOKEN_USER we read back is aligned.
            let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let res = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len);
            let out = res.map_err(werr).and_then(|()| {
                let user = &*(buf.as_ptr() as *const TOKEN_USER);
                let mut s = PWSTR::null();
                ConvertSidToStringSidW(user.User.Sid, &mut s).map_err(werr)?;
                let text = s.to_string().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
                let _ = LocalFree(Some(HLOCAL(s.0.cast())));
                text
            });
            let _ = CloseHandle(token);
            out
        }
    }

    pub fn default_endpoint() -> io::Result<String> {
        Ok(format!(r"\\.\pipe\pevv-link-{}", current_sid()?))
    }

    /// The client's process id (server end of the pipe).
    pub fn peer_pid(s: &Stream) -> io::Result<u32> {
        use std::os::windows::io::AsRawHandle;
        let mut pid = 0u32;
        // SAFETY: the handle is a live pipe handle owned by `s`; `pid` is valid for the call.
        unsafe { GetNamedPipeClientProcessId(HANDLE(s.as_raw_handle()), &mut pid) }.map_err(werr)?;
        Ok(pid)
    }

    pub struct Listener {
        name: Vec<u16>,
        sddl: Vec<u16>,
        next: Option<HANDLE>,
        first: bool,
    }

    // The raw handle is only ever used by the thread that owns the listener.
    unsafe impl Send for Listener {}

    impl Listener {
        pub fn bind(endpoint: &str) -> io::Result<Self> {
            let sddl = wide(&format!("D:P(A;;GA;;;{})", current_sid()?));
            let mut l = Self { name: wide(endpoint), sddl, next: None, first: true };
            l.next = Some(l.create()?);
            Ok(l)
        }

        fn create(&mut self) -> io::Result<HANDLE> {
            unsafe {
                let mut sd = PSECURITY_DESCRIPTOR::default();
                ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(self.sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None).map_err(werr)?;
                let sa = SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: sd.0,
                    bInheritHandle: false.into(),
                };
                let mut open = PIPE_ACCESS_DUPLEX;
                if self.first {
                    open |= FILE_FLAG_FIRST_PIPE_INSTANCE;
                }
                let h = CreateNamedPipeW(
                    PCWSTR(self.name.as_ptr()),
                    open,
                    PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    64 * 1024,
                    64 * 1024,
                    0,
                    Some(&sa),
                );
                let _ = LocalFree(Some(HLOCAL(sd.0)));
                if h == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                self.first = false;
                Ok(h)
            }
        }

        pub(super) fn accept_stream(&mut self) -> io::Result<Stream> {
            let h = match self.next.take() {
                Some(h) => h,
                None => self.create()?,
            };
            let connected = unsafe { ConnectNamedPipe(h, None) };
            if let Err(e) = connected {
                if e.code() != ERROR_PIPE_CONNECTED.to_hresult() {
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                    return Err(werr(e));
                }
            }
            // A new instance exists before the connected one is handed out: no gap where a client finds no pipe.
            self.next = Some(self.create()?);
            Ok(unsafe { File::from_raw_handle(h.0) })
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            if let Some(h) = self.next.take() {
                unsafe {
                    let _ = CloseHandle(h);
                }
            }
        }
    }

    pub fn connect(endpoint: &str) -> io::Result<Stream> {
        let started = Instant::now();
        loop {
            match OpenOptions::new().read(true).write(true).open(endpoint) {
                Ok(f) => return Ok(f),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && started.elapsed() < Duration::from_secs(2) => {
                    std::thread::sleep(Duration::from_millis(25))
                }
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => return Err(io::Error::new(io::ErrorKind::NotFound, "the PEVV app is not running")),
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    pub type Stream = UnixStream;

    pub fn default_endpoint() -> io::Result<String> {
        let dir = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|d| !d.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "XDG_RUNTIME_DIR is not set"))?;
        Ok(PathBuf::from(dir).join("pevv-link").join("native.sock").to_string_lossy().into_owned())
    }

    /// The uid on the other end of the socket, from the kernel (SO_PEERCRED), not from anything the peer says.
    pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for the call and sized as getsockopt expects.
        let rc = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    /// The pid on the other end of the socket, from the kernel (SO_PEERCRED).
    pub fn peer_pid(s: &UnixStream) -> io::Result<u32> {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for the call and sized as getsockopt expects.
        let rc = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.pid as u32)
    }

    pub struct Listener {
        inner: UnixListener,
    }

    impl Listener {
        pub fn bind(endpoint: &str) -> io::Result<Self> {
            let path = Path::new(endpoint);
            if let Some(dir) = path.parent() {
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
            // A socket left by a crash is replaced; one that still answers belongs to a running app.
            if path.exists() {
                if UnixStream::connect(path).is_ok() {
                    return Err(io::Error::new(io::ErrorKind::AddrInUse, "another PEVV app is listening"));
                }
                std::fs::remove_file(path)?;
            }
            let inner = UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self { inner })
        }

        pub(super) fn accept_stream(&mut self) -> io::Result<Stream> {
            loop {
                let (s, _) = self.inner.accept()?;
                // SAFETY: geteuid has no preconditions.
                let me = unsafe { libc::geteuid() };
                match peer_uid(&s) {
                    Ok(uid) if uid == me => return Ok(s),
                    _ => drop(s),
                }
            }
        }
    }

    pub fn connect(endpoint: &str) -> io::Result<Stream> {
        let s = UnixStream::connect(endpoint).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => io::Error::new(io::ErrorKind::NotFound, "the PEVV app is not running"),
            _ => e,
        })?;
        // SAFETY: geteuid has no preconditions.
        if peer_uid(&s)? != unsafe { libc::geteuid() } {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the socket belongs to another user"));
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link_proto::{read_frame, write_frame};

    fn endpoint(tag: &str) -> String {
        #[cfg(windows)]
        {
            format!(r"\\.\pipe\pevv-link-test-{tag}-{}", std::process::id())
        }
        #[cfg(unix)]
        {
            let dir = std::env::temp_dir().join(format!("pevv-link-test-{tag}-{}", std::process::id()));
            dir.join("t.sock").to_string_lossy().into_owned()
        }
    }

    #[test]
    fn echo_round_trip_over_the_real_channel() {
        let ep = endpoint("echo");
        let mut l = Listener::bind(&ep).unwrap();
        let t = std::thread::spawn(move || {
            let mut c = l.accept().unwrap();
            while let Some(f) = read_frame(&mut c).unwrap() {
                write_frame(&mut c, &f).unwrap();
            }
        });
        let mut c = connect(&ep).unwrap();
        write_frame(&mut c, b"hello").unwrap();
        assert_eq!(read_frame(&mut c).unwrap().unwrap(), b"hello");
        write_frame(&mut c, b"again").unwrap();
        assert_eq!(read_frame(&mut c).unwrap().unwrap(), b"again");
        drop(c);
        t.join().unwrap();
    }

    #[test]
    fn the_server_learns_the_clients_process_id_from_the_os() {
        let ep = endpoint("pid");
        let mut l = Listener::bind(&ep).unwrap();
        let t = std::thread::spawn(move || l.accept().unwrap().peer_pid().unwrap());
        let c = connect(&ep).unwrap();
        // The client is this very process.
        assert_eq!(t.join().unwrap(), std::process::id());
        drop(c);
    }

    #[test]
    fn connecting_to_nothing_says_not_running() {
        let e = connect(&endpoint("nobody")).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn the_name_cannot_be_squatted_twice() {
        let ep = endpoint("twice");
        let _first = Listener::bind(&ep).unwrap();
        assert!(Listener::bind(&ep).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pipe_name_carries_the_user_sid_and_the_dacl_is_owner_only() {
        let name = default_endpoint().unwrap();
        assert!(name.starts_with(r"\\.\pipe\pevv-link-S-1-"), "{name}");
        // The SDDL the listener builds grants to this SID alone (protected, no inherited ACEs).
        let sid = imp::current_sid().unwrap();
        assert_eq!(format!("D:P(A;;GA;;;{sid})").matches("(A;").count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn socket_is_private_and_peer_uid_is_ours() {
        use std::os::unix::fs::PermissionsExt;
        let ep = endpoint("perm");
        let mut l = Listener::bind(&ep).unwrap();
        let mode = std::fs::metadata(&ep).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(std::path::Path::new(&ep).parent().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let t = std::thread::spawn(move || l.accept().map(|_| ()));
        let c = connect(&ep).unwrap();
        assert_eq!(imp::peer_uid(&c.0).unwrap(), unsafe { libc::geteuid() });
        drop(c);
        t.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(std::path::Path::new(&ep).parent().unwrap());
    }
}
