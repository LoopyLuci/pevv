//! `pevv-native-host`: what a browser starts when the PEVV extension calls
//! `chrome.runtime.connectNative("com.luciverse.pevv")`.
//!
//! It is a relay and nothing more: it holds no secret and decides nothing. Each message from the
//! browser (stdin, 4-byte length + JSON) goes to the running PEVV desktop app over a private local
//! channel together with the extension origin the browser passed as argv[1]; the app's reply
//! goes back to the browser (stdout). The app authenticates and answers. If the app is not
//! running the reply is `app-not-running` (and `unlock-request` / `launch` start it first).
//!
//! Never print to stdout except framed replies: stdout is the browser's channel.

#[path = "../link_ipc.rs"]
mod link_ipc;
#[path = "../link_proto.rs"]
mod link_proto;

use link_proto::{allowed_extension_ids, origin_allowed, read_frame, write_frame, PROTO_VERSION};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

fn error(code: &str) -> Value {
    json!({ "v": PROTO_VERSION, "type": "error", "code": code })
}

struct Host<C: Read + Write> {
    origin: String,
    ids: Vec<String>,
    conn: Option<C>,
    connect: Box<dyn FnMut() -> io::Result<C>>,
    /// Start the app; true if a start was attempted.
    launch: Box<dyn FnMut() -> bool>,
    /// How long to wait for a freshly launched app to open its channel.
    wait: Duration,
}

impl<C: Read + Write> Host<C> {
    fn open(&mut self, may_launch: bool) -> Result<(), &'static str> {
        if self.conn.is_some() {
            return Ok(());
        }
        match (self.connect)() {
            Ok(c) => {
                self.conn = Some(c);
                return Ok(());
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err("app-unreachable"),
            Err(_) => {}
        }
        if !may_launch || !(self.launch)() {
            return Err("app-not-running");
        }
        let started = Instant::now();
        loop {
            if let Ok(c) = (self.connect)() {
                self.conn = Some(c);
                return Ok(());
            }
            if started.elapsed() >= self.wait {
                return Err("app-not-running");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn exchange(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        let c = self.conn.as_mut().ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        write_frame(c, frame)?;
        read_frame(c)?.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
    }

    fn handle(&mut self, raw: &[u8]) -> Value {
        let Ok(msg) = serde_json::from_slice::<Value>(raw) else { return error("bad-request") };
        let Some(kind) = msg.get("type").and_then(Value::as_str).map(str::to_owned) else { return error("bad-request") };
        // The browser already enforced `allowed_origins`; refusing here too costs nothing.
        if origin_allowed(&self.origin, &self.ids).is_none() {
            return error("origin-denied");
        }
        if kind == "launch" {
            return match self.open(true) {
                Ok(()) => json!({ "v": PROTO_VERSION, "type": "launch", "ok": true }),
                Err(code) => error(code),
            };
        }
        // Only an explicit unlock (or launch) request starts the app; status checks never do.
        if let Err(code) = self.open(kind == "unlock-request") {
            return error(code);
        }
        let frame = serde_json::to_vec(&json!({ "origin": self.origin, "msg": msg })).unwrap_or_default();
        let mut result = self.exchange(&frame);
        if matches!(&result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe) {
            // The app restarted since the last message: nothing was delivered, so one fresh try is safe.
            self.conn = None;
            if self.open(false).is_ok() {
                result = self.exchange(&frame);
            }
        }
        match result.ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
            Some(v) => v,
            None => {
                self.conn = None;
                error("app-connection-lost")
            }
        }
    }
}

/// The app next to this binary (`pevv-desktop`), started detached so it outlives the host.
fn launch_app() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let Some(dir) = exe.parent() else { return false };
    let app = dir.join(if cfg!(windows) { "pevv-desktop.exe" } else { "pevv-desktop" });
    if !app.exists() {
        return false;
    }
    let mut cmd = std::process::Command::new(app);
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    cmd.spawn().is_ok()
}

fn main() {
    // Chrome passes `chrome-extension://<id>/` (and on Windows `--parent-window=…`) as arguments.
    let origin = std::env::args().nth(1).unwrap_or_default();
    let mut host: Host<link_ipc::Conn> = Host {
        origin,
        ids: allowed_extension_ids(),
        conn: None,
        connect: Box::new(|| link_ipc::default_endpoint().and_then(|e| link_ipc::connect(&e))),
        launch: Box::new(launch_app),
        wait: Duration::from_secs(10),
    };
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    while let Ok(Some(raw)) = read_frame(&mut stdin) {
        let reply = host.handle(&raw);
        let bytes = serde_json::to_vec(&reply).unwrap_or_default();
        // A reply over 1 MB cannot be sent; tell the browser rather than hang it.
        let sent = write_frame(&mut stdout, &bytes).or_else(|_| write_frame(&mut stdout, &serde_json::to_vec(&error("reply-too-large")).unwrap_or_default()));
        if sent.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    const ID: &str = "dolmkecfaekonkkgpjpamipjleindand";

    /// A pretend app: answers each frame with the next canned reply, remembers what it got.
    struct FakeConn {
        replies: Rc<std::cell::RefCell<VecDeque<Vec<u8>>>>,
        got: Rc<std::cell::RefCell<Vec<Value>>>,
        out: Vec<u8>,
        pending: io::Cursor<Vec<u8>>,
    }

    impl Write for FakeConn {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.out.extend_from_slice(b);
            // Frame complete when the length prefix is satisfied.
            if self.out.len() >= 4 {
                let n = u32::from_le_bytes(self.out[..4].try_into().unwrap()) as usize;
                if self.out.len() == 4 + n {
                    self.got.borrow_mut().push(serde_json::from_slice(&self.out[4..]).unwrap());
                    self.out.clear();
                    let reply = self.replies.borrow_mut().pop_front().unwrap_or_default();
                    let mut framed = Vec::new();
                    write_frame(&mut framed, &reply).unwrap();
                    self.pending = io::Cursor::new(framed);
                }
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for FakeConn {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.pending.read(b)
        }
    }

    type Shared<T> = Rc<std::cell::RefCell<T>>;

    #[allow(clippy::type_complexity)]
    fn host(app_up: bool, origin: &str) -> (Host<FakeConn>, Shared<Vec<Value>>, Shared<VecDeque<Vec<u8>>>, Rc<Cell<u32>>) {
        let got: Shared<Vec<Value>> = Default::default();
        let replies: Shared<VecDeque<Vec<u8>>> = Default::default();
        let launches = Rc::new(Cell::new(0));
        let up = Rc::new(Cell::new(app_up));
        let (g, r, u) = (got.clone(), replies.clone(), up.clone());
        let l = launches.clone();
        let h = Host {
            origin: origin.to_string(),
            ids: vec![ID.to_string()],
            conn: None,
            connect: Box::new(move || {
                if u.get() {
                    Ok(FakeConn { replies: r.clone(), got: g.clone(), out: vec![], pending: io::Cursor::new(vec![]) })
                } else {
                    Err(io::ErrorKind::NotFound.into())
                }
            }),
            launch: Box::new(move || {
                l.set(l.get() + 1);
                up.set(true);
                true
            }),
            wait: Duration::from_millis(0),
        };
        (h, got, replies, launches)
    }

    fn origin() -> String {
        format!("chrome-extension://{ID}/")
    }

    #[test]
    fn relays_with_the_origin_and_returns_the_apps_reply_verbatim() {
        let (mut h, got, replies, launches) = host(true, &origin());
        replies.borrow_mut().push_back(br#"{"v":1,"n":3,"type":"status","body":"{}","mac":"ab"}"#.to_vec());
        let r = h.handle(br#"{"v":1,"n":3,"type":"status","body":"{}","mac":"zz"}"#);
        assert_eq!(r["mac"], "ab");
        assert_eq!(got.borrow()[0]["origin"], origin());
        assert_eq!(got.borrow()[0]["msg"]["type"], "status");
        assert_eq!(launches.get(), 0);
    }

    #[test]
    fn app_not_running_is_reported_and_status_never_launches() {
        let (mut h, _, _, launches) = host(false, &origin());
        assert_eq!(h.handle(br#"{"v":1,"type":"status"}"#)["code"], "app-not-running");
        assert_eq!(h.handle(br#"{"v":1,"type":"match"}"#)["code"], "app-not-running");
        assert_eq!(launches.get(), 0);
    }

    #[test]
    fn unlock_request_and_launch_start_the_app() {
        let (mut h, got, replies, launches) = host(false, &origin());
        replies.borrow_mut().push_back(br#"{"v":1,"type":"unlock-request"}"#.to_vec());
        assert_eq!(h.handle(br#"{"v":1,"type":"unlock-request"}"#)["type"], "unlock-request");
        assert_eq!(launches.get(), 1);
        assert_eq!(got.borrow().len(), 1);
        let (mut h, _, _, launches) = host(false, &origin());
        assert_eq!(h.handle(br#"{"v":1,"type":"launch"}"#)["ok"], true);
        assert_eq!(launches.get(), 1);
    }

    #[test]
    fn a_wrong_origin_or_garbage_never_reaches_the_app() {
        let (mut h, got, _, launches) = host(true, "chrome-extension://pppppppppppppppppppppppppppppppp/");
        assert_eq!(h.handle(br#"{"v":1,"type":"status"}"#)["code"], "origin-denied");
        assert_eq!(h.handle(br#"{"v":1,"type":"launch"}"#)["code"], "origin-denied");
        let (mut h2, got2, _, _) = host(true, "");
        assert_eq!(h2.handle(br#"{"v":1,"type":"status"}"#)["code"], "origin-denied");
        let (mut h3, got3, _, _) = host(true, &origin());
        assert_eq!(h3.handle(b"nope")["code"], "bad-request");
        assert_eq!(h3.handle(br#"{"v":1}"#)["code"], "bad-request");
        assert!(got.borrow().is_empty() && got2.borrow().is_empty() && got3.borrow().is_empty());
        assert_eq!(launches.get(), 0);
    }

    #[test]
    fn a_dead_connection_becomes_connection_lost_and_reconnects_next_time() {
        let (mut h, _, replies, _) = host(true, &origin());
        // The fake app answers with an empty frame body: not JSON.
        replies.borrow_mut().push_back(vec![]);
        assert_eq!(h.handle(br#"{"v":1,"type":"status"}"#)["code"], "app-connection-lost");
        assert!(h.conn.is_none());
        replies.borrow_mut().push_back(br#"{"ok":1}"#.to_vec());
        assert_eq!(h.handle(br#"{"v":1,"type":"status"}"#)["ok"], 1);
    }
}
