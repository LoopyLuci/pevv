//! The app's side of the browser-extension link: who may talk to it and what they may ask.
//!
//! Tauri-free on purpose (the window, the lock state and the vault UI are behind `Ui`) so the
//! whole policy runs under unit tests. The Rust side never holds decrypted logins: `match`,
//! `fill` and `save-offer` are forwarded to the vault UI, which holds the unlocked vault and
//! applies the exact-origin rule itself. What is enforced here, before anything is forwarded:
//!
//! * the browser's `allowed_origins` is not trusted alone: the extension id from argv[1] must be
//!   in `extension-ids.json`;
//! * pairing needs a person's approval in the app, and shows a fingerprint of the secret;
//! * after pairing every request carries a counter and an HMAC-SHA256 under the shared secret;
//!   the counter must be higher than the last accepted one (replays are refused, and the new
//!   counter is on disk before the request is acted on);
//! * `match` / `fill` are refused while locked; origins must be a bare `http(s)://host[:port]`.

use crate::link_proto::{fingerprint, origin_allowed, sign, verify, Dir, PROTO_VERSION};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// What the app lends the link: its window, its lock state and the unlocked vault UI.
pub trait Ui: Send + Sync {
    fn show_window(&self);
    fn lock_now(&self);
    fn unlocked(&self) -> bool;
    /// Ask the person to approve a pairing; blocks until they answer (or it times out = false).
    fn confirm_pair(&self, ext_id: &str, fingerprint: &str) -> bool;
    /// Hand `match` / `fill` / `save-offer` to the vault UI. `Err` carries a short error code.
    fn ask_vault(&self, kind: &str, body: &Value) -> Result<Value, String>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pairing {
    /// Extension id.
    pub ext: String,
    /// Shared 256-bit secret, base64.
    pub secret: String,
    /// Highest request counter accepted so far.
    #[serde(default)]
    pub n: u64,
    /// Unix ms of the approval.
    #[serde(default)]
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkFile {
    /// Browser registration is on (host manifests written). Default on.
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub paired: Vec<Pairing>,
}

fn yes() -> bool {
    true
}

impl Default for LinkFile {
    fn default() -> Self {
        Self { enabled: true, paired: Vec::new() }
    }
}

/// `native-link.json` in the app data folder. Plain text, owner-only (0600) where the OS has modes:
/// it holds the shared secrets, like a browser profile holds its own.
pub struct LinkStore {
    path: Option<PathBuf>,
    pub file: LinkFile,
}

impl LinkStore {
    pub fn open(dir: &Path) -> Self {
        let path = dir.join("native-link.json");
        let file = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        Self { path: Some(path), file }
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self { path: None, file: LinkFile::default() }
    }

    pub fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.file).map_err(io::Error::other)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)
    }

    fn find_mut(&mut self, ext: &str) -> Option<&mut Pairing> {
        self.file.paired.iter_mut().find(|p| p.ext == ext)
    }
}

/// `http(s)://host[:port]` and nothing else (no path, query, credentials), in canonical form.
pub fn web_origin(s: &str) -> Option<String> {
    let u = url::Url::parse(s).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    u.host()?;
    let o = u.origin().ascii_serialization();
    (o == s).then_some(o)
}

fn err(code: &str) -> Value {
    json!({ "v": PROTO_VERSION, "type": "error", "code": code })
}

#[derive(Deserialize)]
struct Request {
    origin: String,
    msg: Value,
}

#[derive(Deserialize)]
struct Envelope {
    n: u64,
    #[serde(rename = "type")]
    kind: String,
    body: String,
    mac: String,
}

pub struct Link {
    store: Mutex<LinkStore>,
    ui: Arc<dyn Ui>,
    ids: Vec<String>,
    pairing: AtomicBool,
    /// The `pevv` command-line tool's side (`cli_core`); frames with `"client": "cli"` go there.
    cli: OnceLock<Arc<crate::cli_core::Cli>>,
}

struct Busy<'a>(&'a AtomicBool);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Link {
    pub fn new(store: LinkStore, ui: Arc<dyn Ui>, ids: Vec<String>) -> Arc<Self> {
        Arc::new(Self { store: Mutex::new(store), ui, ids, pairing: AtomicBool::new(false), cli: OnceLock::new() })
    }

    pub fn enabled(&self) -> bool {
        self.store.lock().map(|s| s.file.enabled).unwrap_or(true)
    }

    pub fn set_enabled(&self, on: bool) -> io::Result<()> {
        let mut s = self.store.lock().map_err(|_| io::Error::other("poisoned"))?;
        s.file.enabled = on;
        s.save()
    }

    /// `(extension id, approved at)` for each pairing.
    pub fn paired(&self) -> Vec<(String, u64)> {
        self.store.lock().map(|s| s.file.paired.iter().map(|p| (p.ext.clone(), p.at)).collect()).unwrap_or_default()
    }

    pub fn unpair(&self, ext: &str) -> io::Result<()> {
        let mut s = self.store.lock().map_err(|_| io::Error::other("poisoned"))?;
        s.file.paired.retain(|p| p.ext != ext);
        s.save()
    }

    pub fn set_cli(&self, cli: Arc<crate::cli_core::Cli>) {
        let _ = self.cli.set(cli);
    }

    /// One connection: a request in, a reply out, until the peer hangs up.
    #[allow(dead_code)]
    pub fn serve<S: Read + Write>(&self, conn: &mut S) -> io::Result<()> {
        self.serve_peer(conn, || None)
    }

    /// Like `serve`. `resolve` names the program on the other end (OS-reported); it runs at most
    /// once, and only when a `pevv` frame arrives, so browser-host connections never pay for it.
    pub fn serve_peer<S: Read + Write>(&self, conn: &mut S, mut resolve: impl FnMut() -> Option<crate::cli_core::Peer>) -> io::Result<()> {
        let mut peer: Option<Option<crate::cli_core::Peer>> = None;
        while let Some(frame) = crate::link_proto::read_frame(conn)? {
            let reply = match serde_json::from_slice::<Value>(&frame) {
                Ok(v) if v.get("client").and_then(Value::as_str) == Some(crate::cli_proto::CLIENT_KIND) => {
                    let p = peer.get_or_insert_with(&mut resolve).as_ref();
                    match self.cli.get() {
                        Some(cli) => cli.handle(p, &v),
                        None => json!({ "v": PROTO_VERSION, "ok": false, "error": "bad-request" }),
                    }
                }
                _ => self.handle(&frame),
            };
            let bytes = serde_json::to_vec(&reply).map_err(io::Error::other)?;
            crate::link_proto::write_frame(conn, &bytes)?;
        }
        Ok(())
    }

    pub fn handle(&self, frame: &[u8]) -> Value {
        let Ok(req) = serde_json::from_slice::<Request>(frame) else { return err("bad-request") };
        if !self.enabled() {
            return err("disabled");
        }
        let Some(ext) = origin_allowed(&req.origin, &self.ids) else { return err("origin-denied") };
        let Some(msg) = req.msg.as_object() else { return err("bad-request") };
        if msg.get("v").and_then(Value::as_u64) != Some(PROTO_VERSION) {
            return err("unsupported-version");
        }
        match msg.get("type").and_then(Value::as_str) {
            Some("pair") => self.pair(&ext, &req.msg),
            Some(_) => self.authed(&ext, &req.msg),
            None => err("bad-request"),
        }
    }

    fn pair(&self, ext: &str, msg: &Value) -> Value {
        let Some(secret) = msg.get("secret").and_then(Value::as_str).and_then(|s| B64.decode(s).ok()).filter(|s| s.len() == 32) else {
            return err("bad-request");
        };
        if self.pairing.swap(true, Ordering::SeqCst) {
            return err("busy");
        }
        let _busy = Busy(&self.pairing);
        self.ui.show_window();
        if !self.ui.confirm_pair(ext, &fingerprint(&secret)) {
            return err("pair-denied");
        }
        {
            let Ok(mut st) = self.store.lock() else { return err("internal") };
            st.file.paired.retain(|p| p.ext != ext);
            st.file.paired.push(Pairing { ext: ext.to_string(), secret: B64.encode(&secret), n: 0, at: now_ms() });
            if st.save().is_err() {
                st.file.paired.retain(|p| p.ext != ext);
                return err("internal");
            }
        }
        json!({ "v": PROTO_VERSION, "type": "pair-ok", "mac": sign(&secret, Dir::App, 0, "pair-ok", "") })
    }

    fn authed(&self, ext: &str, msg: &Value) -> Value {
        let Ok(env) = serde_json::from_value::<Envelope>(msg.clone()) else { return err("bad-request") };
        let secret = {
            let Ok(mut st) = self.store.lock() else { return err("internal") };
            let Some(p) = st.find_mut(ext) else { return err("not-paired") };
            let Ok(secret) = B64.decode(&p.secret) else { return err("not-paired") };
            if !verify(&secret, Dir::Ext, env.n, &env.kind, &env.body, &env.mac) {
                return err("bad-mac");
            }
            if env.n <= p.n {
                return err("replay");
            }
            // The counter is spent (and written) before the request is acted on.
            p.n = env.n;
            if st.save().is_err() {
                return err("internal");
            }
            secret
        };
        let result = match serde_json::from_str::<Value>(&env.body) {
            Ok(body) if body.is_object() => self.dispatch(&env.kind, &body),
            _ => json!({ "ok": false, "error": "bad-request" }),
        };
        let body = result.to_string();
        json!({ "v": PROTO_VERSION, "n": env.n, "type": env.kind, "body": body, "mac": sign(&secret, Dir::App, env.n, &env.kind, &body) })
    }

    fn dispatch(&self, kind: &str, body: &Value) -> Value {
        let fail = |code: &str| json!({ "ok": false, "error": code });
        let unlocked = self.ui.unlocked();
        match kind {
            "status" => json!({ "ok": true, "locked": !unlocked }),
            "unlock-request" => {
                self.ui.show_window();
                json!({ "ok": true, "locked": !unlocked })
            }
            "lock" => {
                self.ui.lock_now();
                json!({ "ok": true, "locked": true })
            }
            "match" | "fill" | "save-offer" => {
                let Some(origin) = body.get("origin").and_then(Value::as_str).and_then(web_origin) else { return fail("bad-origin") };
                let text = |k: &str, max: usize| body.get(k).and_then(Value::as_str).filter(|s| s.len() <= max);
                let fwd = match kind {
                    "match" => json!({ "origin": origin }),
                    "fill" => {
                        let Some(id) = text("id", 64).filter(|s| !s.is_empty()) else { return fail("bad-request") };
                        json!({ "origin": origin, "id": id })
                    }
                    _ => {
                        let (Some(user), Some(pw)) = (text("username", 1024), text("password", 4096).filter(|s| !s.is_empty())) else {
                            return fail("bad-request");
                        };
                        json!({ "origin": origin, "username": user, "password": pw })
                    }
                };
                // An offer can wait for the person to unlock; reading logins cannot.
                if kind != "save-offer" && !unlocked {
                    return fail("locked");
                }
                match self.ui.ask_vault(kind, &fwd) {
                    Ok(Value::Object(mut m)) => {
                        m.insert("ok".into(), Value::Bool(true));
                        Value::Object(m)
                    }
                    Ok(_) => json!({ "ok": true }),
                    Err(code) => fail(&code),
                }
            }
            _ => fail("unknown-type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const EXT: &str = "dolmkecfaekonkkgpjpamipjleindand";
    const SECRET: [u8; 32] = [9u8; 32];

    struct FakeUi {
        unlocked: AtomicBool,
        approve: AtomicBool,
        locks: AtomicUsize,
        shown: AtomicUsize,
        seen_fp: Mutex<Vec<String>>,
        asked: Mutex<Vec<(String, Value)>>,
        answer: Mutex<Result<Value, String>>,
    }

    impl FakeUi {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                unlocked: AtomicBool::new(true),
                approve: AtomicBool::new(true),
                locks: AtomicUsize::new(0),
                shown: AtomicUsize::new(0),
                seen_fp: Mutex::new(vec![]),
                asked: Mutex::new(vec![]),
                answer: Mutex::new(Ok(json!({}))),
            })
        }
    }

    impl Ui for FakeUi {
        fn show_window(&self) {
            self.shown.fetch_add(1, Ordering::SeqCst);
        }
        fn lock_now(&self) {
            self.locks.fetch_add(1, Ordering::SeqCst);
            self.unlocked.store(false, Ordering::SeqCst);
        }
        fn unlocked(&self) -> bool {
            self.unlocked.load(Ordering::SeqCst)
        }
        fn confirm_pair(&self, _ext: &str, fp: &str) -> bool {
            self.seen_fp.lock().unwrap().push(fp.to_string());
            self.approve.load(Ordering::SeqCst)
        }
        fn ask_vault(&self, kind: &str, body: &Value) -> Result<Value, String> {
            self.asked.lock().unwrap().push((kind.to_string(), body.clone()));
            self.answer.lock().unwrap().clone()
        }
    }

    fn link(ui: &Arc<FakeUi>) -> Arc<Link> {
        Link::new(LinkStore::memory(), ui.clone(), vec![EXT.to_string()])
    }

    fn origin() -> String {
        format!("chrome-extension://{EXT}/")
    }

    fn frame(origin: &str, msg: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({ "origin": origin, "msg": msg })).unwrap()
    }

    fn pair_msg() -> Value {
        json!({ "v": 1, "type": "pair", "secret": B64.encode(SECRET) })
    }

    fn signed(n: u64, kind: &str, body: Value) -> Value {
        let body = body.to_string();
        json!({ "v": 1, "n": n, "type": kind, "body": body, "mac": sign(&SECRET, Dir::Ext, n, kind, &body) })
    }

    fn paired(ui: &Arc<FakeUi>) -> Arc<Link> {
        let l = link(ui);
        assert_eq!(l.handle(&frame(&origin(), pair_msg()))["type"], "pair-ok");
        l
    }

    fn call(l: &Link, n: u64, kind: &str, body: Value) -> Value {
        l.handle(&frame(&origin(), signed(n, kind, body)))
    }

    fn reply_body(r: &Value) -> Value {
        serde_json::from_str(r["body"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn pairing_needs_approval_and_shows_the_fingerprint() {
        let ui = FakeUi::new();
        let l = link(&ui);
        let r = l.handle(&frame(&origin(), pair_msg()));
        assert_eq!(r["type"], "pair-ok");
        assert!(verify(&SECRET, Dir::App, 0, "pair-ok", "", r["mac"].as_str().unwrap()));
        assert_eq!(*ui.seen_fp.lock().unwrap(), vec![fingerprint(&SECRET)]);
        assert_eq!(ui.shown.load(Ordering::SeqCst), 1);
        assert_eq!(l.paired().len(), 1);

        let ui = FakeUi::new();
        ui.approve.store(false, Ordering::SeqCst);
        let l = link(&ui);
        assert_eq!(l.handle(&frame(&origin(), pair_msg()))["code"], "pair-denied");
        assert!(l.paired().is_empty());
        // Nothing works without a pairing.
        assert_eq!(call(&l, 1, "status", json!({}))["code"], "not-paired");
    }

    #[test]
    fn pairing_refuses_bad_secrets_and_a_second_prompt() {
        let ui = FakeUi::new();
        let l = link(&ui);
        for bad in [json!("AAAA"), json!(5), Value::Null] {
            assert_eq!(l.handle(&frame(&origin(), json!({ "v": 1, "type": "pair", "secret": bad })))["code"], "bad-request");
        }
        l.pairing.store(true, Ordering::SeqCst);
        assert_eq!(l.handle(&frame(&origin(), pair_msg()))["code"], "busy");
        assert!(ui.seen_fp.lock().unwrap().is_empty());
    }

    #[test]
    fn only_listed_extensions_get_in() {
        let ui = FakeUi::new();
        let l = link(&ui);
        let other = format!("chrome-extension://{}/", "p".repeat(32));
        assert_eq!(l.handle(&frame(&other, pair_msg()))["code"], "origin-denied");
        assert_eq!(l.handle(&frame("https://evil.test/", pair_msg()))["code"], "origin-denied");
        assert_eq!(l.handle(&frame("", pair_msg()))["code"], "origin-denied");
        assert_eq!(l.handle(b"not json")["code"], "bad-request");
        assert!(ui.seen_fp.lock().unwrap().is_empty(), "no prompt for a stranger");
        let mut m = pair_msg();
        m["v"] = json!(2);
        assert_eq!(l.handle(&frame(&origin(), m))["code"], "unsupported-version");
    }

    #[test]
    fn switching_the_link_off_stops_answering() {
        let ui = FakeUi::new();
        let l = paired(&ui);
        l.set_enabled(false).unwrap();
        assert_eq!(call(&l, 1, "status", json!({}))["code"], "disabled");
        assert_eq!(l.handle(&frame(&origin(), pair_msg()))["code"], "disabled");
        l.set_enabled(true).unwrap();
        assert_eq!(call(&l, 1, "status", json!({}))["type"], "status");
    }

    #[test]
    fn replies_are_signed_and_replays_are_refused() {
        let ui = FakeUi::new();
        let l = paired(&ui);
        let r = call(&l, 10, "status", json!({}));
        assert_eq!(r["n"], 10);
        assert!(verify(&SECRET, Dir::App, 10, "status", r["body"].as_str().unwrap(), r["mac"].as_str().unwrap()));
        assert_eq!(reply_body(&r), json!({ "ok": true, "locked": false }));
        // Same counter again, and an older one: both replays, even though the MAC is valid.
        assert_eq!(call(&l, 10, "status", json!({}))["code"], "replay");
        assert_eq!(call(&l, 9, "status", json!({}))["code"], "replay");
        assert_eq!(call(&l, 11, "status", json!({}))["type"], "status");
    }

    #[test]
    fn tampering_and_wrong_keys_fail() {
        let ui = FakeUi::new();
        let l = paired(&ui);
        let mut m = signed(5, "match", json!({ "origin": "https://a.test" }));
        m["body"] = json!(json!({ "origin": "https://b.test" }).to_string());
        assert_eq!(l.handle(&frame(&origin(), m))["code"], "bad-mac");
        let mut m = signed(5, "match", json!({ "origin": "https://a.test" }));
        m["type"] = json!("fill");
        assert_eq!(l.handle(&frame(&origin(), m))["code"], "bad-mac");
        let mut m = signed(5, "status", json!({}));
        m["mac"] = json!(sign(&[1u8; 32], Dir::Ext, 5, "status", "{}"));
        assert_eq!(l.handle(&frame(&origin(), m))["code"], "bad-mac");
        // A signature the app itself made (a reply) is not a request.
        let body = "{}";
        let m = json!({ "v": 1, "n": 6, "type": "status", "body": body, "mac": sign(&SECRET, Dir::App, 6, "status", body) });
        assert_eq!(l.handle(&frame(&origin(), m))["code"], "bad-mac");
        // A bad MAC does not burn the counter.
        assert_eq!(call(&l, 5, "status", json!({}))["type"], "status");
    }

    #[test]
    fn counters_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let ui = FakeUi::new();
        let l = Link::new(LinkStore::open(dir.path()), ui.clone(), vec![EXT.to_string()]);
        assert_eq!(l.handle(&frame(&origin(), pair_msg()))["type"], "pair-ok");
        assert_eq!(call(&l, 100, "status", json!({}))["n"], 100);
        let again = Link::new(LinkStore::open(dir.path()), ui, vec![EXT.to_string()]);
        assert_eq!(call(&again, 100, "status", json!({}))["code"], "replay");
        assert_eq!(call(&again, 101, "status", json!({}))["n"], 101);
        again.unpair(EXT).unwrap();
        assert_eq!(call(&again, 102, "status", json!({}))["code"], "not-paired");
        let on_disk = std::fs::read_to_string(dir.path().join("native-link.json")).unwrap();
        assert!(!on_disk.contains("secret\": \"\""));
    }

    #[test]
    fn lock_state_and_unlock_request() {
        let ui = FakeUi::new();
        let l = paired(&ui);
        let before = ui.shown.load(Ordering::SeqCst);
        assert_eq!(reply_body(&call(&l, 1, "unlock-request", json!({}))), json!({ "ok": true, "locked": false }));
        assert_eq!(ui.shown.load(Ordering::SeqCst), before + 1);
        assert_eq!(reply_body(&call(&l, 2, "lock", json!({}))), json!({ "ok": true, "locked": true }));
        assert_eq!(ui.locks.load(Ordering::SeqCst), 1);
        assert_eq!(reply_body(&call(&l, 3, "status", json!({}))), json!({ "ok": true, "locked": true }));
        assert_eq!(reply_body(&call(&l, 4, "frobnicate", json!({})))["error"], "unknown-type");
    }

    #[test]
    fn logins_are_only_served_when_unlocked_and_for_a_bare_origin() {
        let ui = FakeUi::new();
        *ui.answer.lock().unwrap() = Ok(json!({ "logins": [{ "id": "1", "title": "A", "username": "u" }] }));
        let l = paired(&ui);
        let r = reply_body(&call(&l, 1, "match", json!({ "origin": "https://a.test" })));
        assert_eq!(r["ok"], true);
        assert_eq!(r["logins"][0]["id"], "1");
        assert_eq!(ui.asked.lock().unwrap()[0], ("match".to_string(), json!({ "origin": "https://a.test" })));

        for (n, bad) in [
            "https://a.test/",
            "https://a.test/login",
            "https://user@a.test",
            "https://a.test?x=1",
            "ftp://a.test",
            "javascript:alert(1)",
            "HTTPS://A.TEST",
            "a.test",
            "",
        ]
        .iter()
        .enumerate()
        {
            let r = reply_body(&call(&l, 10 + n as u64, "match", json!({ "origin": bad })));
            assert_eq!(r["error"], "bad-origin", "{bad}");
        }
        assert_eq!(ui.asked.lock().unwrap().len(), 1, "malformed origins never reach the vault");
        assert_eq!(web_origin("http://localhost:8080"), Some("http://localhost:8080".into()));
        assert_eq!(web_origin("https://a.test:443"), None, "default port is not canonical");

        ui.unlocked.store(false, Ordering::SeqCst);
        assert_eq!(reply_body(&call(&l, 30, "match", json!({ "origin": "https://a.test" })))["error"], "locked");
        assert_eq!(reply_body(&call(&l, 31, "fill", json!({ "origin": "https://a.test", "id": "1" })))["error"], "locked");
        assert_eq!(ui.asked.lock().unwrap().len(), 1);
    }

    #[test]
    fn fill_forwards_the_exact_origin_and_id() {
        let ui = FakeUi::new();
        *ui.answer.lock().unwrap() = Ok(json!({ "username": "u", "password": "p" }));
        let l = paired(&ui);
        let r = reply_body(&call(&l, 1, "fill", json!({ "origin": "https://a.test", "id": "abc" })));
        assert_eq!((r["username"].as_str(), r["password"].as_str()), (Some("u"), Some("p")));
        assert_eq!(ui.asked.lock().unwrap()[0].1, json!({ "origin": "https://a.test", "id": "abc" }));
        assert_eq!(reply_body(&call(&l, 2, "fill", json!({ "origin": "https://a.test" })))["error"], "bad-request");
        *ui.answer.lock().unwrap() = Err("no-match".into());
        assert_eq!(reply_body(&call(&l, 3, "fill", json!({ "origin": "https://a.test", "id": "zzz" })))["error"], "no-match");
    }

    #[test]
    fn save_offers_are_accepted_while_locked_but_validated() {
        let ui = FakeUi::new();
        ui.unlocked.store(false, Ordering::SeqCst);
        let l = paired(&ui);
        let r = reply_body(&call(&l, 1, "save-offer", json!({ "origin": "https://a.test", "username": "me", "password": "pw" })));
        assert_eq!(r["ok"], true);
        assert_eq!(ui.asked.lock().unwrap()[0].1["password"], "pw");
        assert_eq!(reply_body(&call(&l, 2, "save-offer", json!({ "origin": "https://a.test", "username": "me", "password": "" })))["error"], "bad-request");
        let huge = "x".repeat(5000);
        assert_eq!(reply_body(&call(&l, 3, "save-offer", json!({ "origin": "https://a.test", "username": "me", "password": huge })))["error"], "bad-request");
        assert_eq!(ui.asked.lock().unwrap().len(), 1);
    }

    #[test]
    fn serve_runs_frames_until_hangup() {
        struct Duplex {
            input: io::Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl Read for Duplex {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.input.read(b)
            }
        }
        impl Write for Duplex {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.output.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let ui = FakeUi::new();
        let l = paired(&ui);
        let mut input = Vec::new();
        crate::link_proto::write_frame(&mut input, &frame(&origin(), signed(1, "status", json!({})))).unwrap();
        crate::link_proto::write_frame(&mut input, &frame(&origin(), signed(1, "status", json!({})))).unwrap();
        let mut d = Duplex { input: io::Cursor::new(input), output: vec![] };
        l.serve(&mut d).unwrap();
        let mut out = io::Cursor::new(d.output);
        let first: Value = serde_json::from_slice(&crate::link_proto::read_frame(&mut out).unwrap().unwrap()).unwrap();
        let second: Value = serde_json::from_slice(&crate::link_proto::read_frame(&mut out).unwrap().unwrap()).unwrap();
        assert_eq!(first["type"], "status");
        assert_eq!(second["code"], "replay");
    }

    #[test]
    fn pevv_frames_go_to_the_cli_policy_with_the_os_reported_caller() {
        use crate::cli_core::{Answer, Cli, CliStore, CliUi, SecretsPrompt, Source, VaultEnv};
        use crate::cli_proto::{envelope, CliRequest, Purpose, Var};
        use crate::link_ipc::{connect, Listener};
        use crate::link_proto::{read_frame, write_frame};
        struct CliFake(Mutex<Vec<String>>);
        impl CliUi for CliFake {
            fn show_window(&self) {}
            fn unlocked(&self) -> bool {
                true
            }
            fn lock_now(&self) {}
            fn confirm_client(&self, exe: &str, _changed: bool) -> bool {
                self.0.lock().unwrap().push(exe.to_string());
                true
            }
            fn confirm_secrets(&self, _p: &SecretsPrompt) -> Answer {
                Answer::Once
            }
            fn ask_vault_env(&self, _p: &[String], _e: &[String]) -> Result<VaultEnv, String> {
                Ok(VaultEnv {
                    vars: vec![Var { name: "K".into(), value: "v".into() }],
                    sources: vec![Source { kind: "env".into(), name: "dev".into(), env: "dev".into() }],
                })
            }
        }
        #[cfg(windows)]
        let ep = format!(r"\\.\pipe\pevv-link-test-cli-{}", std::process::id());
        #[cfg(unix)]
        let ep = std::env::temp_dir().join(format!("pevv-link-cli-{}", std::process::id())).join("c.sock").to_string_lossy().into_owned();
        let ui = FakeUi::new();
        let l = link(&ui);
        let seen = Arc::new(CliFake(Mutex::new(vec![])));
        l.set_cli(Cli::new(CliStore::memory(), seen.clone()));
        let mut listener = Listener::bind(&ep).unwrap();
        let server = l.clone();
        let t = std::thread::spawn(move || {
            let mut c = listener.accept().unwrap();
            let pid = c.peer_pid().ok();
            server.serve_peer(&mut c, move || pid.and_then(crate::cli_core::peer_of_pid)).unwrap();
        });
        let mut c = connect(&ep).unwrap();
        let ask = |c: &mut crate::link_ipc::Conn, req: &CliRequest| -> Value {
            write_frame(c, &serde_json::to_vec(&envelope(req)).unwrap()).unwrap();
            serde_json::from_slice(&read_frame(c).unwrap().unwrap()).unwrap()
        };
        assert_eq!(ask(&mut c, &CliRequest::Status)["locked"], false);
        let r = ask(
            &mut c,
            &CliRequest::Secrets {
                purpose: Purpose::Env,
                projects: vec![],
                envs: vec!["dev".into()],
                command: vec![],
                cwd: String::new(),
                format: Some(crate::cli_proto::Format::Sh),
            },
        );
        assert_eq!(r["vars"][0]["name"], "K");
        // The app learned the caller's path from the OS: it is this test program.
        let seen_exe = seen.0.lock().unwrap().clone();
        assert_eq!(seen_exe.len(), 1, "asked once for the connection's program");
        assert_eq!(std::fs::canonicalize(&seen_exe[0]).ok(), std::fs::canonicalize(std::env::current_exe().unwrap()).ok());
        // A frame without the cli marker still takes the extension path.
        write_frame(&mut c, &frame("https://evil.test/", pair_msg())).unwrap();
        let r: Value = serde_json::from_slice(&read_frame(&mut c).unwrap().unwrap()).unwrap();
        assert_eq!(r["code"], "origin-denied");
        drop(c);
        t.join().unwrap();
    }

    #[test]
    fn end_to_end_over_the_real_local_channel() {
        use crate::link_ipc::{connect, Listener};
        use crate::link_proto::{read_frame, write_frame};
        #[cfg(windows)]
        let ep = format!(r"\\.\pipe\pevv-link-test-core-{}", std::process::id());
        #[cfg(unix)]
        let ep = std::env::temp_dir().join(format!("pevv-link-core-{}", std::process::id())).join("c.sock").to_string_lossy().into_owned();
        let ui = FakeUi::new();
        let l = link(&ui);
        let mut listener = Listener::bind(&ep).unwrap();
        let server = l.clone();
        let t = std::thread::spawn(move || {
            let mut c = listener.accept().unwrap();
            server.serve(&mut c).unwrap();
        });
        let mut c = connect(&ep).unwrap();
        write_frame(&mut c, &frame(&origin(), pair_msg())).unwrap();
        let r: Value = serde_json::from_slice(&read_frame(&mut c).unwrap().unwrap()).unwrap();
        assert_eq!(r["type"], "pair-ok");
        write_frame(&mut c, &frame(&origin(), signed(7, "status", json!({})))).unwrap();
        let r: Value = serde_json::from_slice(&read_frame(&mut c).unwrap().unwrap()).unwrap();
        assert_eq!(reply_body(&r)["locked"], false);
        drop(c);
        t.join().unwrap();
    }
}
