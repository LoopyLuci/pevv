//! The app's side of `pevv run` / `pevv env` / `pevv status` / `pevv lock`: who may call, and what
//! each request needs before a secret leaves the app.
//!
//! Tauri-free (the window, the lock state and the vault UI are behind `CliUi`) so the whole policy
//! runs under unit tests. Like the browser link, this side never holds decrypted variables: the
//! unlocked vault UI picks them (`ask_vault_env`) and they only travel on to the caller after
//! the person has said yes. Policy, in order:
//!
//! * the caller is identified by the OS (the peer process id of the local channel, then that
//!   process's executable path and a SHA-256 of the file), never by anything it sends;
//! * the first time an executable path (or the same path with different contents) calls, the
//!   person is asked; the answer is kept in `cli-access.json` and can be revoked in Settings;
//! * `status` and `lock` need nothing more; they reveal and risk nothing;
//! * `secrets` needs the vault unlocked and a fresh answer in the app: the command, the
//!   variable names and where they come from are shown (never the values). `run` can be allowed
//!   for 8 hours for exactly that command line, working folder, sources and variable names;
//!   `env` (which prints the secrets) always asks.

use crate::cli_proto::{CliRequest, Format, Purpose, Var, CLI_VERSION, MAX_ARGS, MAX_ARGV_BYTES, MAX_NAMES, MAX_NAME_LEN};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// How long "allow this command" lasts.
pub const ALLOW_MS: u64 = 8 * 60 * 60 * 1000;
const MAX_ALLOWED: usize = 64;

/// What the app lends this module.
pub trait CliUi: Send + Sync {
    fn show_window(&self);
    fn unlocked(&self) -> bool;
    fn lock_now(&self);
    /// First contact from this executable (or its contents changed). Blocks until answered.
    fn confirm_client(&self, exe: &str, changed: bool) -> bool;
    /// Approve handing these variables to the caller. Blocks until answered.
    fn confirm_secrets(&self, prompt: &SecretsPrompt) -> Answer;
    /// Ask the unlocked vault UI for the variables of these projects / environments. `Err` is a short code.
    fn ask_vault_env(&self, projects: &[String], envs: &[String]) -> Result<VaultEnv, String>;
    /// The variables were handed over (after a yes, or under an 8 h allowance): for the activity log.
    /// `program` is the command's first word only, never its arguments.
    fn served(&self, _purpose: Purpose, _program: &str, _variables: usize) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Deny,
    Once,
    /// Not for `env`: it prints the secrets, so it asks every time.
    For8h,
}

/// Where a set of variables came from: a project (its linked environment, else the active one),
/// an environment named directly, or the active environment (no option given).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Source {
    pub kind: String,
    pub name: String,
    pub env: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VaultEnv {
    pub vars: Vec<Var>,
    #[serde(default)]
    pub sources: Vec<Source>,
}

/// What the person is shown. Variable *names* only.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretsPrompt {
    pub purpose: Purpose,
    pub command: Vec<String>,
    pub cwd: String,
    pub exe: String,
    pub format: Option<Format>,
    pub sources: Vec<Source>,
    pub names: Vec<String>,
}

/// The calling process, as the OS reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub exe: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approved {
    pub path: String,
    pub sha256: String,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Allowed {
    pub key: String,
    /// The command line, for the Settings list.
    pub label: String,
    pub until: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliFile {
    #[serde(default)]
    pub approved: Vec<Approved>,
    #[serde(default)]
    pub commands: Vec<Allowed>,
}

/// `cli-access.json` in the app data folder (owner-only on Unix). Paths, hashes and command
/// lines; no secret is ever written here.
pub struct CliStore {
    path: Option<PathBuf>,
    pub file: CliFile,
}

impl CliStore {
    pub fn open(dir: &Path) -> Self {
        let path = dir.join("cli-access.json");
        let file = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        Self { path: Some(path), file }
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self { path: None, file: CliFile::default() }
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
}

fn same_path(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// SHA-256 (hex) of a file, streamed.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h)?;
    Ok(crate::link_proto::hex(&h.finalize()))
}

/// The executable path of a running process, from the OS.
#[cfg(windows)]
pub fn exe_of_pid(pid: u32) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
    // SAFETY: plain Win32 calls; the handle is closed before returning and the buffer outlives the call.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 32 * 1024];
        let mut len = buf.len() as u32;
        let r = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(h);
        r.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

#[cfg(target_os = "linux")]
pub fn exe_of_pid(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn exe_of_pid(_pid: u32) -> Option<String> {
    None
}

/// Who is on the other end: the OS's process id, that process's executable, and a hash of that file.
pub fn peer_of_pid(pid: u32) -> Option<Peer> {
    let exe = exe_of_pid(pid)?;
    let sha256 = sha256_file(Path::new(&exe)).ok()?;
    Some(Peer { pid, exe, sha256 })
}

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_NAME_LEN && s.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

/// What an allowance is bound to (the program's path and contents, the command line, the working
/// folder, where the variables come from and their names): change any part and the person is asked again.
fn allowance_key(exe: &str, sha256: &str, command: &[String], cwd: &str, sources: &[Source], names: &[String]) -> String {
    let mut src: Vec<(&str, &str, &str)> = sources.iter().map(|s| (s.kind.as_str(), s.name.as_str(), s.env.as_str())).collect();
    src.sort_unstable();
    let mut names: Vec<&str> = names.iter().map(String::as_str).collect();
    names.sort_unstable();
    let canon = json!([exe.to_ascii_lowercase(), sha256, command, cwd, src, names]).to_string();
    crate::link_proto::hex(&Sha256::digest(canon.as_bytes()))
}

fn fail(code: &str) -> Value {
    json!({ "v": CLI_VERSION, "ok": false, "error": code })
}

struct Busy<'a>(&'a AtomicBool);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn real_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub struct Cli {
    store: Mutex<CliStore>,
    ui: Arc<dyn CliUi>,
    /// One question at a time: a program cannot bury the person in prompts.
    asking: AtomicBool,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl Cli {
    pub fn new(store: CliStore, ui: Arc<dyn CliUi>) -> Arc<Self> {
        Self::with_clock(store, ui, Box::new(real_now))
    }

    pub fn with_clock(store: CliStore, ui: Arc<dyn CliUi>, now: Box<dyn Fn() -> u64 + Send + Sync>) -> Arc<Self> {
        Arc::new(Self { store: Mutex::new(store), ui, asking: AtomicBool::new(false), now })
    }

    pub fn approved(&self) -> Vec<Approved> {
        self.store.lock().map(|s| s.file.approved.clone()).unwrap_or_default()
    }

    /// Commands allowed for 8 h that have not run out.
    pub fn allowed(&self) -> Vec<Allowed> {
        let now = (self.now)();
        self.store.lock().map(|s| s.file.commands.iter().filter(|c| c.until > now).cloned().collect()).unwrap_or_default()
    }

    pub fn revoke_client(&self, path: &str) -> io::Result<()> {
        let mut s = self.store.lock().map_err(|_| io::Error::other("poisoned"))?;
        s.file.approved.retain(|a| !same_path(&a.path, path));
        s.save()
    }

    pub fn revoke_command(&self, key: &str) -> io::Result<()> {
        let mut s = self.store.lock().map_err(|_| io::Error::other("poisoned"))?;
        s.file.commands.retain(|c| c.key != key);
        s.save()
    }

    /// One request frame (already known to carry `"client": "cli"`) from `peer`.
    pub fn handle(&self, peer: Option<&Peer>, frame: &Value) -> Value {
        if frame.get("v").and_then(Value::as_u64) != Some(CLI_VERSION) {
            return fail("unsupported-version");
        }
        let Ok(req) = serde_json::from_value::<CliRequest>(frame.clone()) else { return fail("bad-request") };
        let Some(peer) = peer else { return fail("peer-unknown") };
        if let Err(code) = self.authorize(peer) {
            return fail(code);
        }
        match req {
            CliRequest::Status => json!({ "v": CLI_VERSION, "ok": true, "locked": !self.ui.unlocked() }),
            CliRequest::Lock => {
                self.ui.lock_now();
                json!({ "v": CLI_VERSION, "ok": true, "locked": true })
            }
            CliRequest::Secrets { purpose, projects, envs, command, cwd, format } => self.secrets(peer, purpose, projects, envs, command, cwd, format),
        }
    }

    fn authorize(&self, peer: &Peer) -> Result<(), &'static str> {
        let changed = {
            let Ok(s) = self.store.lock() else { return Err("internal") };
            match s.file.approved.iter().find(|a| same_path(&a.path, &peer.exe)) {
                Some(a) if a.sha256 == peer.sha256 => return Ok(()),
                Some(_) => true,
                None => false,
            }
        };
        if self.asking.swap(true, Ordering::SeqCst) {
            return Err("busy");
        }
        let _busy = Busy(&self.asking);
        self.ui.show_window();
        if !self.ui.confirm_client(&peer.exe, changed) {
            return Err("client-denied");
        }
        let Ok(mut s) = self.store.lock() else { return Err("internal") };
        s.file.approved.retain(|a| !same_path(&a.path, &peer.exe));
        s.file.approved.push(Approved { path: peer.exe.clone(), sha256: peer.sha256.clone(), at: (self.now)() });
        s.save().map_err(|_| "internal")
    }

    #[allow(clippy::too_many_arguments)]
    fn secrets(
        &self,
        peer: &Peer,
        purpose: Purpose,
        projects: Vec<String>,
        envs: Vec<String>,
        command: Vec<String>,
        cwd: String,
        format: Option<Format>,
    ) -> Value {
        if projects.len() + envs.len() > MAX_NAMES || !projects.iter().chain(&envs).all(|n| name_ok(n)) {
            return fail("bad-request");
        }
        if command.len() > MAX_ARGS || command.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES || cwd.len() > 4096 {
            return fail("bad-request");
        }
        match purpose {
            Purpose::Run if command.is_empty() => return fail("bad-request"),
            Purpose::Env if format.is_none() => return fail("bad-request"),
            _ => {}
        }
        if !self.ui.unlocked() {
            self.ui.show_window();
            return fail("locked");
        }
        let env = match self.ui.ask_vault_env(&projects, &envs) {
            Ok(e) => e,
            Err(code) => return fail(&code),
        };
        let mut names: Vec<String> = env.vars.iter().map(|v| v.name.clone()).collect();
        names.sort();
        names.dedup();
        if names.is_empty() {
            return fail("no-vars");
        }
        let key = allowance_key(&peer.exe, &peer.sha256, &command, &cwd, &env.sources, &names);
        let now = (self.now)();
        let pre_allowed = purpose == Purpose::Run && self.store.lock().map(|s| s.file.commands.iter().any(|c| c.key == key && c.until > now)).unwrap_or(false);
        if !pre_allowed {
            if self.asking.swap(true, Ordering::SeqCst) {
                return fail("busy");
            }
            let _busy = Busy(&self.asking);
            self.ui.show_window();
            let prompt = SecretsPrompt { purpose, command: command.clone(), cwd, exe: peer.exe.clone(), format, sources: env.sources.clone(), names };
            match self.ui.confirm_secrets(&prompt) {
                Answer::Deny => return fail("request-denied"),
                Answer::Once => {}
                Answer::For8h if purpose == Purpose::Run => {
                    let Ok(mut s) = self.store.lock() else { return fail("internal") };
                    s.file.commands.retain(|c| c.until > now && c.key != key);
                    let label: String = command.join(" ").chars().take(200).collect();
                    s.file.commands.push(Allowed { key, label, until: now + ALLOW_MS });
                    let extra = s.file.commands.len().saturating_sub(MAX_ALLOWED);
                    s.file.commands.drain(..extra);
                    if s.save().is_err() {
                        return fail("internal");
                    }
                }
                Answer::For8h => {}
            }
        }
        let program = command.first().map(|c| c.rsplit(['\\', '/']).next().unwrap_or("").chars().take(40).collect::<String>()).unwrap_or_default();
        self.ui.served(purpose, &program, env.vars.len());
        json!({ "v": CLI_VERSION, "ok": true, "vars": env.vars, "sources": env.sources })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_proto::envelope;
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    struct FakeUi {
        unlocked: AtomicBool,
        client_ok: AtomicBool,
        answer: Mutex<Answer>,
        vars: Mutex<Result<VaultEnv, String>>,
        client_prompts: AtomicUsize,
        secret_prompts: Mutex<Vec<SecretsPrompt>>,
        locks: AtomicUsize,
        shown: AtomicUsize,
        asked: Mutex<Vec<(Vec<String>, Vec<String>)>>,
        served: Mutex<Vec<(Purpose, String, usize)>>,
    }

    impl FakeUi {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                unlocked: AtomicBool::new(true),
                client_ok: AtomicBool::new(true),
                answer: Mutex::new(Answer::Once),
                vars: Mutex::new(Ok(VaultEnv {
                    vars: vec![Var { name: "TOKEN".into(), value: "s3cret".into() }, Var { name: "API_URL".into(), value: "https://x".into() }],
                    sources: vec![Source { kind: "project".into(), name: "api".into(), env: "dev".into() }],
                })),
                client_prompts: AtomicUsize::new(0),
                secret_prompts: Mutex::new(vec![]),
                locks: AtomicUsize::new(0),
                shown: AtomicUsize::new(0),
                asked: Mutex::new(vec![]),
                served: Mutex::new(vec![]),
            })
        }
    }

    impl CliUi for FakeUi {
        fn show_window(&self) {
            self.shown.fetch_add(1, Ordering::SeqCst);
        }
        fn unlocked(&self) -> bool {
            self.unlocked.load(Ordering::SeqCst)
        }
        fn lock_now(&self) {
            self.locks.fetch_add(1, Ordering::SeqCst);
            self.unlocked.store(false, Ordering::SeqCst);
        }
        fn confirm_client(&self, _exe: &str, _changed: bool) -> bool {
            self.client_prompts.fetch_add(1, Ordering::SeqCst);
            self.client_ok.load(Ordering::SeqCst)
        }
        fn confirm_secrets(&self, p: &SecretsPrompt) -> Answer {
            self.secret_prompts.lock().unwrap().push(p.clone());
            *self.answer.lock().unwrap()
        }
        fn ask_vault_env(&self, projects: &[String], envs: &[String]) -> Result<VaultEnv, String> {
            self.asked.lock().unwrap().push((projects.to_vec(), envs.to_vec()));
            self.vars.lock().unwrap().clone()
        }
        fn served(&self, purpose: Purpose, program: &str, n: usize) {
            self.served.lock().unwrap().push((purpose, program.to_string(), n));
        }
    }

    fn peer(sha: &str) -> Peer {
        Peer { pid: 4242, exe: "/opt/pevv/pevv".into(), sha256: sha.into() }
    }

    fn secrets(purpose: Purpose, command: &[&str]) -> Value {
        envelope(&CliRequest::Secrets {
            purpose,
            projects: vec!["api".into()],
            envs: vec![],
            command: command.iter().map(|s| s.to_string()).collect(),
            cwd: "/w".into(),
            format: (purpose == Purpose::Env).then_some(Format::Dotenv),
        })
    }

    fn cli(ui: &Arc<FakeUi>) -> Arc<Cli> {
        Cli::new(CliStore::memory(), ui.clone())
    }

    #[test]
    fn a_new_executable_is_asked_once_and_remembered() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        let p = peer("aa");
        assert_eq!(c.handle(Some(&p), &envelope(&CliRequest::Status))["locked"], false);
        assert_eq!(c.handle(Some(&p), &envelope(&CliRequest::Status))["locked"], false);
        assert_eq!(ui.client_prompts.load(Ordering::SeqCst), 1);
        assert_eq!(c.approved().len(), 1);
        assert_eq!(c.approved()[0].path, "/opt/pevv/pevv");
        // Same path, different contents: asked again.
        assert_eq!(c.handle(Some(&peer("bb")), &envelope(&CliRequest::Status))["ok"], true);
        assert_eq!(ui.client_prompts.load(Ordering::SeqCst), 2);
        assert_eq!(c.approved().len(), 1, "one entry per path");
    }

    #[test]
    fn a_refused_executable_gets_nothing_and_is_asked_again_next_time() {
        let ui = FakeUi::new();
        ui.client_ok.store(false, Ordering::SeqCst);
        let c = cli(&ui);
        let r = c.handle(Some(&peer("aa")), &secrets(Purpose::Run, &["x"]));
        assert_eq!(r["error"], "client-denied");
        assert!(r.get("vars").is_none());
        assert!(c.approved().is_empty());
        assert!(ui.asked.lock().unwrap().is_empty(), "the vault was not even consulted");
        c.handle(Some(&peer("aa")), &envelope(&CliRequest::Status));
        assert_eq!(ui.client_prompts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn an_unknown_caller_or_version_is_refused() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        assert_eq!(c.handle(None, &envelope(&CliRequest::Status))["error"], "peer-unknown");
        let mut f = envelope(&CliRequest::Status);
        f["v"] = json!(99);
        assert_eq!(c.handle(Some(&peer("aa")), &f)["error"], "unsupported-version");
        assert_eq!(c.handle(Some(&peer("aa")), &json!({ "v": 1, "type": "frob" }))["error"], "bad-request");
        assert_eq!(ui.client_prompts.load(Ordering::SeqCst), 0, "no prompt for a malformed request");
    }

    #[test]
    fn lock_and_status() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        let p = peer("aa");
        assert_eq!(c.handle(Some(&p), &envelope(&CliRequest::Lock))["locked"], true);
        assert_eq!(ui.locks.load(Ordering::SeqCst), 1);
        assert_eq!(c.handle(Some(&p), &envelope(&CliRequest::Status))["locked"], true);
    }

    #[test]
    fn secrets_need_an_unlocked_vault_and_an_answer() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        let p = peer("aa");
        ui.unlocked.store(false, Ordering::SeqCst);
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "test"]))["error"], "locked");
        assert!(ui.asked.lock().unwrap().is_empty());
        ui.unlocked.store(true, Ordering::SeqCst);

        *ui.answer.lock().unwrap() = Answer::Deny;
        let r = c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "test"]));
        assert_eq!(r["error"], "request-denied");
        assert!(r.get("vars").is_none(), "a refusal carries no secret");

        *ui.answer.lock().unwrap() = Answer::Once;
        let r = c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "test"]));
        assert_eq!(r["ok"], true);
        assert_eq!(r["vars"][0], json!({ "name": "TOKEN", "value": "s3cret" }));
        // The popup shows the command and the names, never a value.
        let prompts = ui.secret_prompts.lock().unwrap();
        let shown = serde_json::to_string(&prompts[1]).unwrap();
        assert!(!shown.contains("s3cret") && !shown.contains("https://x"), "{shown}");
        assert_eq!(prompts[1].names, vec!["API_URL".to_string(), "TOKEN".to_string()]);
        assert_eq!(prompts[1].command, vec!["npm".to_string(), "test".to_string()]);
        assert_eq!(prompts[1].exe, "/opt/pevv/pevv");
        assert_eq!(ui.asked.lock().unwrap()[0], (vec!["api".to_string()], vec![]));
        // The activity log gets the program name, never its arguments.
        assert_eq!(*ui.served.lock().unwrap(), vec![(Purpose::Run, "npm".to_string(), 2)]);
    }

    #[test]
    fn eight_hour_allowance_is_bound_to_the_exact_command_and_expires() {
        let ui = FakeUi::new();
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let c = Cli::with_clock(CliStore::memory(), ui.clone(), {
            let k = clock.clone();
            Box::new(move || k.load(Ordering::SeqCst))
        });
        let p = peer("aa");
        *ui.answer.lock().unwrap() = Answer::For8h;
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "test"]))["ok"], true);
        assert_eq!(ui.secret_prompts.lock().unwrap().len(), 1);
        assert_eq!(c.allowed().len(), 1);
        assert_eq!(c.allowed()[0].label, "npm test");

        // Same command: no prompt. A different one: prompt.
        *ui.answer.lock().unwrap() = Answer::Deny;
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "test"]))["ok"], true);
        assert_eq!(ui.secret_prompts.lock().unwrap().len(), 1);
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "publish"]))["error"], "request-denied");
        assert_eq!(ui.secret_prompts.lock().unwrap().len(), 2);
        // A different caller path, a different variable set: prompt.
        let other = Peer { exe: "/tmp/pevv".into(), ..peer("aa") };
        assert_eq!(c.handle(Some(&other), &secrets(Purpose::Run, &["npm", "test"]))["error"], "request-denied");
        ui.vars.lock().unwrap().as_mut().unwrap().vars.push(Var { name: "NEW".into(), value: "1".into() });
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "test"]))["error"], "request-denied");
        ui.vars.lock().unwrap().as_mut().unwrap().vars.pop();

        // Just before it ends, and just after.
        clock.store(1_000_000 + ALLOW_MS - 1, Ordering::SeqCst);
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "test"]))["ok"], true);
        clock.store(1_000_000 + ALLOW_MS, Ordering::SeqCst);
        assert!(c.allowed().is_empty());
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["npm", "test"]))["error"], "request-denied");
    }

    #[test]
    fn env_always_asks_and_never_gets_an_allowance() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        let p = peer("aa");
        *ui.answer.lock().unwrap() = Answer::For8h;
        for _ in 0..2 {
            assert_eq!(c.handle(Some(&p), &secrets(Purpose::Env, &[]))["ok"], true);
        }
        assert_eq!(ui.secret_prompts.lock().unwrap().len(), 2);
        assert!(c.allowed().is_empty());
        assert_eq!(ui.secret_prompts.lock().unwrap()[0].format, Some(Format::Dotenv));
    }

    #[test]
    fn revoking_a_client_or_a_command_takes_effect() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        let p = peer("aa");
        *ui.answer.lock().unwrap() = Answer::For8h;
        c.handle(Some(&p), &secrets(Purpose::Run, &["x"]));
        let key = c.allowed()[0].key.clone();
        c.revoke_command(&key).unwrap();
        assert!(c.allowed().is_empty());
        *ui.answer.lock().unwrap() = Answer::Deny;
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["x"]))["error"], "request-denied");
        c.revoke_client("/opt/pevv/pevv").unwrap();
        assert!(c.approved().is_empty());
        c.handle(Some(&p), &envelope(&CliRequest::Status));
        assert_eq!(ui.client_prompts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn bad_requests_never_reach_the_vault() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        let p = peer("aa");
        let bad = |projects: Vec<String>, command: Vec<String>, purpose, format| {
            envelope(&CliRequest::Secrets { purpose, projects, envs: vec![], command, cwd: String::new(), format })
        };
        assert_eq!(c.handle(Some(&p), &bad(vec!["a b".into()], vec!["x".into()], Purpose::Run, None))["error"], "bad-request");
        assert_eq!(c.handle(Some(&p), &bad(vec![], vec![], Purpose::Run, None))["error"], "bad-request");
        assert_eq!(c.handle(Some(&p), &bad(vec![], vec![], Purpose::Env, None))["error"], "bad-request");
        assert_eq!(c.handle(Some(&p), &bad((0..=MAX_NAMES).map(|i| format!("p{i}")).collect(), vec!["x".into()], Purpose::Run, None))["error"], "bad-request");
        assert!(ui.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn vault_errors_and_empty_sets_are_passed_back_without_a_prompt() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        let p = peer("aa");
        *ui.vars.lock().unwrap() = Err("no-such-env".into());
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["x"]))["error"], "no-such-env");
        *ui.vars.lock().unwrap() = Ok(VaultEnv { vars: vec![], sources: vec![] });
        assert_eq!(c.handle(Some(&p), &secrets(Purpose::Run, &["x"]))["error"], "no-vars");
        assert!(ui.secret_prompts.lock().unwrap().is_empty());
    }

    #[test]
    fn one_question_at_a_time() {
        let ui = FakeUi::new();
        let c = cli(&ui);
        c.asking.store(true, Ordering::SeqCst);
        assert_eq!(c.handle(Some(&peer("aa")), &envelope(&CliRequest::Status))["error"], "busy");
        assert_eq!(ui.client_prompts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn approvals_and_allowances_persist_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let ui = FakeUi::new();
        let c = Cli::new(CliStore::open(dir.path()), ui.clone());
        *ui.answer.lock().unwrap() = Answer::For8h;
        assert_eq!(c.handle(Some(&peer("aa")), &secrets(Purpose::Run, &["npm", "test"]))["ok"], true);
        let again = Cli::new(CliStore::open(dir.path()), ui.clone());
        assert_eq!(again.approved().len(), 1);
        assert_eq!(again.allowed().len(), 1);
        let text = std::fs::read_to_string(dir.path().join("cli-access.json")).unwrap();
        assert!(!text.contains("s3cret") && !text.contains("TOKEN"), "{text}");
        // An approved path is not asked about again after a restart.
        let before = ui.client_prompts.load(Ordering::SeqCst);
        again.handle(Some(&peer("aa")), &envelope(&CliRequest::Status));
        assert_eq!(ui.client_prompts.load(Ordering::SeqCst), before);
    }

    #[test]
    fn this_process_can_be_identified_by_its_pid() {
        let p = peer_of_pid(std::process::id()).expect("own exe");
        let me = std::env::current_exe().unwrap();
        assert!(
            same_path(&p.exe, &me.to_string_lossy()) || std::fs::canonicalize(&p.exe).ok() == std::fs::canonicalize(&me).ok(),
            "{} vs {}",
            p.exe,
            me.display()
        );
        assert_eq!(p.sha256, sha256_file(&me).unwrap());
        assert!(peer_of_pid(u32::MAX - 1).is_none());
    }

    #[test]
    fn file_hashes_change_with_the_contents() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x");
        std::fs::write(&f, b"one").unwrap();
        let a = sha256_file(&f).unwrap();
        assert_eq!(a.len(), 64);
        std::fs::write(&f, b"two").unwrap();
        assert_ne!(a, sha256_file(&f).unwrap());
    }
}
