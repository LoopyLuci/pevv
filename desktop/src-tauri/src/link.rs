//! Browser-extension link, Tauri side: the local IPC server, the prompts the person answers in
//! the app window, the hand-off of `match` / `fill` / `save-offer` to the unlocked vault UI, and
//! the host registration. Policy lives in `link_core` (and is tested there); this file is wiring.

use crate::cli_core::{peer_of_pid, Answer, Cli, CliStore, CliUi, SecretsPrompt, VaultEnv};
use crate::cli_proto::Purpose;
use crate::link_core::{Link, LinkStore, Ui};
use crate::link_ipc::{default_endpoint, Listener};
use crate::link_proto::allowed_extension_ids;
use crate::link_register::{self, current_os, Layout, RealSink};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};

/// The webview shows these (pairing approval) and answers with `link_prompt_answer`.
pub const EVENT_PROMPT: &str = "link-prompt";
/// A `match` / `fill` / `save-offer` for the vault UI; it answers with `link_respond`.
pub const EVENT_REQUEST: &str = "link-request";

/// A `pevv` approval (new program, or secrets for a command) for the webview to show; it answers with `cli_prompt_answer`.
pub const EVENT_CLI_PROMPT: &str = "cli-prompt";

/// `pevv` was given variables: the webview writes it to the activity log.
pub const EVENT_CLI_SERVED: &str = "cli-served";

const PAIR_TIMEOUT: Duration = Duration::from_secs(120);
const CLI_TIMEOUT: Duration = Duration::from_secs(120);
const VAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 16;

struct PairPrompt {
    ext: String,
    fingerprint: String,
    tx: SyncSender<bool>,
}

/// A `pevv` question waiting for the person. `view` is what the webview shows (no secret values).
struct CliPrompt {
    view: Value,
    tx: SyncSender<Answer>,
}

type VaultReply = Result<Value, String>;

pub struct TauriUi {
    app: AppHandle,
    unlocked: AtomicBool,
    next: AtomicU64,
    prompts: Mutex<HashMap<u64, PairPrompt>>,
    cli_prompts: Mutex<HashMap<u64, CliPrompt>>,
    waiters: Mutex<HashMap<u64, SyncSender<VaultReply>>>,
    show: Box<dyn Fn(&AppHandle) + Send + Sync>,
    lock: Box<dyn Fn(&AppHandle) + Send + Sync>,
}

impl TauriUi {
    pub fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }

    pub fn set_unlocked(&self, on: bool) {
        self.unlocked.store(on, Ordering::SeqCst);
    }
}

impl Ui for TauriUi {
    fn show_window(&self) {
        (self.show)(&self.app);
    }

    fn lock_now(&self) {
        self.set_unlocked(false);
        (self.lock)(&self.app);
    }

    fn unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }

    fn confirm_pair(&self, ext_id: &str, fingerprint: &str) -> bool {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = sync_channel(1);
        if let Ok(mut p) = self.prompts.lock() {
            p.insert(id, PairPrompt { ext: ext_id.to_string(), fingerprint: fingerprint.to_string(), tx });
        }
        let _ = self.app.emit(EVENT_PROMPT, json!({ "kind": "pair", "id": id, "extId": ext_id, "fingerprint": fingerprint }));
        let answer = rx.recv_timeout(PAIR_TIMEOUT).unwrap_or(false);
        if let Ok(mut p) = self.prompts.lock() {
            p.remove(&id);
        }
        let _ = self.app.emit(EVENT_PROMPT, json!({ "kind": "closed", "id": id }));
        answer
    }

    fn ask_vault(&self, kind: &str, body: &Value) -> VaultReply {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = sync_channel(1);
        self.waiters.lock().map_err(|_| "internal".to_string())?.insert(id, tx);
        let _ = self.app.emit(EVENT_REQUEST, json!({ "id": id, "kind": kind, "body": body }));
        let r = rx.recv_timeout(VAULT_TIMEOUT).unwrap_or_else(|_| Err("app-busy".to_string()));
        if let Ok(mut w) = self.waiters.lock() {
            w.remove(&id);
        }
        r
    }
}

impl TauriUi {
    /// Show a `pevv` question and wait for the answer (no answer in time = deny).
    fn ask_cli(&self, kind: &str, mut view: Value) -> Answer {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = sync_channel(1);
        if let Some(o) = view.as_object_mut() {
            o.insert("id".into(), json!(id));
            o.insert("kind".into(), json!(kind));
        }
        if let Ok(mut p) = self.cli_prompts.lock() {
            p.insert(id, CliPrompt { view: view.clone(), tx });
        }
        let _ = self.app.emit(EVENT_CLI_PROMPT, view);
        let answer = rx.recv_timeout(CLI_TIMEOUT).unwrap_or(Answer::Deny);
        if let Ok(mut p) = self.cli_prompts.lock() {
            p.remove(&id);
        }
        let _ = self.app.emit(EVENT_CLI_PROMPT, json!({ "kind": "closed", "id": id }));
        answer
    }
}

impl CliUi for TauriUi {
    fn show_window(&self) {
        Ui::show_window(self);
    }

    fn unlocked(&self) -> bool {
        Ui::unlocked(self)
    }

    fn lock_now(&self) {
        Ui::lock_now(self);
    }

    fn confirm_client(&self, exe: &str, changed: bool) -> bool {
        self.ask_cli("client", json!({ "exe": exe, "changed": changed })) != Answer::Deny
    }

    fn confirm_secrets(&self, p: &SecretsPrompt) -> Answer {
        self.ask_cli("secrets", serde_json::to_value(p).unwrap_or(Value::Null))
    }

    fn ask_vault_env(&self, projects: &[String], envs: &[String]) -> Result<VaultEnv, String> {
        let v = Ui::ask_vault(self, "cli-env", &json!({ "projects": projects, "envs": envs }))?;
        serde_json::from_value(v).map_err(|_| "failed".to_string())
    }

    fn served(&self, purpose: Purpose, program: &str, variables: usize) {
        let _ = self.app.emit(EVENT_CLI_SERVED, json!({ "purpose": purpose, "program": program, "variables": variables }));
    }
}

pub struct Runtime {
    pub link: Arc<Link>,
    pub cli: Arc<Cli>,
    pub ui: Arc<TauriUi>,
    data_dir: PathBuf,
    /// Why the IPC server is not running (e.g. the name is taken), if it is not.
    pub server_error: Mutex<Option<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptView {
    id: u64,
    ext_id: String,
    fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedView {
    ext_id: String,
    at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateView {
    enabled: bool,
    host_exists: bool,
    registered: Vec<&'static str>,
    paired: Vec<PairedView>,
    /// Why registration is not possible here ("appimage"), if it is not.
    unsupported: Option<&'static str>,
    server_error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliClientView {
    path: String,
    at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliCommandView {
    key: String,
    label: String,
    until: u64,
}

/// What `pevv` may do: programs allowed to call, and commands allowed for 8 hours.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliView {
    clients: Vec<CliClientView>,
    commands: Vec<CliCommandView>,
}

fn host_exe() -> PathBuf {
    let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default();
    dir.join(if cfg!(windows) { "pevv-native-host.exe" } else { "pevv-native-host" })
}

fn unsupported() -> Option<&'static str> {
    (cfg!(target_os = "linux") && std::env::var_os("APPIMAGE").is_some()).then_some("appimage")
}

fn config_home() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(x);
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")).unwrap_or_else(std::env::temp_dir)
}

fn layout(data_dir: &Path) -> Layout {
    // With PEVV_DATA_DIR nothing is registered with the user's real browsers: the Linux manifests go
    // under the override and the Windows registry entries under a private subtree.
    match crate::datadir::override_dir() {
        Some(d) => {
            Layout { os: current_os(), data_dir: data_dir.to_path_buf(), config_home: d.join("config"), reg_root: r"Software\Luciverse-PevvPortable".into() }
        }
        None => Layout { os: current_os(), data_dir: data_dir.to_path_buf(), config_home: config_home(), reg_root: "Software".into() },
    }
}

/// The app data folder without a running Tauri app (installer hooks). Same place `lib.rs::data_dir` uses.
pub fn env_data_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    };
    crate::datadir::data_dir(|| base.unwrap_or_else(std::env::temp_dir))
}

/// `--register-link` / `--unregister-link`, run by the installer. Registering respects an
/// earlier "off" in the app; unregistering always happens. Returns false for an unknown flag.
pub fn run_cli(flag: &str) -> bool {
    let dir = env_data_dir();
    match flag {
        "--register-link" => {
            if LinkStore::open(&dir).file.enabled && unsupported().is_none() && host_exe().exists() {
                let _ = link_register::register(&mut RealSink, &layout(&dir), &host_exe(), &allowed_extension_ids());
            }
            true
        }
        "--unregister-link" => {
            let _ = link_register::unregister(&mut RealSink, &layout(&dir));
            true
        }
        _ => false,
    }
}

impl Runtime {
    pub fn view(&self) -> StateView {
        let ids = allowed_extension_ids();
        let host = host_exe();
        StateView {
            enabled: self.link.enabled(),
            host_exists: host.exists(),
            registered: link_register::registered(&layout(&self.data_dir), &host, &ids),
            paired: self.link.paired().into_iter().map(|(ext_id, at)| PairedView { ext_id, at }).collect(),
            unsupported: unsupported(),
            server_error: self.server_error.lock().ok().and_then(|e| e.clone()),
        }
    }

    /// Bring the registration in line with the setting (also repairs a moved install).
    pub fn sync_registration(&self) {
        let (dir, host, ids) = (layout(&self.data_dir), host_exe(), allowed_extension_ids());
        if self.link.enabled() && unsupported().is_none() && host.exists() {
            if link_register::registered(&dir, &host, &ids).len()
                < link_register::BROWSERS.iter().filter(|b| cfg!(not(windows)) || !b.reg_key.is_empty()).count()
            {
                let _ = link_register::register(&mut RealSink, &dir, &host, &ids);
            }
        } else if !self.link.enabled() {
            let _ = link_register::unregister(&mut RealSink, &dir);
        }
    }

    pub fn set_enabled(&self, on: bool) -> Result<(), String> {
        self.link.set_enabled(on).map_err(|e| e.to_string())?;
        self.sync_registration();
        Ok(())
    }

    pub fn prompts(&self) -> Vec<PromptView> {
        self.ui
            .prompts
            .lock()
            .map(|p| p.iter().map(|(id, v)| PromptView { id: *id, ext_id: v.ext.clone(), fingerprint: v.fingerprint.clone() }).collect())
            .unwrap_or_default()
    }

    pub fn answer_prompt(&self, id: u64, approve: bool) {
        if let Some(p) = self.ui.prompts.lock().ok().and_then(|p| p.get(&id).map(|v| v.tx.clone())) {
            let _ = p.try_send(approve);
        }
    }

    pub fn cli_view(&self) -> CliView {
        CliView {
            clients: self.cli.approved().into_iter().map(|a| CliClientView { path: a.path, at: a.at }).collect(),
            commands: self.cli.allowed().into_iter().map(|c| CliCommandView { key: c.key, label: c.label, until: c.until }).collect(),
        }
    }

    pub fn cli_prompts(&self) -> Vec<Value> {
        self.ui.cli_prompts.lock().map(|p| p.values().map(|v| v.view.clone()).collect()).unwrap_or_default()
    }

    /// `answer`: "deny", "once" or "8h".
    pub fn cli_answer(&self, id: u64, answer: &str) {
        let a = match answer {
            "once" => Answer::Once,
            "8h" => Answer::For8h,
            _ => Answer::Deny,
        };
        if let Some(tx) = self.ui.cli_prompts.lock().ok().and_then(|p| p.get(&id).map(|v| v.tx.clone())) {
            let _ = tx.try_send(a);
        }
    }

    pub fn respond(&self, id: u64, result: VaultReply) {
        if let Some(tx) = self.ui.waiters.lock().ok().and_then(|w| w.get(&id).cloned()) {
            let _ = tx.try_send(result);
        }
    }
}

/// Build the runtime and start the IPC server on its own threads.
pub fn start(
    app: &AppHandle,
    data_dir: PathBuf,
    show: impl Fn(&AppHandle) + Send + Sync + 'static,
    lock: impl Fn(&AppHandle) + Send + Sync + 'static,
) -> Arc<Runtime> {
    let ui = Arc::new(TauriUi {
        app: app.clone(),
        unlocked: AtomicBool::new(false),
        next: AtomicU64::new(1),
        prompts: Mutex::new(HashMap::new()),
        cli_prompts: Mutex::new(HashMap::new()),
        waiters: Mutex::new(HashMap::new()),
        show: Box::new(show),
        lock: Box::new(lock),
    });
    let link = Link::new(LinkStore::open(&data_dir), ui.clone(), allowed_extension_ids());
    let cli = Cli::new(CliStore::open(&data_dir), ui.clone());
    link.set_cli(cli.clone());
    let rt = Arc::new(Runtime { link: link.clone(), cli, ui, data_dir, server_error: Mutex::new(None) });
    match default_endpoint().and_then(|e| Listener::bind(&e)) {
        Ok(mut listener) => {
            std::thread::spawn(move || {
                let open = Arc::new(AtomicUsize::new(0));
                while let Ok(mut conn) = listener.accept() {
                    if open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        open.fetch_sub(1, Ordering::SeqCst);
                        continue;
                    }
                    let (link, open) = (link.clone(), open.clone());
                    std::thread::spawn(move || {
                        // The OS names the caller; only a `pevv` frame makes this look it up.
                        let pid = conn.peer_pid().ok();
                        let _ = link.serve_peer(&mut conn, move || pid.and_then(peer_of_pid));
                        open.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
        }
        Err(e) => {
            if let Ok(mut s) = rt.server_error.lock() {
                *s = Some(e.to_string());
            }
        }
    }
    let r = rt.clone();
    std::thread::spawn(move || r.sync_registration());
    rt
}
