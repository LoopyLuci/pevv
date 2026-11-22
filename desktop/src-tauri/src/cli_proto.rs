//! What the `pevv` command-line tool and the desktop app say to each other, and the parts of the
//! tool that need no I/O: argument parsing, the `env` output formats, and the rule for merging
//! the vault's variables into a child's environment. No Tauri, so the `pevv` binary
//! (which `#[path]`-includes this file) stays small and everything runs under unit tests.
//!
//! Wire: the same private local channel and framing as the browser link (`link_ipc`,
//! `link_proto::{read_frame,write_frame}`), with `"client": "cli"` in the request. The app, not the
//! tool, decides who is calling: it asks the OS for the client's process id and reads that
//! process's executable path, so nothing the tool says about itself is trusted.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ffi::OsString;

pub const CLIENT_KIND: &str = "cli";
pub const CLI_VERSION: u64 = 1;

/// Exit codes of `pevv` itself. A wrapped command's own exit code is passed through unchanged, so
/// these can collide with it; scripts that care use `pevv status` first.
pub const EXIT_FAIL: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_NO_APP: i32 = 3;
pub const EXIT_LOCKED: i32 = 4;
pub const EXIT_DENIED: i32 = 5;

pub const MAX_NAMES: usize = 16;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_ARGS: usize = 256;
pub const MAX_ARGV_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Dotenv,
    Json,
    Sh,
    Ps,
}

impl Format {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "dotenv" => Some(Self::Dotenv),
            "json" => Some(Self::Json),
            "sh" => Some(Self::Sh),
            "ps" => Some(Self::Ps),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Dotenv => "dotenv",
            Self::Json => "json",
            Self::Sh => "sh",
            Self::Ps => "ps",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    Run { projects: Vec<String>, envs: Vec<String>, argv: Vec<String> },
    Env { projects: Vec<String>, envs: Vec<String>, format: Format },
    Status,
    Lock,
    Help,
}

pub const USAGE: &str = "\
pevv: use the secrets in your PEVV vault from the command line (the PEVV app must be running and unlocked)

  pevv run [--project NAME | --env ENV]... -- <command> [args]
        run a command with the vault's environment variables added; its exit code is passed through
  pevv env [--project NAME | --env ENV]... --format dotenv|json|sh|ps
        print the variables to stdout (the app asks you first, every time)
  pevv status        locked or unlocked (exit code 0 unlocked, 4 locked)
  pevv lock          lock the vault now

With no --project / --env the active environment is used. --project NAME uses the environment
linked to that project in PEVV (else the active one); --env ENV names an environment directly.
Secrets are never printed by `run`. Exit codes of pevv itself: 2 usage, 3 app not running,
4 locked, 5 denied by you in the app.";

/// A usage error (the message is safe to print).
#[derive(Debug, PartialEq, Eq)]
pub struct Usage(pub String);

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_NAME_LEN && s.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

/// Parse everything after the program name.
pub fn parse_args(args: &[String]) -> Result<Cmd, Usage> {
    let Some(first) = args.first() else { return Ok(Cmd::Help) };
    let rest = &args[1..];
    match first.as_str() {
        "help" | "--help" | "-h" => Ok(Cmd::Help),
        "status" if rest.is_empty() => Ok(Cmd::Status),
        "lock" if rest.is_empty() => Ok(Cmd::Lock),
        "status" | "lock" => Err(Usage(format!("`pevv {first}` takes no arguments"))),
        "run" | "env" => {
            let mut projects = Vec::new();
            let mut envs = Vec::new();
            let mut format = None;
            let mut i = 0;
            let mut argv = None;
            while i < rest.len() {
                let a = rest[i].as_str();
                // `--flag=value` and `--flag value` both work.
                let (flag, inline) = match a.split_once('=') {
                    Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
                    _ => (a, None),
                };
                if flag == "--" {
                    argv = Some(rest[i + 1..].to_vec());
                    break;
                }
                let mut value = |what: &str| -> Result<String, Usage> {
                    if let Some(v) = inline.clone() {
                        return Ok(v);
                    }
                    i += 1;
                    rest.get(i).cloned().ok_or_else(|| Usage(format!("{flag} needs {what}")))
                };
                match flag {
                    "--project" | "-p" => {
                        let v = value("a project name")?;
                        if !name_ok(&v) {
                            return Err(Usage(format!("bad project name: {v}")));
                        }
                        if !projects.contains(&v) {
                            projects.push(v);
                        }
                    }
                    "--env" | "-e" => {
                        let v = value("an environment name")?;
                        if !name_ok(&v) {
                            return Err(Usage(format!("bad environment name: {v}")));
                        }
                        if !envs.contains(&v) {
                            envs.push(v);
                        }
                    }
                    "--format" | "-f" if first == "env" => {
                        let v = value("a format")?;
                        format = Some(Format::parse(&v).ok_or_else(|| Usage(format!("unknown format {v} (use dotenv, json, sh or ps)")))?);
                    }
                    other => return Err(Usage(format!("unknown option {other} for `pevv {first}`"))),
                }
                i += 1;
            }
            if projects.len() + envs.len() > MAX_NAMES {
                return Err(Usage("too many --project / --env options".into()));
            }
            if first == "run" {
                let argv = argv.ok_or_else(|| Usage("`pevv run` needs `--` before the command, e.g. pevv run --project api -- npm test".into()))?;
                if argv.is_empty() {
                    return Err(Usage("no command after `--`".into()));
                }
                if argv.len() > MAX_ARGS || argv.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES {
                    return Err(Usage("the command line is too long".into()));
                }
                Ok(Cmd::Run { projects, envs, argv })
            } else {
                if argv.is_some() {
                    return Err(Usage("`pevv env` does not run a command; use `pevv run`".into()));
                }
                let format = format.ok_or_else(|| Usage("`pevv env` needs --format dotenv|json|sh|ps".into()))?;
                Ok(Cmd::Env { projects, envs, format })
            }
        }
        other => Err(Usage(format!("unknown command {other} (try `pevv help`)"))),
    }
}

/* ───────────── wire messages ───────────── */

/// What the tool asks the app for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CliRequest {
    Status,
    Lock,
    Secrets {
        purpose: Purpose,
        #[serde(default)]
        projects: Vec<String>,
        #[serde(default)]
        envs: Vec<String>,
        /// `run`: the command line, for the person to read in the approval.
        #[serde(default)]
        command: Vec<String>,
        #[serde(default)]
        cwd: String,
        /// `env`: how the tool will print them.
        #[serde(default)]
        format: Option<Format>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    Run,
    Env,
}

/// The envelope that marks a frame as the CLI's (the browser link's frames carry `origin` instead).
pub fn envelope(req: &CliRequest) -> Value {
    let mut v = serde_json::to_value(req).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert("client".into(), json!(CLIENT_KIND));
        o.insert("v".into(), json!(CLI_VERSION));
    }
    v
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Var {
    pub name: String,
    pub value: String,
}

/// The `ENV_NAME` rule of the vault (`src/pevv/model.ts`).
pub fn valid_var_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(f) if f.is_ascii_alphabetic() || f == '_') && c.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Plain text for the error codes the app answers with.
pub fn explain(code: &str) -> &'static str {
    match code {
        "locked" => "PEVV is locked. Unlock it in the app, then try again.",
        "client-denied" => "You did not allow this program to use PEVV.",
        "request-denied" => "You declined the request in PEVV.",
        "busy" => "PEVV is already asking about another request.",
        "peer-unknown" => "PEVV could not tell which program is calling.",
        "no-such-env" => "That environment does not exist in the vault.",
        "no-vars" => "There are no variables in that environment.",
        "app-busy" => "PEVV did not answer in time.",
        "unsupported-version" => "This pevv is not the same version as the app. Update both.",
        "bad-request" => "PEVV did not understand the request.",
        _ => "PEVV could not do that.",
    }
}

pub fn exit_code_for(code: &str) -> i32 {
    match code {
        "locked" => EXIT_LOCKED,
        "client-denied" | "request-denied" => EXIT_DENIED,
        _ => EXIT_FAIL,
    }
}

/* ───────────── env output formats ───────────── */

fn dotenv_value(v: &str) -> String {
    let plain = !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_./:@+-".contains(&b));
    if plain || v.is_empty() {
        return v.to_string();
    }
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r"))
}

/// The variables in `format`. Names that are not valid variable names are skipped (the caller warns).
pub fn render(vars: &[Var], format: Format) -> String {
    let ok: Vec<&Var> = vars.iter().filter(|v| valid_var_name(&v.name)).collect();
    match format {
        Format::Dotenv => ok.iter().map(|v| format!("{}={}\n", v.name, dotenv_value(&v.value))).collect(),
        Format::Json => {
            let mut m = serde_json::Map::new();
            for v in ok {
                m.insert(v.name.clone(), Value::String(v.value.clone()));
            }
            format!("{}\n", serde_json::to_string_pretty(&Value::Object(m)).unwrap_or_else(|_| "{}".into()))
        }
        Format::Sh => ok.iter().map(|v| format!("export {}='{}'\n", v.name, v.value.replace('\'', "'\\''"))).collect(),
        Format::Ps => ok.iter().map(|v| format!("$env:{} = '{}'\n", v.name, v.value.replace('\'', "''"))).collect(),
    }
}

/* ───────────── child environment ───────────── */

pub struct Merged {
    /// The child's whole environment: the parent's, with the vault's variables on top.
    pub env: Vec<(OsString, OsString)>,
    /// Names the vault replaced (they were already set in the parent). Names only, never values.
    pub overridden: Vec<String>,
}

fn same_name(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    // Windows environment names are case-insensitive.
    if cfg!(windows) {
        a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

/// Child env = parent env + vault vars; the vault wins, and each replaced name is reported.
pub fn merge_env(parent: impl IntoIterator<Item = (OsString, OsString)>, vault: &[Var]) -> Merged {
    let mut env: Vec<(OsString, OsString)> = parent.into_iter().collect();
    let mut overridden = BTreeSet::new();
    for v in vault.iter().filter(|v| valid_var_name(&v.name) && !v.value.contains('\0')) {
        let name = OsString::from(&v.name);
        if let Some(slot) = env.iter_mut().find(|(k, _)| same_name(k, &name)) {
            if slot.1 != OsString::from(&v.value) {
                overridden.insert(v.name.clone());
            }
            *slot = (name, OsString::from(&v.value));
        } else {
            env.push((name, OsString::from(&v.value)));
        }
    }
    Merged { env, overridden: overridden.into_iter().collect() }
}

/// Run `argv` with exactly `env`, inheriting stdio, and return its exit code (128 + signal on Unix).
pub fn run_child(argv: &[String], env: Vec<(OsString, OsString)>) -> std::io::Result<i32> {
    let (prog, args) = argv.split_first().ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut cmd = std::process::Command::new(prog);
    cmd.args(args).env_clear().envs(env);
    let status = cmd.status()?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(128 + sig);
        }
    }
    Ok(status.code().unwrap_or(EXIT_FAIL))
}

/* ───────────── the tool, minus process-level plumbing ───────────── */

/// What `execute` needs from the process around it (so tests can supply their own).
pub struct Io<'a> {
    pub out: &'a mut dyn std::io::Write,
    pub err: &'a mut dyn std::io::Write,
    pub parent_env: Vec<(OsString, OsString)>,
    pub cwd: String,
}

fn exchange<C: std::io::Read + std::io::Write>(conn: &mut C, req: &CliRequest) -> Result<Value, String> {
    let body = serde_json::to_vec(&envelope(req)).map_err(|e| e.to_string())?;
    crate::link_proto::write_frame(conn, &body).map_err(|e| format!("could not talk to PEVV: {e}"))?;
    let frame =
        crate::link_proto::read_frame(conn).map_err(|e| format!("could not talk to PEVV: {e}"))?.ok_or_else(|| "PEVV closed the connection".to_string())?;
    serde_json::from_slice(&frame).map_err(|_| "PEVV sent something this pevv does not understand".to_string())
}

/// Carry out one command over an open connection to the app. Returns the process exit code.
/// Secrets are written only by `env`, to `io.out`; nothing else ever prints a value.
pub fn execute<C: std::io::Read + std::io::Write>(cmd: &Cmd, conn: &mut C, io: &mut Io) -> i32 {
    let say = |io: &mut Io, msg: &str| {
        let _ = writeln!(io.err, "pevv: {msg}");
    };
    let req = match cmd {
        Cmd::Help => {
            let _ = writeln!(io.out, "{USAGE}");
            return 0;
        }
        Cmd::Status => CliRequest::Status,
        Cmd::Lock => CliRequest::Lock,
        Cmd::Run { projects, envs, argv } => CliRequest::Secrets {
            purpose: Purpose::Run,
            projects: projects.clone(),
            envs: envs.clone(),
            command: argv.clone(),
            cwd: io.cwd.clone(),
            format: None,
        },
        Cmd::Env { projects, envs, format } => CliRequest::Secrets {
            purpose: Purpose::Env,
            projects: projects.clone(),
            envs: envs.clone(),
            command: Vec::new(),
            cwd: io.cwd.clone(),
            format: Some(*format),
        },
    };
    let reply = match exchange(conn, &req) {
        Ok(r) => r,
        Err(m) => {
            say(io, &m);
            return EXIT_FAIL;
        }
    };
    if reply.get("ok").and_then(Value::as_bool) != Some(true) {
        let code = reply.get("error").and_then(Value::as_str).unwrap_or("failed");
        say(io, explain(code));
        return exit_code_for(code);
    }
    match cmd {
        Cmd::Status | Cmd::Lock => {
            let locked = reply.get("locked").and_then(Value::as_bool).unwrap_or(true);
            let _ = writeln!(io.out, "{}", if locked { "locked" } else { "unlocked" });
            if locked && matches!(cmd, Cmd::Status) {
                EXIT_LOCKED
            } else {
                0
            }
        }
        Cmd::Run { .. } | Cmd::Env { .. } if reply.get("vars").is_none() => {
            say(io, explain("failed"));
            EXIT_FAIL
        }
        Cmd::Run { argv, .. } => {
            let vars: Vec<Var> = serde_json::from_value(reply["vars"].clone()).unwrap_or_default();
            let merged = merge_env(std::mem::take(&mut io.parent_env), &vars);
            if !merged.overridden.is_empty() {
                say(io, &format!("warning: the vault replaced existing variable(s): {}", merged.overridden.join(", ")));
            }
            match run_child(argv, merged.env) {
                Ok(code) => code,
                Err(e) => {
                    // The OS error mentions the program, never the environment.
                    say(io, &format!("cannot run {}: {e}", argv[0]));
                    EXIT_FAIL
                }
            }
        }
        Cmd::Env { format, .. } => {
            let vars: Vec<Var> = serde_json::from_value(reply["vars"].clone()).unwrap_or_default();
            let skipped: Vec<&str> = vars.iter().filter(|v| !valid_var_name(&v.name)).map(|v| v.name.as_str()).collect();
            if !skipped.is_empty() {
                say(io, &format!("warning: skipped variable(s) that are not valid names: {}", skipped.join(", ")));
            }
            let _ = io.out.write_all(render(&vars, *format).as_bytes());
            let _ = io.out.flush();
            0
        }
        Cmd::Help => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn a(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn var(n: &str, v: &str) -> Var {
        Var { name: n.into(), value: v.into() }
    }

    #[test]
    fn parses_run_with_projects_envs_and_the_command() {
        let c = parse_args(&a(&["run", "--project", "api", "--env=prod", "-p", "web", "--", "npm", "test", "--", "-x"])).unwrap();
        assert_eq!(c, Cmd::Run { projects: a(&["api", "web"]), envs: a(&["prod"]), argv: a(&["npm", "test", "--", "-x"]) });
        // Options after `--` belong to the command.
        let c = parse_args(&a(&["run", "--", "ls", "--project", "x"])).unwrap();
        assert_eq!(c, Cmd::Run { projects: vec![], envs: vec![], argv: a(&["ls", "--project", "x"]) });
        // Repeats collapse.
        let Cmd::Run { projects, .. } = parse_args(&a(&["run", "-p", "a", "-p", "a", "--", "x"])).unwrap() else { panic!() };
        assert_eq!(projects, a(&["a"]));
    }

    #[test]
    fn run_needs_a_command_after_the_double_dash() {
        assert!(parse_args(&a(&["run", "--project", "a"])).is_err());
        assert!(parse_args(&a(&["run", "--"])).is_err());
        assert!(parse_args(&a(&["run", "npm", "test"])).is_err(), "the command must follow --");
        assert!(parse_args(&a(&["run", "--project"])).is_err());
        assert!(parse_args(&a(&["run", "--bogus", "--", "x"])).is_err());
        assert!(parse_args(&a(&["run", "--project", "a b", "--", "x"])).is_err());
        assert!(parse_args(&a(&["run", "--format", "json", "--", "x"])).is_err(), "--format is for env");
    }

    #[test]
    fn parses_env_status_lock_help() {
        assert_eq!(
            parse_args(&a(&["env", "--project", "api", "--format", "dotenv"])).unwrap(),
            Cmd::Env { projects: a(&["api"]), envs: vec![], format: Format::Dotenv }
        );
        assert_eq!(parse_args(&a(&["env", "--format=PS"])).unwrap(), Cmd::Env { projects: vec![], envs: vec![], format: Format::Ps });
        assert!(parse_args(&a(&["env"])).is_err());
        assert!(parse_args(&a(&["env", "--format", "yaml"])).is_err());
        assert!(parse_args(&a(&["env", "--format", "sh", "--", "ls"])).is_err());
        assert_eq!(parse_args(&a(&["status"])).unwrap(), Cmd::Status);
        assert_eq!(parse_args(&a(&["lock"])).unwrap(), Cmd::Lock);
        assert!(parse_args(&a(&["lock", "now"])).is_err());
        assert_eq!(parse_args(&[]).unwrap(), Cmd::Help);
        assert_eq!(parse_args(&a(&["--help"])).unwrap(), Cmd::Help);
        assert!(parse_args(&a(&["frobnicate"])).is_err());
    }

    #[test]
    fn limits_are_enforced() {
        let many: Vec<String> = (0..=MAX_NAMES).flat_map(|i| ["-e".to_string(), format!("e{i}")]).collect();
        let mut args = vec!["run".to_string()];
        args.extend(many);
        args.extend(a(&["--", "x"]));
        assert!(parse_args(&args).is_err());
        let long = vec!["x".repeat(MAX_ARGV_BYTES + 1)];
        let mut args = a(&["run", "--"]);
        args.extend(long);
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn requests_carry_the_client_kind_and_round_trip() {
        let req =
            CliRequest::Secrets { purpose: Purpose::Run, projects: a(&["api"]), envs: vec![], command: a(&["npm", "test"]), cwd: "/w".into(), format: None };
        let v = envelope(&req);
        assert_eq!(v["client"], "cli");
        assert_eq!(v["type"], "secrets");
        assert_eq!(v["purpose"], "run");
        assert_eq!(serde_json::from_value::<CliRequest>(v).unwrap(), req);
        assert_eq!(envelope(&CliRequest::Status)["type"], "status");
        let e = serde_json::from_value::<CliRequest>(json!({ "type": "secrets", "purpose": "env", "format": "json" })).unwrap();
        assert_eq!(
            e,
            CliRequest::Secrets { purpose: Purpose::Env, projects: vec![], envs: vec![], command: vec![], cwd: String::new(), format: Some(Format::Json) }
        );
        assert!(serde_json::from_value::<CliRequest>(json!({ "type": "secrets", "purpose": "steal" })).is_err());
        assert!(serde_json::from_value::<CliRequest>(json!({ "type": "nope" })).is_err());
    }

    #[test]
    fn formats_quote_what_needs_quoting() {
        let vars = [var("A", "plain-1.2"), var("B", "it's \"x\" $HOME\nnext"), var("bad name", "x"), var("EMPTY", "")];
        assert_eq!(render(&vars, Format::Dotenv), "A=plain-1.2\nB=\"it's \\\"x\\\" $HOME\\nnext\"\nEMPTY=\n");
        assert_eq!(render(&vars, Format::Sh), "export A='plain-1.2'\nexport B='it'\\''s \"x\" $HOME\nnext'\nexport EMPTY=''\n");
        assert_eq!(render(&vars, Format::Ps), "$env:A = 'plain-1.2'\n$env:B = 'it''s \"x\" $HOME\nnext'\n$env:EMPTY = ''\n");
        let j: Value = serde_json::from_str(&render(&vars, Format::Json)).unwrap();
        assert_eq!(j["B"], "it's \"x\" $HOME\nnext");
        assert!(j.get("bad name").is_none());
        assert_eq!(render(&[], Format::Json).trim(), "{}");
    }

    #[test]
    fn the_vault_wins_over_the_parent_and_overrides_are_reported() {
        let parent = vec![
            (OsString::from("PATH"), OsString::from("/bin")),
            (OsString::from("TOKEN"), OsString::from("old")),
            (OsString::from("SAME"), OsString::from("v")),
        ];
        let m = merge_env(parent, &[var("TOKEN", "new"), var("FRESH", "1"), var("SAME", "v"), var("bad-name", "x"), var("NUL", "a\0b")]);
        let get = |k: &str| m.env.iter().find(|(n, _)| n == k).map(|(_, v)| v.to_string_lossy().into_owned());
        assert_eq!(get("PATH").as_deref(), Some("/bin"), "the parent's own variables stay");
        assert_eq!(get("TOKEN").as_deref(), Some("new"), "the vault wins");
        assert_eq!(get("FRESH").as_deref(), Some("1"));
        assert_eq!(get("bad-name"), None);
        assert_eq!(get("NUL"), None);
        assert_eq!(m.overridden, a(&["TOKEN"]), "only a changed value counts as an override, and only the name is reported");
        assert_eq!(m.env.len(), 4);
    }

    #[test]
    fn a_later_vault_value_replaces_an_earlier_one() {
        let m = merge_env(Vec::new(), &[var("K", "1"), var("K", "2")]);
        assert_eq!(m.env, vec![(OsString::from("K"), OsString::from("2"))]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_names_are_case_insensitive() {
        let m = merge_env(vec![(OsString::from("Path"), OsString::from("a"))], &[var("PATH", "b")]);
        assert_eq!(m.env.len(), 1);
        assert_eq!(m.overridden, a(&["PATH"]));
    }

    fn shell(code: i32) -> Vec<String> {
        if cfg!(windows) {
            a(&["cmd", "/C", &format!("exit {code}")])
        } else {
            a(&["sh", "-c", &format!("exit {code}")])
        }
    }

    fn base_env() -> Vec<(OsString, OsString)> {
        std::env::vars_os()
            .filter(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("PATH") || k.to_string_lossy().eq_ignore_ascii_case("SystemRoot"))
            .collect()
    }

    #[test]
    fn the_childs_exit_code_passes_through_and_it_sees_the_vault_vars() {
        assert_eq!(run_child(&shell(0), base_env()).unwrap(), 0);
        assert_eq!(run_child(&shell(7), base_env()).unwrap(), 7);
        let probe = if cfg!(windows) {
            a(&["cmd", "/C", "if \"%PEVV_T%\"==\"seen\" (exit 9) else (exit 1)"])
        } else {
            a(&["sh", "-c", "[ \"$PEVV_T\" = seen ] && exit 9 || exit 1"])
        };
        let m = merge_env(base_env(), &[var("PEVV_T", "seen")]);
        assert_eq!(run_child(&probe, m.env).unwrap(), 9);
        assert!(run_child(&a(&["pevv-no-such-program-xyz"]), base_env()).is_err());
    }

    /// A connection whose replies are canned: reads come from `input`, writes are kept.
    struct Canned {
        input: std::io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }
    impl std::io::Read for Canned {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Canned {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.sent.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn canned(reply: Value) -> Canned {
        let mut input = Vec::new();
        crate::link_proto::write_frame(&mut input, &serde_json::to_vec(&reply).unwrap()).unwrap();
        Canned { input: std::io::Cursor::new(input), sent: Vec::new() }
    }

    fn sent_request(c: &Canned) -> Value {
        serde_json::from_slice(&crate::link_proto::read_frame(&mut std::io::Cursor::new(c.sent.clone())).unwrap().unwrap()).unwrap()
    }

    fn go(cmd: &Cmd, reply: Value) -> (i32, String, String, Value) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut c = canned(reply);
        let code = execute(cmd, &mut c, &mut Io { out: &mut out, err: &mut err, parent_env: base_env(), cwd: "/w".into() });
        (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap(), sent_request(&c))
    }

    #[test]
    fn run_asks_the_app_runs_the_child_and_never_prints_a_secret() {
        let probe = if cfg!(windows) {
            a(&["cmd", "/C", "if \"%PEVV_T%\"==\"hunter2\" (exit 11) else (exit 1)"])
        } else {
            a(&["sh", "-c", "[ \"$PEVV_T\" = hunter2 ] && exit 11 || exit 1"])
        };
        let cmd = Cmd::Run { projects: a(&["api"]), envs: vec![], argv: probe };
        let (code, out, err, req) = go(&cmd, json!({ "ok": true, "vars": [{ "name": "PEVV_T", "value": "hunter2" }] }));
        assert_eq!(code, 11, "the child saw the variable and its exit code came back");
        assert!(!out.contains("hunter2") && !err.contains("hunter2"));
        assert_eq!(req["client"], "cli");
        assert_eq!(req["purpose"], "run");
        assert_eq!(req["projects"][0], "api");
        assert_eq!(req["cwd"], "/w");
        assert_eq!(req["command"][0], cmd_first(&cmd));
    }

    fn cmd_first(c: &Cmd) -> String {
        match c {
            Cmd::Run { argv, .. } => argv[0].clone(),
            _ => String::new(),
        }
    }

    #[test]
    fn run_warns_by_name_when_the_vault_replaces_a_variable() {
        std::env::set_var("PEVV_PARENT_T", "from-parent");
        let cmd = Cmd::Run { projects: vec![], envs: vec![], argv: shell(0) };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut c = canned(json!({ "ok": true, "vars": [{ "name": "PEVV_PARENT_T", "value": "from-vault" }] }));
        let parent: Vec<_> = std::env::vars_os().collect();
        assert_eq!(execute(&cmd, &mut c, &mut Io { out: &mut out, err: &mut err, parent_env: parent, cwd: String::new() }), 0);
        let err = String::from_utf8(err).unwrap();
        assert!(err.contains("PEVV_PARENT_T") && !err.contains("from-vault") && !err.contains("from-parent"), "{err}");
    }

    #[test]
    fn env_prints_to_stdout_only_what_the_app_sent() {
        let cmd = Cmd::Env { projects: vec![], envs: a(&["prod"]), format: Format::Sh };
        let (code, out, err, req) = go(&cmd, json!({ "ok": true, "vars": [{ "name": "A", "value": "1" }, { "name": "no good", "value": "x" }] }));
        assert_eq!(
            (code, out.as_str()),
            (
                0,
                "export A='1'
"
            )
        );
        assert!(err.contains("no good"));
        assert_eq!((req["purpose"].as_str(), req["format"].as_str(), req["envs"][0].as_str()), (Some("env"), Some("sh"), Some("prod")));
    }

    #[test]
    fn refusals_print_a_plain_reason_and_no_secret() {
        let cmd = Cmd::Env { projects: vec![], envs: vec![], format: Format::Json };
        let (code, out, err, _) = go(&cmd, json!({ "ok": false, "error": "request-denied" }));
        assert_eq!((code, out.as_str()), (EXIT_DENIED, ""));
        assert!(err.starts_with("pevv: "));
        assert_eq!(go(&Cmd::Run { projects: vec![], envs: vec![], argv: shell(0) }, json!({ "ok": false, "error": "locked" })).0, EXIT_LOCKED);
        assert_eq!(go(&Cmd::Status, json!({ "ok": true, "locked": true })).0, EXIT_LOCKED);
        let (code, out, _, req) = go(&Cmd::Status, json!({ "ok": true, "locked": false }));
        assert_eq!(
            (code, out.as_str(), req["type"].as_str()),
            (
                0,
                "unlocked
",
                Some("status")
            )
        );
        assert_eq!(
            go(&Cmd::Lock, json!({ "ok": true, "locked": true })).1,
            "locked
"
        );
        // A reply without variables is a failure, not an empty run.
        assert_eq!(go(&Cmd::Env { projects: vec![], envs: vec![], format: Format::Sh }, json!({ "ok": true })).0, EXIT_FAIL);
    }

    #[test]
    fn a_child_that_cannot_start_is_reported_without_its_environment() {
        let cmd = Cmd::Run { projects: vec![], envs: vec![], argv: a(&["pevv-no-such-program-xyz"]) };
        let (code, out, err, _) = go(&cmd, json!({ "ok": true, "vars": [{ "name": "K", "value": "topsecret" }] }));
        assert_eq!(code, EXIT_FAIL);
        assert!(out.is_empty() && !err.contains("topsecret") && err.contains("pevv-no-such-program-xyz"));
    }

    #[test]
    fn explain_never_echoes_input() {
        for c in ["locked", "client-denied", "request-denied", "busy", "whatever"] {
            assert!(!explain(c).is_empty());
        }
        assert_eq!(exit_code_for("locked"), EXIT_LOCKED);
        assert_eq!(exit_code_for("request-denied"), EXIT_DENIED);
        assert_eq!(exit_code_for("other"), EXIT_FAIL);
    }
}
