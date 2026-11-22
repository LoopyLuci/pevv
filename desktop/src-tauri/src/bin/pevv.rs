//! `pevv`: use the secrets in your PEVV vault from a terminal or a script.
//!
//! It holds no secret and decides nothing. Each command is one request to the running, unlocked
//! PEVV app over the same private local channel the browser link uses; the app works out which
//! program is calling (from the OS, not from this tool), asks you to allow it, and asks you
//! again before any secret leaves the app. See `cli_proto.rs` for the commands and exit codes.
//!
//! `pevv run` never prints a secret. `pevv env` prints them to stdout, because that is what you asked for.

#[path = "../cli_proto.rs"]
mod cli_proto;
#[path = "../link_ipc.rs"]
mod link_ipc;
#[path = "../link_proto.rs"]
mod link_proto;

use cli_proto::{execute, parse_args, Cmd, Io, EXIT_NO_APP, EXIT_USAGE};
use std::io;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pevv: {}\n(try `pevv help`)", e.0);
            std::process::exit(EXIT_USAGE);
        }
    };
    if cmd == Cmd::Help {
        println!("{}", cli_proto::USAGE);
        return;
    }
    let (mut out, mut err) = (io::stdout(), io::stderr());
    let mut conn = match link_ipc::default_endpoint().and_then(|e| link_ipc::connect(&e)) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("pevv: the PEVV app is not running. Start it and unlock it, then try again.");
            std::process::exit(EXIT_NO_APP);
        }
        Err(e) => {
            eprintln!("pevv: cannot reach the PEVV app: {e}");
            std::process::exit(EXIT_NO_APP);
        }
    };
    let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let code = execute(&cmd, &mut conn, &mut Io { out: &mut out, err: &mut err, parent_env: std::env::vars_os().collect(), cwd });
    std::process::exit(code);
}
