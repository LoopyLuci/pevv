// Release builds on Windows are a GUI app: no console window.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Installer hooks: write / remove the browser registration, then exit without a window.
    if let Some(flag) = std::env::args().nth(1).filter(|a| a.starts_with("--") && a.ends_with("-link")) {
        if pevv_desktop_lib::run_link_cli(&flag) {
            return;
        }
    }
    if let Some(flag) = std::env::args().nth(1).filter(|a| a == "--add-path" || a == "--remove-path") {
        if pevv_desktop_lib::run_path_cli(&flag) {
            return;
        }
    }
    pevv_desktop_lib::run();
}
