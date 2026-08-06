//! IsaHat desktop shell.
//!
//! The Rust side is intentionally thin: all audit logic lives in the Python
//! core, reached through the local bridge (`isahat serve`). The shell only
//! renders the React UI and enforces a loopback-only CSP.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running IsaHat desktop");
}
