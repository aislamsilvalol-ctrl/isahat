//! IsaHat desktop shell.
//!
//! The Rust side is intentionally thin: all audit logic lives in the Python
//! core, reached through the local bridge (`isahat serve`). The shell renders
//! the React UI and reads the local bridge token so the webview can
//! authenticate. The token is returned to the webview only — it is never logged.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

fn data_dir() -> Result<PathBuf, String> {
    if let Ok(override_dir) = std::env::var("ISAHAT_HOME") {
        if !override_dir.is_empty() {
            return Ok(PathBuf::from(override_dir));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "home directory is not set; cannot locate the bridge token".to_string())?;
    Ok(PathBuf::from(home).join(".isahat"))
}

#[tauri::command]
fn bridge_token() -> Result<String, String> {
    let path = data_dir()?.join("bridge.token");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("bridge token file is not readable: {}", path.display()))?;
    let token = text.trim();
    if token.is_empty() {
        return Err(format!("bridge token file is empty: {}", path.display()));
    }
    Ok(token.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![bridge_token])
        .run(tauri::generate_context!())
        .expect("error while running IsaHat desktop");
}
