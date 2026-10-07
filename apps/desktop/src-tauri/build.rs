fn main() {
    // Declare the in-app command so tauri-build emits the `allow-bridge-token`
    // permission. A capability that names that permission fails validation
    // unless the command is listed here. `tauri_build::build()` does not infer
    // it from `#[tauri::command]`.
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["bridge_token"])),
    )
    .expect("failed to run tauri-build");
}
