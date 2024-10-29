use std::path::PathBuf;

use cerberus_store::create_database;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn init_store(path: String) -> Result<(), ()> {
    let mut filename = PathBuf::from(path);
    filename.push("store.sqlite3");

    let result = create_database(filename).await;

    // don't do this!
    match result {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            init_store
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
