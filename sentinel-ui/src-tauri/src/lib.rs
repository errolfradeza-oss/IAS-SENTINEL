mod scanner;
mod quarantine;
mod exclusions;
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(scanner::ScanState::default())
        .invoke_handler(tauri::generate_handler![
            scanner::start_scan,
            scanner::cancel_scan,
            quarantine::quarantine_threat,
            quarantine::delete_detected_file,
            quarantine::list_quarantine,
            quarantine::restore_quarantine,
            quarantine::delete_quarantine,
            quarantine::delete_all_quarantine,
            quarantine::list_history,
            quarantine::clear_history,
            exclusions::list_exclusions,
            exclusions::add_exclusion,
            exclusions::remove_exclusion
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
