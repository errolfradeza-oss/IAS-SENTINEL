use std::{
    fs,
    path::{Path, PathBuf},
};

use tauri::{AppHandle, Manager};

fn exclusions_file(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?;

    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("exclusions.json"))
}

fn read_paths(app: &AppHandle) -> Result<Vec<String>, String> {
    let file = exclusions_file(app)?;

    if !file.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(file).map_err(|e| e.to_string())?;

    serde_json::from_str(&contents)
        .map_err(|e| format!("Could not read exclusions: {e}"))
}

fn write_paths(app: &AppHandle, paths: &[String]) -> Result<(), String> {
    let file = exclusions_file(app)?;
    let contents = serde_json::to_string_pretty(paths)
        .map_err(|e| e.to_string())?;

    fs::write(file, contents).map_err(|e| e.to_string())
}

fn normalize(path: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map_err(|e| format!("Cannot access this path: {e}"))
}

#[tauri::command]
pub fn list_exclusions(app: AppHandle) -> Result<Vec<String>, String> {
    read_paths(&app)
}

#[tauri::command]
pub fn add_exclusion(app: AppHandle, path: String) -> Result<Vec<String>, String> {
    let canonical = normalize(&path)?;
    let normalized = canonical.to_string_lossy().into_owned();
    let mut paths = read_paths(&app)?;

    // Avoid duplicate entries.
    if !paths.iter().any(|saved| {
        normalize(saved)
            .map(|existing| existing == canonical)
            .unwrap_or_else(|_| {
                Path::new(saved).to_string_lossy().eq_ignore_ascii_case(&normalized)
            })
    }) {
        paths.push(normalized);
        paths.sort_by_key(|p| p.to_lowercase());
        write_paths(&app, &paths)?;
    }

    Ok(paths)
}

#[tauri::command]
pub fn remove_exclusion(
    app: AppHandle,
    path: String,
) -> Result<Vec<String>, String> {
    let target = normalize(&path).ok();
    let mut paths = read_paths(&app)?;

    paths.retain(|saved| {
        if let (Some(target), Ok(existing)) = (&target, normalize(saved)) {
            existing != *target
        } else {
            !saved.eq_ignore_ascii_case(&path)
        }
    });

    write_paths(&app, &paths)?;
    Ok(paths)
}

/// Returns true if a path is itself excluded or is inside an excluded folder.
pub fn is_excluded(path: &Path, exclusions: &[PathBuf]) -> bool {
    exclusions.iter().any(|excluded| path.starts_with(excluded))
}

/// Loads canonical paths for the scanner.
pub fn load_excluded_paths(app: &AppHandle) -> Result<Vec<PathBuf>, String> {
    read_paths(app)?
        .iter()
        .map(|path| {
            fs::canonicalize(path)
                .map_err(|e| format!("Invalid saved exclusion '{}': {e}", path))
        })
        .collect()
}