//! Sentinel quarantine and event history.

use std::{
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use uuid::Uuid;

// XOR only prevents accidental execution; it is not cryptographic encryption.
const XOR_KEY: u8 = 0xA5;
static LOCK: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub file_name: String,
    pub detection_name: String,
    pub severity: String,
    pub sha256: String,
    pub size: u64,
    pub date: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HistoryEvent {
    pub action: String,
    pub file_name: String,
    pub detection_name: String,
    pub severity: String,
    pub date: String,
}

fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn base_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_local_data_dir().map_err(|error| error.to_string())?;
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Ok(dir)
}

fn quarantine_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = base_dir(app)?.join("sentinel-quarantine");
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Ok(dir)
}

fn validate_id(id: &str) -> Result<(), String> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| "Invalid quarantine id.".to_string())
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|error| error.to_string())?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|error| {
        let _ = fs::remove_file(&tmp);
        error.to_string()
    })
}

fn xor_copy(src: &Path, dst: &Path, hash_input: bool) -> std::io::Result<String> {
    let mut input = File::open(src)?;
    let mut output = BufWriter::new(File::create(dst)?);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if hash_input {
            hasher.update(&buffer[..count]);
        }
        for byte in &mut buffer[..count] {
            *byte ^= XOR_KEY;
        }
        if !hash_input {
            hasher.update(&buffer[..count]);
        }
        output.write_all(&buffer[..count])?;
    }

    output.flush()?;
    output.get_ref().sync_all()?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn read_entry(dir: &Path, id: &str) -> Result<QuarantineEntry, String> {
    let bytes = fs::read(dir.join(format!("{id}.json")))
        .map_err(|_| "Quarantine item not found.".to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| format!("Corrupt quarantine record: {error}"))
}

fn remove_item_files(dir: &Path, id: &str) -> Result<(), String> {
    for extension in ["quar", "json"] {
        let path = dir.join(format!("{id}.{extension}"));
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn history_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(base_dir(app)?.join("history.json"))
}

fn read_history(app: &AppHandle) -> Vec<HistoryEvent> {
    history_path(app)
        .ok()
        .and_then(|path| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn log_event(app: &AppHandle, action: &str, entry: &QuarantineEntry) {
    let Ok(path) = history_path(app) else { return };
    let mut events = read_history(app);
    events.push(HistoryEvent {
        action: action.into(),
        file_name: entry.file_name.clone(),
        detection_name: entry.detection_name.clone(),
        severity: entry.severity.clone(),
        date: now(),
    });
    if events.len() > 500 {
        let excess = events.len() - 500;
        events.drain(0..excess);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(&events) {
        let _ = write_atomic(&path, &bytes);
    }
}

#[tauri::command(async)]
pub fn quarantine_threat(
    app: AppHandle,
    path: String,
    name: String,
    severity: String,
    sha256: Option<String>,
) -> Result<QuarantineEntry, String> {
    let _guard = lock();
    let qdir = quarantine_dir(&app)?;
    let src = PathBuf::from(&path);
    let canonical = fs::canonicalize(&src).map_err(|_| format!("File not found: {path}"))?;
    let canonical_qdir = fs::canonicalize(&qdir).unwrap_or(qdir.clone());

    if canonical.starts_with(&canonical_qdir) {
        return Err("File is already in quarantine.".into());
    }
    #[cfg(windows)]
    if let Ok(windows_dir) = std::env::var("WINDIR") {
        if let Ok(canonical_windows_dir) = fs::canonicalize(windows_dir) {
            if canonical.starts_with(canonical_windows_dir) {
                return Err("Refusing to quarantine files inside the Windows directory.".into());
            }
        }
    }

    let metadata = fs::symlink_metadata(&src).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("Not a regular file.".into());
    }

    let id = Uuid::new_v4().to_string();
    let data_path = qdir.join(format!("{id}.quar"));
    let meta_path = qdir.join(format!("{id}.json"));
    let computed = xor_copy(&src, &data_path, true).map_err(|error| {
        let _ = fs::remove_file(&data_path);
        format!("Could not copy file (in use or no permission): {error}")
    })?;

    if let Some(expected) = sha256.as_deref().filter(|value| !value.is_empty()) {
        if !expected.eq_ignore_ascii_case(&computed) {
            let _ = fs::remove_file(&data_path);
            return Err("File changed since the scan; it was not quarantined.".into());
        }
    }

    let entry = QuarantineEntry {
        id: id.clone(),
        original_path: path.clone(),
        file_name: src
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone()),
        detection_name: name,
        severity,
        sha256: computed,
        size: metadata.len(),
        date: now(),
    };

    let json = serde_json::to_vec_pretty(&entry).map_err(|error| error.to_string())?;
    if let Err(error) = write_atomic(&meta_path, &json) {
        let _ = remove_item_files(&qdir, &id);
        return Err(error);
    }

    #[cfg(windows)]
    let original_permissions = metadata.permissions();
    #[cfg(windows)]
    if original_permissions.readonly() {
        let mut writable_permissions = original_permissions.clone();
        writable_permissions.set_readonly(false);
        fs::set_permissions(&src, writable_permissions).map_err(|error| error.to_string())?;
    }

    if let Err(error) = fs::remove_file(&src) {
        #[cfg(windows)]
        if original_permissions.readonly() {
            let _ = fs::set_permissions(&src, original_permissions);
        }
        let _ = remove_item_files(&qdir, &id);
        return Err(format!(
            "Could not remove the original (file in use or protected): {error}"
        ));
    }

    log_event(&app, "quarantined", &entry);
    Ok(entry)
}

#[tauri::command(async)]
pub fn delete_detected_file(
    app: AppHandle,
    path: String,
    name: String,
    severity: String,
    sha256: Option<String>,
) -> Result<(), String> {
    let _guard = lock();
    let src = PathBuf::from(&path);
    let canonical = fs::canonicalize(&src).map_err(|_| format!("File not found: {path}"))?;
    let qdir = quarantine_dir(&app)?;
    let canonical_qdir = fs::canonicalize(&qdir).unwrap_or(qdir);
    if canonical.starts_with(canonical_qdir) {
        return Err("Use the quarantine controls to delete an isolated file.".into());
    }
    #[cfg(windows)]
    if let Ok(windows_dir) = std::env::var("WINDIR") {
        if let Ok(canonical_windows_dir) = fs::canonicalize(windows_dir) {
            if canonical.starts_with(canonical_windows_dir) {
                return Err("Refusing to delete files inside the Windows directory.".into());
            }
        }
    }

    let metadata = fs::symlink_metadata(&src).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("Not a regular file.".into());
    }
    let expected = sha256.ok_or("The scan hash is required before deleting this file.")?;
    let actual = sha256_file(&src).map_err(|error| error.to_string())?;
    if !expected.eq_ignore_ascii_case(&actual) {
        return Err("File changed since the scan; it was not deleted.".into());
    }

    fs::remove_file(&src)
        .map_err(|error| format!("Could not delete the file (in use or protected): {error}"))?;

    let entry = QuarantineEntry {
        id: String::new(),
        original_path: path,
        file_name: src
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        detection_name: name,
        severity,
        sha256: actual,
        size: metadata.len(),
        date: now(),
    };
    log_event(&app, "deleted", &entry);
    Ok(())
}

#[tauri::command(async)]
pub fn list_quarantine(app: AppHandle) -> Result<Vec<QuarantineEntry>, String> {
    let _guard = lock();
    list_quarantine_unlocked(&app)
}

fn list_quarantine_unlocked(app: &AppHandle) -> Result<Vec<QuarantineEntry>, String> {
    let qdir = quarantine_dir(app)?;
    let mut items: Vec<QuarantineEntry> = fs::read_dir(&qdir)
        .map_err(|error| error.to_string())?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter_map(|path| fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect();
    items.sort_by(|left, right| right.date.cmp(&left.date));
    Ok(items)
}

#[tauri::command(async)]
pub fn restore_quarantine(app: AppHandle, id: String) -> Result<(), String> {
    validate_id(&id)?;
    let _guard = lock();
    let qdir = quarantine_dir(&app)?;
    let entry = read_entry(&qdir, &id)?;
    let data_path = qdir.join(format!("{id}.quar"));
    let dest = PathBuf::from(&entry.original_path);

    if dest.exists() {
        return Err("A file already exists at the original location.".into());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }

    let tmp = dest.with_extension("sentinel-restoring");
    let hash = xor_copy(&data_path, &tmp, false).map_err(|error| {
        let _ = fs::remove_file(&tmp);
        format!("Restore failed: {error}")
    })?;
    if hash != entry.sha256 {
        let _ = fs::remove_file(&tmp);
        return Err("Integrity check failed; the quarantined file is damaged.".into());
    }
    fs::rename(&tmp, &dest).map_err(|error| {
        let _ = fs::remove_file(&tmp);
        error.to_string()
    })?;

    remove_item_files(&qdir, &id)?;
    log_event(&app, "restored", &entry);
    Ok(())
}

#[tauri::command(async)]
pub fn delete_quarantine(app: AppHandle, id: String) -> Result<(), String> {
    validate_id(&id)?;
    let _guard = lock();
    let qdir = quarantine_dir(&app)?;
    let entry = read_entry(&qdir, &id)?;
    remove_item_files(&qdir, &id)?;
    log_event(&app, "deleted", &entry);
    Ok(())
}

#[tauri::command(async)]
pub fn delete_all_quarantine(app: AppHandle) -> Result<usize, String> {
    let _guard = lock();
    let items = list_quarantine_unlocked(&app)?;
    let qdir = quarantine_dir(&app)?;
    for entry in &items {
        remove_item_files(&qdir, &entry.id)?;
        log_event(&app, "deleted", entry);
    }
    Ok(items.len())
}

#[tauri::command(async)]
pub fn list_history(app: AppHandle) -> Vec<HistoryEvent> {
    let _guard = lock();
    read_history(&app)
}

#[tauri::command(async)]
pub fn clear_history(app: AppHandle) -> Result<(), String> {
    let _guard = lock();
    write_atomic(&history_path(&app)?, b"[]")
}
