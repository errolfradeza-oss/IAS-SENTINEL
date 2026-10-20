//! Sentinel native scan engine (quick / full / custom).

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tauri::{path::BaseDirectory, AppHandle, Emitter, Manager, State};
use walkdir::{DirEntry, WalkDir};

const MAX_FILE_SIZE: u64 = 200 * 1024 * 1024;
const MAX_BUF: usize = 1024 * 1024;
const EMIT_EVERY: Duration = Duration::from_millis(80);

const RISKY_EXT: &[&str] = &[
    "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "msi",
    "jar", "com", "pif", "lnk", "hta", "sys", "apk", "sh", "py", "docm", "xlsm",
    "pptm", "zip", "rar", "7z", "iso",
];

#[derive(Default)]
pub struct ScanState {
    cancel: Arc<AtomicBool>,
    running: AtomicBool,
}

#[derive(Clone, Serialize)]
pub struct Threat {
    pub path: String,
    pub name: String,
    pub severity: String,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub mode: String,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub threats: Vec<Threat>,
    pub threat_count: usize,
    pub cancelled: bool,
    pub duration_ms: u64,
}

#[derive(Clone, Serialize)]
struct Progress {
    phase: &'static str,
    done: usize,
    total: usize,
    percent: f64,
    threats: usize,
    current: String,
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, ScanState>,
    mode: String,
    path: Option<String>,
) -> Result<ScanResult, String> {
    if state.running.swap(true, Ordering::SeqCst) {
        return Err("A scan is already running.".into());
    }
    state.cancel.store(false, Ordering::SeqCst);

    let cancel = state.cancel.clone();
    let handle = app.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || run_scan(handle, mode, path, cancel))
        .await
        .map_err(|error| format!("Scan thread failed: {error}"))
        .and_then(|result| result);

    state.running.store(false, Ordering::SeqCst);
    outcome
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, ScanState>) {
    state.cancel.store(true, Ordering::SeqCst);
}

fn run_scan(
    app: AppHandle,
    mode: String,
    path: Option<String>,
    cancel: Arc<AtomicBool>,
) -> Result<ScanResult, String> {
    let started = Instant::now();
    let signatures = load_signatures(&app)?;

    let (roots, only_risky): (Vec<(PathBuf, usize)>, bool) = match mode.as_str() {
        "quick" => (quick_roots(), true),
        "full" => (all_roots(), false),
        "custom" => {
            let picked = path.ok_or("No file or folder selected.")?;
            let picked = PathBuf::from(picked);
            if !picked.exists() {
                return Err(format!("Path not found: {}", picked.display()));
            }
            (vec![(picked, usize::MAX)], false)
        }
        other => return Err(format!("Unknown scan mode: {other}")),
    };

    let mut files: Vec<PathBuf> = Vec::new();
    let mut last_emit = Instant::now();

    'roots: for (root, max_depth) in &roots {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if root.is_file() {
            files.push(root.clone());
            continue;
        }

        let walker = WalkDir::new(root)
            .max_depth(*max_depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| !skip_dir(entry));

        for entry in walker {
            if cancel.load(Ordering::Relaxed) {
                break 'roots;
            }
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() {
                continue;
            }
            if only_risky && !has_risky_ext(entry.path()) {
                continue;
            }
            files.push(entry.into_path());

            if last_emit.elapsed() >= EMIT_EVERY {
                last_emit = Instant::now();
                let _ = app.emit(
                    "scan-progress",
                    Progress {
                        phase: "enumerating",
                        done: files.len(),
                        total: 0,
                        percent: 0.0,
                        threats: 0,
                        current: String::new(),
                    },
                );
            }
        }
    }

    let total = files.len();
    let done = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let threat_total = AtomicUsize::new(0);
    let threats: Mutex<Vec<Threat>> = Mutex::new(Vec::new());
    let emit_gate = Mutex::new(Instant::now());

    let workers = std::thread::available_parallelism()
        .map(|count| count.get().saturating_sub(1).max(1))
        .unwrap_or(2);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .map_err(|error| error.to_string())?;

    pool.install(|| {
        files.par_iter().for_each(|file| {
            if cancel.load(Ordering::Relaxed) {
                return;
            }

            match hash_file(file, &cancel) {
                Ok(Some(hash)) => {
                    if let Some(signature) = signatures.get(&hash) {
                        threat_total.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut list) = threats.lock() {
                            list.push(Threat {
                                path: file.to_string_lossy().into_owned(),
                                name: signature.name.clone(),
                                severity: signature.severity.clone(),
                                sha256: hash,
                            });
                        }
                    }
                }
                _ => {
                    skipped.fetch_add(1, Ordering::Relaxed);
                }
            }

            let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
            if let Ok(mut gate) = emit_gate.try_lock() {
                if gate.elapsed() >= EMIT_EVERY || finished == total {
                    *gate = Instant::now();
                    let _ = app.emit(
                        "scan-progress",
                        Progress {
                            phase: "scanning",
                            done: finished,
                            total,
                            percent: finished as f64 / total.max(1) as f64 * 100.0,
                            threats: threat_total.load(Ordering::Relaxed),
                            current: file.to_string_lossy().into_owned(),
                        },
                    );
                }
            }
        });
    });

    let cancelled = cancel.load(Ordering::Relaxed);
    let mut threats = threats.into_inner().unwrap_or_default();
    threats.sort_by(|left, right| left.path.cmp(&right.path));

    let files_skipped = skipped.load(Ordering::Relaxed);
    let finished = done.load(Ordering::Relaxed);

    Ok(ScanResult {
        mode,
        files_scanned: finished.saturating_sub(files_skipped),
        files_skipped,
        threat_count: threats.len(),
        threats,
        cancelled,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

fn hash_file(path: &Path, cancel: &AtomicBool) -> std::io::Result<Option<String>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > MAX_FILE_SIZE {
        return Ok(None);
    }

    let mut buffer = vec![0u8; (len as usize).clamp(4096, MAX_BUF)];
    let mut hasher = Sha256::new();

    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(Some(hex))
}

fn has_risky_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| RISKY_EXT.contains(&extension.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn skip_dir(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return false;
    }

    let name = entry.file_name().to_string_lossy().to_lowercase();
    if matches!(
        name.as_str(),
        "$recycle.bin"
            | "system volume information"
            | "winsxs"
            | ".git"
            | "node_modules"
            | "sentinel-quarantine"
    ) {
        return true;
    }

    #[cfg(unix)]
    if matches!(entry.path().to_str(), Some("/proc" | "/sys" | "/dev" | "/run")) {
        return true;
    }

    false
}

fn quick_roots() -> Vec<(PathBuf, usize)> {
    let mut roots: Vec<(PathBuf, usize)> = Vec::new();

    for directory in [dirs::download_dir(), dirs::desktop_dir(), dirs::document_dir()]
        .into_iter()
        .flatten()
    {
        roots.push((directory, usize::MAX));
    }

    roots.push((std::env::temp_dir(), usize::MAX));

    #[cfg(windows)]
    {
        if let Some(roaming) = dirs::config_dir() {
            roots.push((
                roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
                usize::MAX,
            ));
            roots.push((roaming, 3));
        }
        if let Ok(program_data) = std::env::var("PROGRAMDATA") {
            roots.push((
                PathBuf::from(program_data).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"),
                usize::MAX,
            ));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(home) = dirs::home_dir() {
            roots.push((home.join(".config/autostart"), usize::MAX));
            roots.push((home.join(".local/bin"), usize::MAX));
        }
        roots.push((PathBuf::from("/tmp"), usize::MAX));
    }

    let mut seen: Vec<PathBuf> = Vec::new();
    roots.retain(|(path, _)| {
        if !path.exists() || seen.contains(path) {
            return false;
        }
        seen.push(path.clone());
        true
    });
    roots
}

fn all_roots() -> Vec<(PathBuf, usize)> {
    #[cfg(windows)]
    {
        ('A'..='Z')
            .map(|letter| PathBuf::from(format!("{letter}:\\")))
            .filter(|path| path.exists())
            .map(|path| (path, usize::MAX))
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![(PathBuf::from("/"), usize::MAX)]
    }
}

#[derive(Clone)]
struct Sig {
    name: String,
    severity: String,
}

fn default_sig() -> Sig {
    Sig {
        name: "Known malware".into(),
        severity: "High".into(),
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn text_field(map: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| map.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

fn sig_from_value(value: &Value) -> Sig {
    match value {
        Value::String(name) => Sig {
            name: name.clone(),
            severity: "High".into(),
        },
        Value::Object(map) => Sig {
            name: text_field(map, &["name", "threat", "detection", "malware", "family"])
                .unwrap_or_else(|| "Known malware".into()),
            severity: text_field(map, &["severity", "risk", "level"])
                .unwrap_or_else(|| "High".into()),
        },
        _ => default_sig(),
    }
}

fn collect_signatures(value: &Value, output: &mut HashMap<String, Sig>) {
    match value {
        Value::Object(map) => {
            if let Some(hash) =
                text_field(map, &["sha256", "hash", "sha_256", "sha-256"])
                    .filter(|hash| is_sha256(hash))
            {
                output.insert(hash.to_lowercase(), sig_from_value(value));
                return;
            }
            for (key, inner) in map {
                if is_sha256(key) {
                    output.insert(key.to_lowercase(), sig_from_value(inner));
                } else {
                    collect_signatures(inner, output);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(hash) if is_sha256(hash) => {
                        output.insert(hash.to_lowercase(), default_sig());
                    }
                    other => collect_signatures(other, output),
                }
            }
        }
        _ => {}
    }
}

fn find_signatures_file(app: &AppHandle) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(path) = app.path().resolve("signatures.json", BaseDirectory::Resource) {
        candidates.push(path);
    }
    if let Ok(cwd) = std::env::current_dir() {
        for relative in [
            "signatures.json",
            "../signatures.json",
            "src/signatures.json",
            "../src/signatures.json",
        ] {
            candidates.push(cwd.join(relative));
        }
    }
    if let Some(directory) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        candidates.push(directory.join("signatures.json"));
    }

    candidates.into_iter().find(|path| path.is_file())
}

fn load_signatures(app: &AppHandle) -> Result<HashMap<String, Sig>, String> {
    let path = find_signatures_file(app)
        .ok_or("signatures.json was not found. Put it next to your app resources.")?;

    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("Could not read {}: {error}", path.display()))?;
    let json: Value = serde_json::from_str(&text)
        .map_err(|error| format!("signatures.json is not valid JSON: {error}"))?;

    let mut signatures = HashMap::new();
    collect_signatures(&json, &mut signatures);

    if signatures.is_empty() {
        return Err(format!(
            "No SHA-256 signatures could be read from {}.",
            path.display()
        ));
    }
    Ok(signatures)
}
