//! Sentinel native scan engine (quick / full / custom).

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
        Arc, Mutex,
    },
    time::{Duration, Instant},
    thread,
};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tauri::{path::BaseDirectory, AppHandle, Emitter, Manager, State};
use walkdir::{DirEntry, WalkDir};
use crate::exclusions::{is_excluded, load_excluded_paths};

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
    paused: Arc<AtomicBool>,
    running: AtomicBool,
}

#[derive(Clone, Serialize)]
pub struct Threat {
    pub path: String,
    pub name: String,
    pub severity: String,
    pub sha256: String,
    pub detection_source: String,
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

//sha-256 cache

#[derive(Default, Serialize, Deserialize)]
struct ClamAvCache {
    fingerprint: String,
    entries: HashMap<String, Vec<CachedDetection>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedDetection {
    name: String,
    severity: String,
}

fn clamav_cache_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|dir| {
        dir.join("Sentinel").join("clamav-cache.json")
    })
}

fn clamav_fingerprint(
    scanner: &Path,
    database: &Path,
) -> Result<String, String> {
    let mut parts = Vec::new();

    for path in std::iter::once(scanner).chain(
        std::fs::read_dir(database)
            .map_err(|e| format!("Cannot inspect ClamAV database: {e}"))?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .map(|entry| entry.path())
            .collect::<Vec<_>>()
            .iter()
            .map(PathBuf::as_path),
    ) {
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Cannot inspect {}: {e}", path.display()))?;

        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);

        parts.push(format!(
            "{}|{}|{}",
            path.display(),
            metadata.len(),
            modified
        ));
    }

    parts.sort();

    let mut hasher = Sha256::new();
    hasher.update(parts.join("\n").as_bytes());

    Ok(format!("{:x}", hasher.finalize()))
}

fn load_clamav_cache(path: &Path, fingerprint: &str) -> ClamAvCache {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ClamAvCache>(&bytes).ok())
        .filter(|cache| cache.fingerprint == fingerprint)
        .unwrap_or_else(|| ClamAvCache {
            fingerprint: fingerprint.to_string(),
            entries: HashMap::new(),
        })
}

fn save_clamav_cache(path: &Path, cache: &ClamAvCache) {
    let Some(parent) = path.parent() else {
        return;
    };

    if std::fs::create_dir_all(parent).is_err() {
        return;
    }

    let Ok(bytes) = serde_json::to_vec(cache) else {
        return;
    };

    let temporary = path.with_extension("tmp");

    if std::fs::write(&temporary, bytes).is_err() {
        return;
    }

    // Keep the existing cache if replacement fails.
    if path.exists() && std::fs::remove_file(path).is_err() {
        let _ = std::fs::remove_file(temporary);
        return;
    }

    if std::fs::rename(&temporary, path).is_err() {
        let _ = std::fs::remove_file(temporary);
    }
}

//added fix
fn keep_progress_monotonic(
    tracker: &Arc<Mutex<f64>>,
    proposed: f64,
) -> f64 {
    let mut highest = tracker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    *highest = highest.max(proposed.clamp(0.0, 99.0));
    *highest
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
    state.paused.store(false, Ordering::SeqCst);

    let cancel = state.cancel.clone();
    let paused = state.paused.clone();
    let handle = app.clone();

    let outcome = tauri::async_runtime::spawn_blocking(move || {
        run_scan(handle, mode, path, cancel, paused)
    })
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

#[tauri::command]
pub fn pause_scan(state: State<'_, ScanState>) {
    if state.running.load(Ordering::SeqCst) {
        state.paused.store(true, Ordering::SeqCst);
    }
}

#[tauri::command]
pub fn resume_scan(state: State<'_, ScanState>) {
    state.paused.store(false, Ordering::SeqCst);
}

//helper for pause
fn wait_if_paused(
    cancel: &AtomicBool,
    paused: &AtomicBool,
) -> bool {
    while paused.load(Ordering::SeqCst) {
        if cancel.load(Ordering::SeqCst) {
            return false;
        }

        thread::sleep(Duration::from_millis(100));
    }

    !cancel.load(Ordering::SeqCst)
}

fn run_scan(
    app: AppHandle,
    mode: String,
    path: Option<String>,
    cancel: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) -> Result<ScanResult, String> {
    let started = Instant::now();
    let progress_percent = Arc::new(Mutex::new(0.0_f64));
    let signatures = load_signatures(&app)?;
    let exclusions = load_excluded_paths(&app)?;

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

        if is_excluded(root, &exclusions) {
            continue;
        }

        if root.is_file() {
            files.push(root.clone());
            continue;
        }

        let walker = WalkDir::new(root)
            .max_depth(*max_depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                !skip_dir(entry) && !is_excluded(entry.path(), &exclusions)
            });

        for entry in walker {
            if cancel.load(Ordering::Relaxed) {
                break 'roots;
            }
            let Ok(entry) = entry else { continue };

            if is_excluded(entry.path(), &exclusions) {
                continue;
            }

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

    //sha 256 cache
    let file_hashes: Mutex<HashMap<PathBuf, String>> =
    Mutex::new(HashMap::new());

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
            if !wait_if_paused(&cancel, &paused) {
            return;
        }

        match hash_file(file, &cancel, &paused) {
                Ok(Some(hash)) => {
                    //sha 256 cache
                    if let Ok(mut hashes) = file_hashes.lock() {
                        hashes.insert(file.clone(), hash.clone());
                    }
                    //def
                    if let Some(signature) = signatures.get(&hash) {
                        threat_total.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut list) = threats.lock() {
                            list.push(Threat {
                                path: file.to_string_lossy().into_owned(),
                                name: signature.name.clone(),
                                severity: signature.severity.clone(),
                                sha256: hash,
                                detection_source: "sha256-signature".into(),
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
                            percent: keep_progress_monotonic(
                                &progress_percent,
                                finished as f64 / total.max(1) as f64 * 90.0,
                            ),
                            threats: threat_total.load(Ordering::Relaxed),
                            current: file.to_string_lossy().into_owned(),
                        },
                    );
                }
            }
        });
    });

    //sha 256 cache
    let file_hashes = file_hashes.into_inner().unwrap_or_default();

    //added
    let mut threats = threats.into_inner().unwrap_or_default();
    let mut engine_errors: Vec<String> = Vec::new();

    
    // Run ClamAV and YARA concurrently.
    let clamav_app = app.clone();
    let clamav_files = files.clone();
    //sha 256 cache
    let clamav_hashes = file_hashes;
    let clamav_cancel = cancel.clone();
    let clamav_paused = paused.clone();
    let clamav_progress = progress_percent.clone();
    let clamav_base_threats = threats.len();

    let yara_app = app.clone();
    let yara_files = files.clone();
    let yara_cancel = cancel.clone();
    let yara_paused = paused.clone();
    let yara_progress = progress_percent.clone();
    let yara_base_threats = threats.len();

    let clamav_thread = thread::spawn(move || {
        if clamav_cancel.load(Ordering::Relaxed) {
            return Ok(Vec::new());
        }

        run_clamav(
            &clamav_app,
            &clamav_hashes,
            &clamav_files,
            &clamav_cancel,
            clamav_base_threats,
            &clamav_progress,
            &clamav_paused,
        )
    });

    let yara_thread = thread::spawn(move || {
        if yara_cancel.load(Ordering::Relaxed) {
            return Ok(Vec::new());
        }

        run_yara(
            &yara_app,
            &yara_files,
            &yara_cancel,
            yara_base_threats,
            &yara_progress,
            &yara_paused,
        )
    });

    // Wait for both engines and merge their detections.
    match clamav_thread.join() {
        Ok(Ok(mut found)) => threats.append(&mut found),
        Ok(Err(error)) => engine_errors.push(error),
        Err(_) => engine_errors.push("ClamAV worker thread panicked.".into()),
    }

    match yara_thread.join() {
        Ok(Ok(mut found)) => threats.append(&mut found),
        Ok(Err(error)) => engine_errors.push(error),
        Err(_) => engine_errors.push("YARA worker thread panicked.".into()),
    }

    threats.sort_by(|a, b| {
        a.path.cmp(&b.path).then_with(|| a.name.cmp(&b.name))
    });

    let cancelled = cancel.load(Ordering::Relaxed);

    for error in &engine_errors {
        eprintln!("[Sentinel scan engine] {error}");
    }

//end added
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

fn hash_file(
    path: &Path,
    cancel: &AtomicBool,
    paused: &AtomicBool,
) -> std::io::Result<Option<String>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > MAX_FILE_SIZE {
        return Ok(None);
    }

    let mut buffer = vec![0u8; (len as usize).clamp(4096, MAX_BUF)];
    let mut hasher = Sha256::new();

    loop {
        if !wait_if_paused(cancel, paused) {
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
        severity: "low".into(),
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
            severity: "Low".into(),
        },
        Value::Object(map) => Sig {
            name: text_field(map, &["name", "threat", "detection", "malware", "family"])
                .unwrap_or_else(|| "Known malware".into()),
            severity: "Low".into(),
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

//helper func

fn find_yara_script() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("yara_scan.py"));
        candidates.push(cwd.join("sentinel-ui/src-tauri/yara_scan.py"));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("yara_scan.py"));
            candidates.push(dir.join("src-tauri/yara_scan.py"));
        }
    }

    candidates.into_iter().find(|p| p.is_file())
}

//fn add engine

fn add_engine_threat(
    output: &mut Vec<Threat>,
    path: String,
    name: String,
    severity: String,
    engine: &str,
    cancel: &AtomicBool,
    paused: &AtomicBool,
) {
    if cancel.load(Ordering::Relaxed) {
        return;
    }

    let full_name = format!("{engine}: {name}");

    // Check for duplicates before doing additional file I/O.
    if output
        .iter()
        .any(|threat| threat.path == path && threat.name == full_name)
    {
        return;
    }

    let sha256 = hash_file(Path::new(&path), cancel, paused)
        .ok()
        .flatten()
        .unwrap_or_default();

    if cancel.load(Ordering::Relaxed) {
        return;
    }

    output.push(Threat {
        path,
        name: full_name,
        severity,
        sha256,
        detection_source: engine.to_ascii_lowercase(),
    });
}

//cancellable clamav scan

fn run_command_cancellable(
    mut command: Command,
    input: Option<&[u8]>,
    cancel: &AtomicBool,
    engine: &str,
    app: &AppHandle,
    total_files: usize,
    percent_start: f64,
    percent_span: f64,
    base_threats: usize,
    progress_percent: &Arc<Mutex<f64>>,
) -> Result<std::process::Output, String> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| format!("Could not launch {engine}: {e}"))?;

    let stdin = child.stdin.take();
    let stdout = child.stdout.take()
        .ok_or_else(|| format!("{engine}: stdout unavailable"))?;
    let stderr = child.stderr.take()
        .ok_or_else(|| format!("{engine}: stderr unavailable"))?;

    // Forward output lines to the main thread as soon as they arrive.
    let (tx, rx) = mpsc::channel::<(bool, Vec<u8>)>();

    let stdout_tx = tx.clone();
    let stdout_reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);

        loop {
            let mut line = Vec::new();

            match reader.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if stdout_tx.send((false, line)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let stderr_reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);

        loop {
            let mut line = Vec::new();

            match reader.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if tx.send((true, line)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Send the JSON file list to the YARA script.
    if let Some(data) = input {
        if let Some(mut pipe) = stdin {
            if let Err(error) = pipe.write_all(data) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();

                return Err(format!("{engine}: input failed: {error}"));
            }
        }
    }

    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut engine_done = 0usize;
    let mut status = None;

    loop {
        if cancel.load(Ordering::Relaxed) && status.is_none() {
            let _ = child.kill();
            status = Some(
                child.wait()
                    .map_err(|e| format!("{engine}: could not stop process: {e}"))?
            );
        }

        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok((is_stderr, line)) => {
                if is_stderr {
                    stderr_bytes.extend_from_slice(&line);
                } else {
                    stdout_bytes.extend_from_slice(&line);
                }

                let line_text = String::from_utf8_lossy(&line);
                let trimmed = line_text.trim();

                // YARA emits machine-readable progress on stderr.
                if engine == "YARA" && is_stderr {
                    if let Ok(message) = serde_json::from_str::<Value>(trimmed) {
                        if message.get("type").and_then(Value::as_str)
                            == Some("progress")
                        {
                            let done = message
                                .get("done")
                                .and_then(Value::as_u64)
                                .unwrap_or(0) as usize;

                            let total = message
                                .get("total")
                                .and_then(Value::as_u64)
                                .unwrap_or(total_files as u64) as usize;

                            let percent = percent_start
                                + (done.min(total.max(1)) as f64
                                    / total.max(1) as f64)
                                    * percent_span;

                            let _ = app.emit(
                                "scan-progress",
                                Progress {
                                    phase: "engine",
                                    done: total_files,
                                    total: total_files,
                                    percent: keep_progress_monotonic(progress_percent, percent),
                                    threats: base_threats,
                                    current: format!(
                                        "YARA: {done}/{total} files analyzed"
                                    ),
                                },
                            );
                        }
                    }
                }

                // ClamAV normally reports each scanned file as ": OK"
                // or ": <detection> FOUND".
                if engine == "ClamAV" && !is_stderr {
                    let is_file_result =
                        trimmed.ends_with(": OK")
                        || trimmed.ends_with(" FOUND");

                    if is_file_result {
                        engine_done = (engine_done + 1).min(total_files);

                        let percent = percent_start
                            + (engine_done as f64
                                / total_files.max(1) as f64)
                                * percent_span;

                        let _ = app.emit(
                            "scan-progress",
                            Progress {
                                phase: "engine",
                                done: total_files,
                                total: total_files,
                                percent: keep_progress_monotonic(progress_percent, percent),
                                threats: base_threats,
                                current: format!(
                                    "ClamAV: {engine_done}/{total_files} files analyzed"
                                ),
                            },
                        );
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if status.is_some() {
                    break;
                }
            }
        }

        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit_status)) => status = Some(exit_status),
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();

                    return Err(format!("{engine}: process wait failed: {error}"));
                }
            }
        }
    }

    let _ = stdout_reader.join();
    let _ = stderr_reader.join();

    Ok(std::process::Output {
        status: status.ok_or_else(|| format!("{engine}: missing exit status"))?,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    })
}

//clamAV
fn run_clamav(
    app: &AppHandle,
    hashes: &HashMap<PathBuf, String>,
    files: &[PathBuf],
    cancel: &AtomicBool,
    base_threats: usize,
    progress_percent: &Arc<Mutex<f64>>,
    paused: &AtomicBool,
) -> Result<Vec<Threat>, String> {
    if files.is_empty() || cancel.load(Ordering::Relaxed) {
        return Ok(Vec::new());
    }

    let scanner = PathBuf::from(
        r"C:\Program Files\ClamAV\clamscan.exe"
    );
    let database = PathBuf::from(r"C:\ProgramData\ClamAV\db");

    if !scanner.is_file() {
        return Err(format!("ClamAV executable not found: {}", scanner.display()));
    }
    if !database.is_dir() {
        return Err(format!("ClamAV database directory not found: {}", database.display()));
    }

    //sha 256 cache    
    let fingerprint = clamav_fingerprint(&scanner, &database)?;
    let cache_path = clamav_cache_path()
        .ok_or("Could not locate the local application data directory.")?;

    let mut cache = load_clamav_cache(&cache_path, &fingerprint);
    let mut uncached_files: Vec<PathBuf> = Vec::new();
    let mut cached_threats = Vec::new();

    for file in files {
        if cancel.load(Ordering::Relaxed) {
            return Ok(cached_threats);
        }

        let Some(hash) = hashes.get(file) else {
            uncached_files.push(file.clone());
            continue;
        };

        if let Some(detections) = cache.entries.get(hash) {
            for detection in detections {
                cached_threats.push(Threat {
                    path: file.to_string_lossy().into_owned(),
                    name: format!("ClamAV: {}", detection.name),
                    severity: detection.severity.clone(),
                    sha256: hash.clone(),
                    detection_source: "clamav".into(),
                });
            }
        } else {
            uncached_files.push(file.clone());
        }
    }

    if uncached_files.is_empty() {
        return Ok(cached_threats);
    }


    let list_path = std::env::temp_dir().join(format!(
        "sentinel-file-list-{}.txt",
        uuid::Uuid::new_v4()
    ));

    let result = (|| -> Result<Vec<Threat>, String> {
        {
            let mut list = File::create(&list_path)
                .map_err(|e| format!("Could not create ClamAV file list: {e}"))?;

            for file in &uncached_files {
                if cancel.load(Ordering::Relaxed) {
                    return Ok(Vec::new());
                }

                let path = file.to_string_lossy();
                if path.contains('\n') || path.contains('\r') {
                    continue;
                }

                writeln!(list, "{path}")
                    .map_err(|e| format!("Could not write ClamAV file list: {e}"))?;
            }
        }

        
        let mut command = Command::new(&scanner);

        command
            .arg(format!("--database={}", database.display()))
            .arg(format!("--file-list={}", list_path.display()))
            .arg("--no-summary");

        let output = run_command_cancellable(
            command,
            None,
            cancel,
            "ClamAV",
            app,
            uncached_files.len(),
            90.0,
            4.5,
            base_threats,
            progress_percent,
        )?;

        if cancel.load(Ordering::Relaxed) {
            return Ok(Vec::new());
        }

        // clamscan exit code 1 means detections were found.
        if !output.status.success()
            && output.status.code() != Some(1)
        {
            return Err(format!(
                "ClamAV failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut threats = Vec::new();

        for line in text.lines() {
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let Some((path, detection)) = line.split_once(": ") else {
                continue;
            };

            let Some(name) = detection.strip_suffix(" FOUND") else {
                continue;
            };

            add_engine_threat(
                &mut threats,
                path.to_string(),
                name.to_string(),
                "High".into(),
                "ClamAV",
                cancel,
                paused,
            );
        }

        Ok(threats)
    })();

    //let _ = std::fs::remove_file(&list_path);
    //result

    //sha 256 cache
    
    let _ = std::fs::remove_file(&list_path);

    match result {
        Ok(mut found) => {
            if !cancel.load(Ordering::Relaxed) {
                // Record clean results for all files submitted successfully.
                for file in &uncached_files {
                    if let Some(hash) = hashes.get(file) {
                        cache.entries.insert(hash.clone(), Vec::new());
                    }
                }

                // Replace clean entries with the detections found.
                for threat in &found {
                    if let Some(hash) = hashes.get(Path::new(&threat.path)) {
                        let name = threat
                            .name
                            .strip_prefix("ClamAV: ")
                            .unwrap_or(&threat.name)
                            .to_string();

                        cache.entries
                            .entry(hash.clone())
                            .or_default()
                            .push(CachedDetection {
                                name,
                                severity: threat.severity.clone(),
                            });
                    }
                }

                save_clamav_cache(&cache_path, &cache);
            }

            cached_threats.append(&mut found);
            Ok(cached_threats)
        }
        Err(error) => Err(error),
    }
}

//fn yara
fn run_yara(
    app: &AppHandle,
    files: &[PathBuf],
    cancel: &AtomicBool,
    base_threats: usize,
    progress_percent: &Arc<Mutex<f64>>,
    paused: &AtomicBool,
) -> Result<Vec<Threat>, String> {
    if files.is_empty() || cancel.load(Ordering::Relaxed) {
        return Ok(Vec::new());
    }

    let script = find_yara_script()
        .ok_or("Could not locate yara_scan.py.")?;

    let paths: Vec<String> = files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    let input = serde_json::to_vec(&paths)
        .map_err(|e| format!("Could not prepare YARA input: {e}"))?;

    
    let mut command = Command::new("python");
    command.arg(&script);

    let output = run_command_cancellable(
        command,
        Some(&input),
        cancel,
        "YARA",
        app,
        files.len(),
        90.0,
        9.0,
        base_threats,
        progress_percent,
    )?;

    if cancel.load(Ordering::Relaxed) {
        return Ok(Vec::new());
    }


    if !output.status.success() {
        return Err(format!(
            "YARA bridge failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Invalid YARA response: {e}"))?;

    if let Some(error) = response.get("error").and_then(Value::as_str) {
        return Err(format!("YARA: {error}"));
    }

    let mut threats = Vec::new();

    if let Some(detections) = response.get("detections").and_then(Value::as_array) {
        for detection in detections {
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let Some(path) = detection.get("path").and_then(Value::as_str) else {
                continue;
            };
            let Some(name) = detection.get("name").and_then(Value::as_str) else {
                continue;
            };

            let severity = detection
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("Medium");

            add_engine_threat(
                &mut threats,
                path.to_string(),
                name.to_string(),
                severity.to_string(),
                "YARA",
                cancel,
                paused,
            );
        }
    }

    Ok(threats)
}

