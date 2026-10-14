const { open, ask } = window.__TAURI__.dialog;
const { Command } = window.__TAURI__.shell;

// ============================================================
// ELEMENTS
// ============================================================

const scanButton = document.querySelector("#scanButton");
const selectFolderButton = document.querySelector("#selectFolderButton");

const scanRing = document.querySelector("#scanRing");
const scanPercent = document.querySelector("#scanPercent");
const scanLabel = document.querySelector("#scanLabel");
const scanHeading = document.querySelector("#scanHeading");
const scanSubtext = document.querySelector("#scanSubtext");

const scanState = document.querySelector("#scanState");
const results = document.querySelector("#results");
const filesScanned = document.querySelector("#filesScanned");
const threatsFound = document.querySelector("#threatsFound");

const selectedFolderText = document.querySelector("#selectedFolder");
const securityStatus = document.querySelector("#securityStatus");
const lastScanTime = document.querySelector("#lastScanTime");

const dashboardPage = document.querySelector("#dashboardPage");
const quarantinePage = document.querySelector("#quarantinePage");
const historyPage = document.querySelector("#historyPage");
const settingsPage = document.querySelector("#settingsPage");

const notificationsToggle = document.querySelector("#notificationsToggle");
const scanSoundToggle = document.querySelector("#scanSoundToggle");
const themeSelect = document.querySelector("#themeSelect");
const clearHistoryButton = document.querySelector("#clearHistoryButton");

const protectionStatus = document.querySelector("#protectionStatus");
const statusDot = document.querySelector(".status-dot");

const securityIcon = document.querySelector("#securityIcon");
const securityTitle = document.querySelector("#securityTitle");
const securityDescription = document.querySelector("#securityDescription");

const scanRippleWrap = document.querySelector("#scanRippleWrap");

// ============================================================
// STATE
// ============================================================

let selectedFolder = null;
let activeScanProgress = null;
let activeRingAnimation = null;
let displayedRingProgress = 0;
let scanInProgress = false;

const SCAN_HISTORY_KEY = "sentinel.scanHistory";
const NOTIFICATIONS_KEY = "sentinel.notifications.enabled";
const SCAN_SOUND_KEY = "sentinel.scanSound.enabled";
const THEME_KEY = "sentinel-theme";

// ============================================================
// SAFE HELPERS
// ============================================================

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => {
        const entities = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        };

        return entities[character];
    });
}

function getStoredBoolean(key, defaultValue = true) {
    const value = localStorage.getItem(key);

    if (value === null) {
        return defaultValue;
    }

    return value === "true";
}

function getScanHistory() {
    try {
        const history = JSON.parse(
            localStorage.getItem(SCAN_HISTORY_KEY) || "[]"
        );

        return Array.isArray(history) ? history : [];
    } catch {
        return [];
    }
}

function saveScanHistory(entry) {
    const history = getScanHistory();

    history.unshift(entry);

    // Keep the latest 100 scans.
    localStorage.setItem(
        SCAN_HISTORY_KEY,
        JSON.stringify(history.slice(0, 100))
    );
}

function formatDate(date = new Date()) {
    return date.toLocaleString();
}

// ============================================================
// CIRCULAR PROGRESS WITH SMOOTH ANIMATION
// ============================================================

function updateCircularProgress(percent) {
    const value = Math.max(0, Math.min(100, percent));

    displayedRingProgress = value;

    if (scanRing) {
        scanRing.style.setProperty("--progress", value);
    }

    if (scanPercent) {
        scanPercent.textContent = `${Math.round(value)}%`;
    }

    if (scanLabel && scanLabel.textContent !== "ERROR") {
        scanLabel.textContent =
            value >= 100 ? "COMPLETE" :
            value > 0 ? "SCANNING" : "READY";
    }
}

function setScanProgress(percent, duration = 220) {
    const target = Math.max(0, Math.min(100, percent));

    if (activeRingAnimation !== null) {
        cancelAnimationFrame(activeRingAnimation);
        activeRingAnimation = null;
    }

    const start = displayedRingProgress;
    const difference = target - start;
    const startTime = performance.now();

    function animateRing(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Ease-out for smooth movement.
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = start + difference * eased;

        updateCircularProgress(current);

        if (progress < 1) {
            activeRingAnimation = requestAnimationFrame(animateRing);
        } else {
            activeRingAnimation = null;
            updateCircularProgress(target);
        }
    }

    activeRingAnimation = requestAnimationFrame(animateRing);
}

function startScanProgress() {
    clearInterval(activeScanProgress);

    setScanProgress(0, 180);

    let current = 0;

    // Simulated progress until the scanner reports actual progress.
    activeScanProgress = setInterval(() => {
        current = Math.min(92, current + Math.random() * 5 + 2);
        setScanProgress(current, 220);
    }, 220);
}

function stopScanProgress(finalPercent = 100) {
    clearInterval(activeScanProgress);
    activeScanProgress = null;

    setScanProgress(finalPercent, 350);
}

function setCircularMessage(heading, description) {
    if (scanHeading) {
        scanHeading.textContent = heading;
    }

    if (scanSubtext) {
        scanSubtext.textContent = description;
    }
}

function setCircularError() {
    if (scanLabel) {
        scanLabel.textContent = "ERROR";
    }

    setCircularMessage(
        "Scan Failed",
        "The scan could not be completed. Check the scanner output."
    );
}

// ============================================================
// SECURITY STATUS
// ============================================================

function setLiveSecurityStatus(status) {
    const states = {
        unknown: {
            text: "Waiting for scan",
            color: "#64748b",
            className: "unknown"
        },
        scanning: {
            text: "Scanning...",
            color: "#38bdf8",
            className: "scanning"
        },
        clean: {
            text: "Protected",
            color: "#22c55e",
            className: "clean"
        },
        slight: {
            text: "Slight threats detected",
            color: "#facc15",
            className: "slight"
        },
        threat: {
            text: "Not protected",
            color: "#ef4444",
            className: "threat"
        },
        error: {
            text: "Protection status unknown",
            color: "#ef4444",
            className: "error"
        }
    };

    const state = states[status] || states.unknown;

    if (scanRing) {
        scanRing.style.setProperty("--ring-color", state.color);
        scanRing.classList.toggle("is-scanning", status === "scanning");
    }

    if (scanRippleWrap) {
        const progressColor = getComputedStyle(scanRing).getPropertyValue("--ring-color").trim()
            || state.color;

        scanRippleWrap.style.setProperty("--ring-color", progressColor);

        scanRippleWrap.classList.toggle(
            "is-scanning",
            ["clean", "slight", "threat"].includes(status)
        );
    }

    if (securityStatus) {
        securityStatus.textContent = state.text;
        securityStatus.className =
            `security-status ${state.className}`;
    }

    if (scanState) {
        scanState.textContent = state.text;
    }

    const liveCard = document.querySelector(".live-security-card");

    if (liveCard) {
        liveCard.dataset.status = status;
    }
}

// ============================================================
// THEME
// ============================================================

function applyTheme(theme) {
    const selectedTheme = theme === "light" ? "light" : "dark";

    document.documentElement.dataset.theme = selectedTheme;
    document.body.dataset.theme = selectedTheme;

    if (themeSelect) {
        themeSelect.value = selectedTheme;
    }

    localStorage.setItem(THEME_KEY, selectedTheme);
}

function initializeTheme() {
    const savedTheme = localStorage.getItem(THEME_KEY) || "dark";
    applyTheme(savedTheme);
}

if (themeSelect) {
    themeSelect.addEventListener("change", (event) => {
        const newTheme = event.target.value;
        const dropdown = event.target;

        const rect = dropdown.getBoundingClientRect();

        // Start the reveal from the center of the dropdown
        const x = rect.left + rect.width / 2;
        const y = rect.top + rect.height / 2;

        document.documentElement.style.setProperty("--theme-x", `${x}px`);
        document.documentElement.style.setProperty("--theme-y", `${y}px`);

        const applyTheme = () => {
            document.documentElement.dataset.theme = newTheme;
            localStorage.setItem("sentinel-theme", newTheme);
        };

        if (document.startViewTransition) {
            document.startViewTransition(() => {
                applyTheme();
            });
        } else {
            applyTheme();
        }
    });
}

initializeTheme();

// ============================================================
// NOTIFICATIONS
// ============================================================

function initializeNotifications() {
    if (notificationsToggle) {
        notificationsToggle.checked = getStoredBoolean(
            NOTIFICATIONS_KEY,
            true
        );

        notificationsToggle.addEventListener("change", () => {
            localStorage.setItem(
                NOTIFICATIONS_KEY,
                String(notificationsToggle.checked)
            );
        });
    }

    if ("Notification" in window &&
        getStoredBoolean(NOTIFICATIONS_KEY, true) &&
        Notification.permission === "default") {
        // Permission is requested only when the user enables
        // notifications and a scan result needs to be reported.
    }
}

async function sendScanNotification(title, message) {
    if (!getStoredBoolean(NOTIFICATIONS_KEY, true)) {
        return;
    }

    if (!("Notification" in window)) {
        return;
    }

    try {
        if (Notification.permission === "default") {
            await Notification.requestPermission();
        }

        if (Notification.permission === "granted") {
            new Notification(title, {
                body: message
            });
        }
    } catch (error) {
        console.warn("Notification unavailable:", error);
    }
}

initializeNotifications();

// ============================================================
// SCAN SOUND
// ============================================================

function initializeScanSound() {
    if (!scanSoundToggle) {
        return;
    }

    scanSoundToggle.checked = getStoredBoolean(
        SCAN_SOUND_KEY,
        true
    );

    scanSoundToggle.addEventListener("change", () => {
        localStorage.setItem(
            SCAN_SOUND_KEY,
            String(scanSoundToggle.checked)
        );
    });
}

function playScanSound(success = true) {
    if (!getStoredBoolean(SCAN_SOUND_KEY, true)) {
        return;
    }

    try {
        const AudioContextClass =
            window.AudioContext || window.webkitAudioContext;

        if (!AudioContextClass) {
            return;
        }

        const context = new AudioContextClass();
        const oscillator = context.createOscillator();
        const gain = context.createGain();

        oscillator.type = "sine";
        oscillator.frequency.value = success ? 880 : 330;

        gain.gain.setValueAtTime(0.12, context.currentTime);
        gain.gain.exponentialRampToValueAtTime(
            0.001,
            context.currentTime + 0.25
        );

        oscillator.connect(gain);
        gain.connect(context.destination);

        oscillator.start();
        oscillator.stop(context.currentTime + 0.25);

        oscillator.onended = () => {
            context.close().catch(() => {});
        };
    } catch (error) {
        console.warn("Scan sound unavailable:", error);
    }
}

initializeScanSound();

// ============================================================
// PAGE NAVIGATION
// ============================================================

function showPage(pageName) {
    const pages = {
        dashboard: dashboardPage,
        quarantine: quarantinePage,
        history: historyPage,
        settings: settingsPage
    };

    Object.values(pages).forEach(page => {
        if (page) {
            page.classList.remove("active");
            page.hidden = true;
        }
    });

    const targetPage = pages[pageName];

    if (targetPage) {
        targetPage.hidden = false;
        targetPage.classList.add("active");
    }

    document.querySelectorAll("[data-page]").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.page === pageName
        );
    });

    if (pageName === "quarantine") {
        loadQuarantine();
    }

    if (pageName === "history") {
        renderHistory();
    }
}

document.querySelectorAll("[data-page]").forEach(button => {
    button.addEventListener("click", () => {
        showPage(button.dataset.page);
    });
});

// Support existing sidebar buttons if they use IDs instead.
document.querySelector("#dashboardButton")?.addEventListener(
    "click",
    () => showPage("dashboard")
);

document.querySelector("#quarantineButton")?.addEventListener(
    "click",
    () => showPage("quarantine")
);

document.querySelector("#historyButton")?.addEventListener(
    "click",
    () => showPage("history")
);

document.querySelector("#settingsButton")?.addEventListener(
    "click",
    () => showPage("settings")
);

// ============================================================
// FOLDER SELECTION
// ============================================================

async function selectScanPath() {
    try {
        const selected = await open({
            multiple: false,
            directory: false,
            title: "Select a file or folder to scan"
        });

        if (!selected) return null;

        selectedFolder = selected;

        if (selectedFolderText) {
            selectedFolderText.textContent = selected;
            selectedFolderText.title = selected;
        }

        return selected;
    } catch (error) {
        console.error("Selection failed:", error);
        setCircularMessage(
            "Selection Failed",
            String(error)
        );
        return null;
    }
}

selectFolderButton?.addEventListener("click", selectScanPath);


// ============================================================
// SCANNER OUTPUT NORMALIZATION
// ============================================================

function parseScannerOutput(stdout) {
    const output = String(stdout || "").trim();

    if (!output) {
        throw new Error("The scanner returned no output.");
    }

    // Python tools sometimes print diagnostic lines before JSON.
    // Try the complete output first, then locate the JSON payload.
    try {
        return JSON.parse(output);
    } catch {
        const firstObject = output.indexOf("{");
        const firstArray = output.indexOf("[");

        let start = -1;

        if (firstObject === -1) {
            start = firstArray;
        } else if (firstArray === -1) {
            start = firstObject;
        } else {
            start = Math.min(firstObject, firstArray);
        }

        if (start !== -1) {
            const lastObject = output.lastIndexOf("}");
            const lastArray = output.lastIndexOf("]");
            const end = Math.max(lastObject, lastArray);

            if (end >= start) {
                try {
                    return JSON.parse(output.slice(start, end + 1));
                } catch {
                    // Fall through to the error below.
                }
            }
        }

        throw new Error(
            `Could not parse scanner output: ${output.slice(0, 300)}`
        );
    }
}

function normalizeScanResult(data) {
    const threats =
        data.threats ??
        data.detections ??
        data.malicious_files ??
        data.infected_files ??
        [];

    const threatList = Array.isArray(threats) ? threats : [];

    const scannedCount = Number(
        data.files_scanned ??
        data.scanned ??
        data.total_scanned ??
        data.total_files ??
        0
    );

    return {
        raw: data,
        filesScanned: Number.isFinite(scannedCount) ? scannedCount : 0,
        threats: threatList,
        threatCount: Number(
            data.threat_count ??
            data.threats_found ??
            data.total_threats ??
            threatList.length
        ),
        success: data.success !== false && data.error == null
    };
}

// ============================================================
// SCAN RESULTS
// ============================================================

function renderScanResults(threatList) {
    if (!results) return;

    if (!Array.isArray(threatList) || threatList.length === 0) {
        results.innerHTML = `
            <div class="result-item clean-result">
                <span class="result-icon">✓</span>
                <div>
                    <strong>No known threats detected.</strong>
                    <p>Your scan did not report any threats.</p>
                </div>
            </div>
        `;
        return;
    }

    results.innerHTML = `
        <div class="threat-header">
            ${threatList.length} THREAT${threatList.length !== 1 ? "S" : ""} DETECTED
        </div>

        <div style="color: #fbbf24; font-size: 12px; margin-bottom: 14px; font-weight: 600;">
            ⚠ Threats have been logged to quarantine for review.
        </div>

        ${threatList.map(threat => {
            const path = typeof threat === "string"
                ? threat
                : threat.path ??
                  threat.file_path ??
                  threat.file ??
                  threat.filename ??
                  "Unknown file";

            const name = typeof threat === "string"
                ? threat.split(/[\\\\/]/).pop()
                : threat.name ??
                  threat.filename ??
                  path.split(/[\\\\/]/).pop();

            const detection = typeof threat === "string"
                ? "Potential threat"
                : threat.name ??
                  threat.threat ??
                  threat.type ??
                  threat.detection ??
                  threat.reason ??
                  "Potential threat";

            const severity = typeof threat === "object" && threat !== null
                ? threat.severity ?? "Unknown"
                : "Unknown";

            return `
                <div class="threat">
                    <div>File: ${escapeHtml(name)}</div>
                    <div>Detection: ${escapeHtml(detection)}</div>
                    <div>Severity: ${escapeHtml(severity)}</div>
                    <div>Path: ${escapeHtml(path)}</div>
                </div>
            `;
        }).join("")}
    `;
}

function updateScanStats(scanned, threatCount) {
    if (filesScanned) {
        filesScanned.textContent = Number(scanned || 0).toLocaleString();
    }

    if (threatsFound) {
        threatsFound.textContent = Number(threatCount || 0).toLocaleString();
    }
}

// ============================================================
// RUN SCAN
// ============================================================

async function scanFolder(folder) {
    // This assumes scanner.py is in the working directory configured
    // for the Tauri shell command.
    const command = Command.create("python", [
        "scanner.py",
        folder
    ]);

    let stdout = "";
    let stderr = "";

    command.stdout.on("data", line => {
        stdout += line;
    });

    command.stderr.on("data", line => {
        stderr += line;
        console.warn("[Scanner]", line);
    });

    const output = await command.execute();

    // Use the execute result if event callbacks did not capture output.
    if (!stdout && output.stdout) {
        stdout = output.stdout;
    }

    if (!stderr && output.stderr) {
        stderr = output.stderr;
    }

    if (output.code !== 0) {
        throw new Error(
            stderr.trim() ||
            `Scanner exited with code ${output.code}.`
        );
    }

    const parsed = parseScannerOutput(stdout);
    const normalized = normalizeScanResult(parsed);

    if (!normalized.success) {
        throw new Error(
            parsed.error || "The scanner reported an error."
        );
    }

    return normalized;
}


async function handleScan() {
    if (scanInProgress) return;

    // Ask for a file if no path has been selected.
    if (!selectedFolder) {
        try {
            const selected = await open({
                multiple: false,
                directory: false,
                title: "Select a file to scan"
            });

            if (!selected) return;

            selectedFolder = selected;

            if (selectedFolderText) {
                selectedFolderText.textContent = selected;
                selectedFolderText.title = selected;
            }
        } catch (error) {
            console.error("File picker failed:", error);
            alert("Could not open the file picker.");
            return;
        }
    }

    scanInProgress = true;

    if (scanButton) {
        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";
    }

    try {
        setLiveSecurityStatus("scanning");
        setCircularMessage(
            "Scanning Your Selection",
            "Checking the selected path for threats..."
        );

        startScanProgress();

        const result = await scanFolder(selectedFolder);

        stopScanProgress(100);

        updateScanStats(
            result.filesScanned,
            result.threatCount
        );

        renderScanResults(result.threats);

        setLiveSecurityStatus(
            result.threatCount > 0 ? "threat" : "clean"
        );

        setCircularMessage(
            result.threatCount > 0 ? "Threats Detected" : "Scan Complete",
            result.threatCount > 0
                ? `${result.threatCount} potential threat(s) detected.`
                : "No known threats reported."
        );

        if (lastScanTime) {
            lastScanTime.textContent = formatDate();
        }

        saveScanHistory({
            date: new Date().toISOString(),
            folder: selectedFolder,
            filesScanned: result.filesScanned,
            threatsFound: result.threatCount,
            status: result.threatCount > 0
                ? "Threats detected"
                : "Clean"
        });

    } catch (error) {
        console.error("Scan failed:", error);
        stopScanProgress(0);
        setLiveSecurityStatus("error");
        setCircularError();

        if (results) {
            results.textContent = `Scan failed: ${error.message}`;
        }
    } finally {
        scanInProgress = false;

        if (scanButton) {
            scanButton.disabled = false;
            scanButton.textContent = "Scan Now";
        }
    }
}


scanButton?.addEventListener("click", handleScan);

// ============================================================
// QUARANTINE TNGINA busseng!!
// ============================================================

function setDeleteAllEnabled(enabled) {
    const button = document.querySelector("#deleteAllQuarantine");

    if (button) {
        button.disabled = !enabled;
    }
}

async function runQuarantineCommand(args) {
    const command = Command.create("python", [
        "quarantine.py",
        ...args
    ]);

    const output = await command.execute();

    if (output.code !== 0) {
        throw new Error(
            output.stderr?.trim() ||
            `Quarantine command failed with code ${output.code}.`
        );
    }

    return output.stdout || "";
}

async function loadQuarantine() {
    const container = document.querySelector("#quarantineList");

    if (!container) {
        return;
    }

    // Disable the delete-all button until we know items exist.
    setDeleteAllEnabled(false);

    container.innerHTML = `
        <div class="result-item">
            <p>Loading quarantined files...</p>
        </div>
    `;

    try {
        const output = await runQuarantineCommand(["list"]);

        let data;

        try {
            data = JSON.parse(output);
        } catch {
            data = output.trim()
                ? output.trim().split("\n")
                : [];
        }

        const items = Array.isArray(data)
            ? data
            : data.items ?? data.quarantine ?? [];

        const countEl = document.querySelector("#quarantineCount");
        if (countEl) {
            countEl.textContent = items.length;
        }

        // Only enable "delete all" when there is something to delete.
        setDeleteAllEnabled(items.length > 0);

        if (!Array.isArray(items) || items.length === 0) {
            container.innerHTML = `
                <div class="result-item">
                    <div>
                        <strong>No quarantined files</strong>
                        <p>Files placed in quarantine will appear here.</p>
                    </div>
                </div>
            `;

            return;
        }

        container.innerHTML = items.map((item, index) => {
            const id = typeof item === "string"
                ? item
                : item.id ?? item.quarantine_id ?? index;

            const path = typeof item === "string"
                ? item
                : item.original_path ??
                  item.path ??
                  item.filename ??
                  "Unknown file";

            const name = path.split(/[\\/]/).pop();

            return `
                <div class="result-item quarantine-item">
                    <div class="result-details">
                        <strong>${escapeHtml(name)}</strong>
                        <small>${escapeHtml(path)}</small>
                    </div>

                    <div class="quarantine-actions">
                        <button
                            type="button"
                            class="quarantine-action restore-button"
                            data-quarantine-action="restore"
                            data-quarantine-id="${escapeHtml(id)}"
                        >
                            Restore
                        </button>

                        <button
                            type="button"
                            class="quarantine-action delete-button"
                            data-quarantine-action="delete"
                            data-quarantine-id="${escapeHtml(id)}"
                        >
                            Delete
                        </button>
                    </div>
                </div>
            `;
        }).join("");
    } catch (error) {
        console.error("Failed to load quarantine:", error);

        container.innerHTML = `
            <div class="result-item error-result">
                <div>
                    <strong>Could not load quarantine</strong>
                    <p>${escapeHtml(error.message)}</p>
                </div>
            </div>
        `;
    }
}

document.querySelector("#quarantineList")?.addEventListener(
    "click",
    async event => {
        const button = event.target.closest(
            "[data-quarantine-action]"
        );

        if (!button) {
            return;
        }

        const action = button.dataset.quarantineAction;
        const id = button.dataset.quarantineId;

        if (!id) {
            return;
        }

        if (!await ask(
            "Permanently delete all quarantined items?",
            { title: "Sentinel", type: "warning" }
        )) {
            return;
        }

        button.disabled = true;

        try {
            await runQuarantineCommand([action, id]);
            await loadQuarantine();
        } catch (error) {
            console.error("Quarantine action failed:", error);
            alert(error.message || "The quarantine action failed.");
        } finally {
            button.disabled = false;
        }
    }
);

document.querySelector("#deleteAllQuarantine")?.addEventListener(
    "click",
    async () => {
        if (!confirm("Permanently delete all quarantined items?")) {
            return;
        }

        try {
            await runQuarantineCommand(["delete-all"]);
            await loadQuarantine();
        } catch (error) {
            console.error("Failed to clear quarantine:", error);
            alert(error.message || "Could not clear quarantine.");
        }
    }
);

// ============================================================
// SCAN HISTORY
// ============================================================

async function renderHistory() {
    const container = document.querySelector("#scanHistory");

    if (!container) {
        return;
    }

    // 1. Local scan history (unchanged behavior)
    const scanHistory = getScanHistory();

    // 2. Quarantine events from history.py on disk
    let events = [];

    try {
        const command = Command.create("python", ["history.py", "list"]);
        const output = await command.execute();

        if (output.code === 0 && output.stdout) {
            const parsed = JSON.parse(output.stdout);
            if (Array.isArray(parsed)) {
                events = parsed;
            }
        }
    } catch (error) {
        console.warn("Could not load event history:", error);
    }

    if (scanHistory.length === 0 && events.length === 0) {
        container.innerHTML = `
            <div class="result-item">
                <div>
                    <strong>No scan history yet</strong>
                    <p>Your completed scans will appear here.</p>
                </div>
            </div>
        `;
        return;
    }

    const scanRows = scanHistory.map(entry => {
        const status = entry.status || "Unknown";
        const date = entry.date
            ? new Date(entry.date).toLocaleString()
            : "Unknown date";

        return `
            <div class="result-item history-item">
                <div class="result-details">
                    <strong>${escapeHtml(status)}</strong>
                    <p>${escapeHtml(entry.folder || "Unknown folder")}</p>
                    <small>${escapeHtml(date)}</small>
                    <small>
                        Files scanned: ${Number(entry.filesScanned || 0)}
                        · Threats: ${Number(entry.threatsFound || 0)}
                    </small>
                </div>
            </div>
        `;
    });

    // Newest events first (history.py already returns newest first)
    const eventRows = events.map(event => `
        <div class="result-item history-item">
            <div class="result-details">
                <strong>${escapeHtml(event.action === "restored" ? "Restored from quarantine" : "Deleted from quarantine")}</strong>
                <p>${escapeHtml(event.file_name || "Unknown file")}</p>
                <small>${escapeHtml(new Date(event.date).toLocaleString())}</small>
                <small>
                    Detection: ${escapeHtml(event.detection_name || "Unknown")}
                    · Severity: ${escapeHtml(event.severity || "Unknown")}
                </small>
            </div>
        </div>
    `);

    container.innerHTML = [...scanRows, ...eventRows].join("");
}

clearHistoryButton?.addEventListener("click", async () => {
    if (!await ask(
        "Clear your entire scan history?",
        { title: "Sentinel", type: "warning" }
    )) {
        return;
    }

    localStorage.removeItem(SCAN_HISTORY_KEY);

    try {
        await Command.create("python", ["history.py", "clear"]).execute();
    } catch (error) {
        console.warn("Could not clear event history:", error);
    }

    renderHistory();
});
// ============================================================
// SETTINGS INITIALIZATION
// ============================================================

function initializeSettings() {
    const configurationToggle = document.querySelector(
        "#scanConfigurationToggle"
    );

    const clearResultsToggle = document.querySelector(
        "#clearResultsToggle"
    );

    const quarantineConfirmationToggle = document.querySelector(
        "#quarantineConfirmationToggle"
    );

    const scanSummaryToggle = document.querySelector(
        "#scanSummaryToggle"
    );

    // These preferences are saved for future use.
    // They do not change scanner.py behavior unless the scanner
    // is explicitly wired to read them.
    const preferenceToggles = [
        configurationToggle,
        clearResultsToggle,
        quarantineConfirmationToggle,
        scanSummaryToggle
    ].filter(Boolean);

    preferenceToggles.forEach(toggle => {
        const key = `sentinel.${toggle.id}.enabled`;

        toggle.checked = getStoredBoolean(key, toggle.checked);

        toggle.addEventListener("change", () => {
            localStorage.setItem(key, String(toggle.checked));
        });
    });
}

initializeSettings();

// ============================================================
// INITIAL STATE
// ============================================================

updateCircularProgress(0);
setLiveSecurityStatus("unknown");

if (scanButton) {
    scanButton.disabled = false;
}

if (selectedFolderText) {
    selectedFolderText.textContent = "No folder selected";
}

// Start on the dashboard.
showPage("dashboard");