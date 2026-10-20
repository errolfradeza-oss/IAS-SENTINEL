const { open, ask, message } = window.__TAURI__.dialog;
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// ============================================================
// ELEMENTS
// ============================================================

const scanButton = document.querySelector("#scanButton");
const selectFolderButton = document.querySelector("#selectFolderButton");
const selectFileButton = document.querySelector("#selectFileButton");

const scanRing = document.querySelector("#scanRing");
const scanPercent = document.querySelector("#scanPercent");
const scanLabel = document.querySelector("#scanLabel");
const scanHeading = document.querySelector("#scanHeading");
const scanSubtext = document.querySelector("#scanSubtext");
const scanOptions = document.querySelector(".scan-options");
const scanSession = document.querySelector("#scanSession");
const modeScanButton = document.querySelector("#modeScanButton");
const backToScanOptionsButton = document.querySelector("#backToScanOptions");
const scanRingPanel = document.querySelector(".scan-ring-panel");
const scanAnotherButton = document.querySelector("#scanAnotherButton");
const dashboardHeading = document.querySelector(".dashboard-heading");
const dashboardLastScan = document.querySelector("#dashboardLastScan");
const scanHeaderStats = document.querySelector("#scanHeaderStats");
const scanHeaderFilesScanned = document.querySelector("#scanHeaderFilesScanned");
const scanHeaderThreatsFound = document.querySelector("#scanHeaderThreatsFound");

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
const protectionBadge = document.querySelector(".protection-status");

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
let activeRingAnimation = null;
let displayedRingProgress = 0;
let scanInProgress = false;
let currentMode = "quick";
let currentThreats = [];
let highestScanProgress = 0;

const SCAN_MODES = {
    quick: {
        label: "Quick Scan",
        idle: "Checks common malware locations and risky file types."
    },
    full: {
        label: "Full Scan",
        idle: "Checks all available files and directories."
    },
    custom: {
        label: "Custom Scan",
        idle: "Checks the file or folder you selected."
    }
};

const SCAN_HISTORY_KEY = "sentinel.scanHistory";
const NOTIFICATIONS_KEY = "sentinel.notifications.enabled";
const SCAN_SOUND_KEY = "sentinel.scanSound.enabled";
const CLEAR_RESULTS_KEY = "sentinel.clearResultsToggle.enabled";
const SCAN_SUMMARY_KEY = "sentinel.scanSummaryToggle.enabled";
const THEME_KEY = "sentinel-theme";

const EMPTY_RESULTS_HTML = `
    <div class="empty-icon">✓</div>
    <span>No threats detected yet.</span>
`;

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

function errorText(error, fallback = "Something went wrong.") {
    if (typeof error === "string") return error;
    return error?.message || fallback;
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

function baseName(path) {
    return String(path ?? "").split(/[\\/]/).pop() || String(path ?? "");
}

function setResultsEmpty() {
    if (!results) return;
    results.className = "scan-result-content results-empty";
    results.innerHTML = EMPTY_RESULTS_HTML;
}

function setResultsHtml(html) {
    if (!results) return;
    results.className = "scan-result-content results-content";
    results.innerHTML = html;
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

}

//fix scan progress
function setScanProgress(percent, duration = 220) {
    let target = Math.max(0, Math.min(100, Number(percent) || 0));

    if (scanInProgress && target < displayedRingProgress && duration !== 0) {
        target = displayedRingProgress;
    }

    if (activeRingAnimation !== null) {
        cancelAnimationFrame(activeRingAnimation);
        activeRingAnimation = null;
    }

    const start = displayedRingProgress;
    const difference = target - start;
    const startTime = performance.now();

    function animateRing(now) {
        const elapsed = now - startTime;
        const progress = duration <= 0
            ? 1
            : Math.min(elapsed / duration, 1);

        const eased = 1 - Math.pow(1 - progress, 3);
        let current = start + difference * eased;

        if (scanInProgress) {
            current = Math.max(start, current);
        }

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

function setScanLabel(text) {
    if (scanLabel) scanLabel.textContent = text;
}

function setScanSubtext(description) {
    if (scanSubtext) scanSubtext.textContent = description;
}

function setCircularMessage(heading, description) {
    if (scanHeading) {
        scanHeading.textContent = heading;
    }

    if (scanSubtext) {
        scanSubtext.textContent = description;
    }
}

function setCircularError(detail) {
    if (scanLabel) scanLabel.textContent = "ERROR";
    setCircularMessage("Scan Failed", detail || "The scan could not be completed.");
}

// ============================================================
// SECURITY STATUS
// ============================================================

function setLiveSecurityStatus(status) {
    const states = {
        unknown: {
            badge: "STATUS UNKNOWN",
            text: "READY",
            color: "#64748b",
            className: "unknown"
        },
        scanning: {
            badge: "SCANNING",
            text: "SCANNING",
            color: "#38bdf8",
            className: "scanning"
        },
        clean: {
            badge: "PROTECTED",
            text: "CLEAN",
            color: "#22c55e",
            className: "clean"
        },
        slight: {
            badge: "MINOR THREATS",
            text: "MINOR THREATS",
            color: "#facc15",
            className: "slight"
        },
        threat: {
            badge: "THREATS DETECTED",
            text: "THREATS FOUND",
            color: "#ef4444",
            className: "threat"
        },
        error: {
            badge: "SCAN ERROR",
            text: "ERROR",
            color: "#f97316",
            className: "error"
        }
    };

    const key = states[status] ? status : "unknown";
    const state = states[key];

    if (scanRing) {
        scanRing.classList.toggle("is-scanning", key === "scanning");
    }

    if (scanRippleWrap) {
        scanRippleWrap.style.setProperty("--ring-color", state.color);

        scanRippleWrap.classList.toggle(
            "is-scanning",
            ["scanning", "clean", "slight", "threat"].includes(key)
        );
    }

    if (protectionStatus) protectionStatus.textContent = state.badge;
    if (protectionBadge) protectionBadge.dataset.status = key;

    if (scanState) {
        scanState.textContent = state.text;
    }

    const liveCard = document.querySelector(".live-security-card");

    if (liveCard) {
        liveCard.dataset.status = key;
    }
}

// ============================================================
// THEME
// ============================================================


const systemLightPreference = window.matchMedia(
    "(prefers-color-scheme: light)"
);

const themeOptions = document.querySelectorAll("[data-theme-option]");

function applyTheme(theme, savePreference = true) {
    const preferredTheme = ["dark", "light", "system"].includes(theme)
        ? theme
        : "dark";

    const resolvedTheme = preferredTheme === "system"
        ? (systemLightPreference.matches ? "light" : "dark")
        : preferredTheme;

    document.documentElement.dataset.theme = resolvedTheme;
    document.body.dataset.theme = resolvedTheme;

    updateThemeSelector(preferredTheme);

    if (savePreference) {
        localStorage.setItem(THEME_KEY, preferredTheme);
    }
}

function updateThemeSelector(theme) {
    themeOptions.forEach(button => {
        const selected = button.dataset.themeOption === theme;

        button.classList.toggle("active", selected);
        button.setAttribute("aria-pressed", String(selected));
    });
}

function initializeTheme() {
    const savedTheme = localStorage.getItem(THEME_KEY) || "dark";
    applyTheme(savedTheme, false);
}

themeOptions.forEach(button => {
    button.addEventListener("click", () => {
        const newTheme = button.dataset.themeOption;
        const rect = button.getBoundingClientRect();

        // Preserve the spiral animation origin at the clicked option.
        document.documentElement.style.setProperty(
            "--theme-x",
            `${rect.left + rect.width / 2}px`
        );

        document.documentElement.style.setProperty(
            "--theme-y",
            `${rect.top + rect.height / 2}px`
        );

        if (document.startViewTransition) {
            document.startViewTransition(() => applyTheme(newTheme));
        } else {
            applyTheme(newTheme);
        }
    });
});

// Follow Windows appearance changes while System Sync is selected.
systemLightPreference.addEventListener("change", () => {
    if (localStorage.getItem(THEME_KEY) !== "system") {
        return;
    }

    applyTheme("system", false);
});

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

    const order = ["dashboard", "quarantine", "history", "settings"];
    const target = pages[pageName];
    const track = document.querySelector(".page-track");

    if (!target || !track) return;

    const index = order.indexOf(pageName);
    if (index < 0) return;

    const currentName = order.find(name =>
        pages[name]?.classList.contains("active")
    );

    if (currentName === pageName) return;

    Object.values(pages).forEach(page => {
        if (page) page.classList.remove("active");
    });

    target.classList.add("active");

    document.querySelectorAll("[data-page]").forEach(button => {
        button.classList.toggle("active", button.dataset.page === pageName);
    });

    // Move the connected page track to the selected page.
    const viewport = document.querySelector(".page-viewport");
    const pageHeight = viewport.clientHeight;
    track.style.transform = `translateY(-${index * pageHeight}px)`;

    track.style.transform = `translateY(-${index * pageHeight}px)`;

    if (pageName === "quarantine") loadQuarantine();
    if (pageName === "history") renderHistory();
}
//helper

document.querySelectorAll("[data-page]").forEach(button => {
    button.addEventListener("click", () => {
        showPage(button.dataset.page);
    });
});

function setModeButton(state) {
    if (!modeScanButton) return;

    const running = state === "running";
    modeScanButton.disabled = state === "cancelling";
    modeScanButton.classList.toggle("is-cancel", running);

    if (state === "running") {
        modeScanButton.textContent = "CANCEL SCAN";
    } else if (state === "cancelling") {
        modeScanButton.textContent = "CANCELLING...";
    } else {
        modeScanButton.textContent = `START ${SCAN_MODES[currentMode].label.toUpperCase()}`;
    }
}

function showScanProgressView() {
    if (scanRingPanel) scanRingPanel.hidden = false;
    if (modeScanButton) modeScanButton.hidden = false;
    if (scanAnotherButton) scanAnotherButton.hidden = true;
}

function showScanResultsView() {
    if (scanRingPanel) scanRingPanel.hidden = true;
    if (modeScanButton) modeScanButton.hidden = true;
    if (scanAnotherButton) scanAnotherButton.hidden = false;
}

function openScanSession(mode) {
    if (scanInProgress || !scanOptions || !scanSession) return;

    currentMode = mode;
    const config = SCAN_MODES[mode];
    scanOptions.hidden = true;
    scanSession.hidden = false;
    setDashboardScanMode(true);
    if (results) results.hidden = true;
    showScanProgressView();

    const liveCard = document.querySelector(".live-security-card");
    if (liveCard) liveCard.dataset.status = "unknown";
    scanRing?.classList.remove("is-scanning");
    scanRippleWrap?.classList.remove("is-scanning");

    setCircularMessage(config.label, config.idle);
    setScanLabel("READY");
    setScanProgress(0, 180);
    setModeButton("idle");
}

document.querySelectorAll("[data-scan-mode]").forEach(button => {
    button.addEventListener("click", () => openScanSession(button.dataset.scanMode));
});

backToScanOptionsButton?.addEventListener("click", () => {
    if (scanInProgress || !scanOptions || !scanSession) return;

    scanSession.hidden = true;
    scanOptions.hidden = false;
    setDashboardScanMode(false);
});

scanAnotherButton?.addEventListener("click", async () => {
    if (scanInProgress) return;
    selectedFolder = null;
    await handleCustomScan();
});

modeScanButton?.addEventListener("click", async () => {
    if (scanInProgress) {
        setModeButton("cancelling");
        try {
            await invoke("cancel_scan");
        } catch (error) {
            console.warn("Cancel failed:", error);
            setModeButton("running");
        }
        return;
    }

    runScanFlow(currentMode, currentMode === "custom" ? selectedFolder : null);
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

function setSelectedPath(path) {
    selectedFolder = path;
    if (selectedFolderText) {
        selectedFolderText.textContent = path;
        selectedFolderText.title = path;
    }
}

async function pickPath(directory) {
    try {
        const selected = await open({
            multiple: false,
            directory,
            title: directory ? "Select a folder to scan" : "Select a file to scan"
        });

        if (!selected) return null;
        setSelectedPath(selected);
        return selected;
    } catch (error) {
        console.error("Selection failed:", error);
        setCircularMessage("Selection Failed", errorText(error));
        return null;
    }
}

selectFolderButton?.addEventListener("click", () => pickPath(true));
selectFileButton?.addEventListener("click", () => pickPath(false));


// ============================================================
// RUST SCAN RESULT NORMALIZATION
// ============================================================

function normalizeScanResult(data) {
    const threats = Array.isArray(data.threats) ? data.threats : [];
    const filesScanned = Number(data.files_scanned ?? 0);
    const threatCount = Number(data.threat_count ?? threats.length);

    return {
        raw: data,
        mode: data.mode ?? currentMode,
        filesScanned: Number.isFinite(filesScanned) ? filesScanned : 0,
        filesSkipped: Number(data.files_skipped ?? 0) || 0,
        threats,
        threatCount: Number.isFinite(threatCount) ? threatCount : threats.length,
        durationMs: Number(data.duration_ms ?? 0) || 0,
        cancelled: data.cancelled === true,
        quarantinedCount: 0,
        quarantineDeclined: false
    };
}

// ============================================================
// SCAN RESULTS
// ============================================================

function renderScanResults(result) {
    if (!results) return;
    const threatList = result.threats;
    currentThreats = threatList;
    const showSummary = getStoredBoolean(SCAN_SUMMARY_KEY, true);
    const summaryHtml = showSummary ? `
        <div class="scan-summary">
            Scanned <strong>${result.filesScanned.toLocaleString()}</strong> file(s)
            ${result.filesSkipped ? ` · Skipped <strong>${result.filesSkipped.toLocaleString()}</strong> (unreadable)` : ""}
            · Threats <strong>${result.threatCount.toLocaleString()}</strong>
        </div>
    ` : "";

    if (!Array.isArray(threatList) || threatList.length === 0) {
        setResultsHtml(`
            ${summaryHtml}
            <div class="result-item clean-result">
                <span class="result-icon">✓</span>
                <div class="result-details">
                    <strong>No known threats detected.</strong>
                    <p>Your scan did not report any threats.</p>
                </div>
            </div>
        `);
        return;
    }

    setResultsHtml(`
        <div class="threat-bulk-actions">
            <button class="threat-action-button quarantine-threat-button" type="button" data-threat-bulk-action="quarantine">
                <span>Quarantine All</span>
            </button>
            <button class="threat-action-button delete-threat-button" type="button" data-threat-bulk-action="delete">
                <span>Delete All</span>
            </button>
            <button class="threat-action-button allow-threat-button" type="button" data-threat-bulk-action="allow">
                <span>Allow All</span>
            </button>
        </div>
        <div class="threats-overview">
            <div class="threats-overview-icon" aria-hidden="true"><span>!</span></div>
            <div class="threats-overview-copy">
                <h4>Threats detected</h4>
                <p>${threatList.length} suspicious file${threatList.length === 1 ? "" : "s"} found during ${escapeHtml(SCAN_MODES[result.mode ?? currentMode].label.toLowerCase())}</p>
            </div>
            <span class="threat-count-badge">${threatList.length} ${threatList.length === 1 ? "threat" : "threats"}</span>
        </div>

        <div class="detected-threat-list">
        ${threatList.map((threat, index) => {
            const isText = typeof threat === "string";
            const path = isText
                ? threat
                : threat.path ?? threat.file_path ?? threat.file ?? "Unknown file";

            const name = baseName(path);

            const detection = isText
                ? "Potential threat"
                : threat.name ??
                  threat.threat ??
                  threat.type ??
                  threat.detection ??
                  threat.reason ??
                  "Potential threat";

            const severity = !isText && threat !== null
                ? threat.severity ?? "Unknown"
                : "Unknown";
            const severityClass = String(severity).toLowerCase().replace(/[^a-z]/g, "");
            const pathParts = String(path).split(/[\\/]/).filter(Boolean);
            const location = pathParts.length > 1
                ? pathParts.slice(Math.max(0, pathParts.length - 3), -1).join("/")
                : path;

            return `
                <article class="detected-threat" data-threat-index="${index}">
                    <div class="detected-threat-heading">
                        <span class="detected-file-icon" aria-hidden="true">!</span>
                        <div class="detected-threat-copy">
                            <h5>${escapeHtml(name)}</h5>
                            <p>${escapeHtml(detection)} · ${escapeHtml(location)}</p>
                        </div>
                        <span class="severity-pill severity-${escapeHtml(severityClass)}">${escapeHtml(severity)}</span>
                    </div>
                    <div class="threat-card-divider"></div>
                    <p class="threat-action-prompt">Choose an action for this file</p>
                    <div class="threat-card-actions">
                        <button class="threat-action-button quarantine-threat-button" type="button" data-threat-action="quarantine">
                            <span class="threat-action-icon" aria-hidden="true">⛨</span>
                            <span>Quarantine</span>
                        </button>
                        <button class="threat-action-button delete-threat-button" type="button" data-threat-action="delete">
                            <span class="threat-action-icon" aria-hidden="true">▤</span>
                            <span>Delete</span>
                        </button>
                        <button class="threat-action-button allow-threat-button" type="button" data-threat-action="allow">
                            <span class="threat-action-icon" aria-hidden="true">⊙</span>
                            <span>Allow</span>
                        </button>
                    </div>
                    <p class="threat-action-feedback" role="status" hidden></p>
                </article>
            `;
        }).join("")}
        </div>
    `);
    results.classList.add("threat-results");
}

function updateScanStats(scanned, threatCount) {
    const scannedText = Number(scanned || 0).toLocaleString();
    const threatText = Number(threatCount || 0).toLocaleString();

    if (filesScanned) {
        filesScanned.textContent = scannedText;
    }
    if (scanHeaderFilesScanned) scanHeaderFilesScanned.textContent = scannedText;

    if (threatsFound) {
        threatsFound.textContent = threatText;
        threatsFound.classList.toggle("has-threats", Number(threatCount) > 0);
    }
    if (scanHeaderThreatsFound) {
        scanHeaderThreatsFound.textContent = threatText;
        scanHeaderThreatsFound.classList.toggle("has-threats", Number(threatCount) > 0);
    }
}

function setDashboardScanMode(active) {
    if (dashboardHeading) dashboardHeading.hidden = active;
    if (scanHeaderStats) scanHeaderStats.hidden = !active;
    if (dashboardLastScan) dashboardLastScan.hidden = active;
    if (protectionBadge) protectionBadge.hidden = !active;
}

function updateLastScanTime(value) {
    if (lastScanTime) {
        lastScanTime.textContent = value;
        lastScanTime.title = value;
    }
}

function initializeLastScanTime() {
    const latestScan = getScanHistory().find(entry => entry.date && Number.isFinite(Date.parse(entry.date)));
    updateLastScanTime(latestScan ? new Date(latestScan.date).toLocaleString() : "Never");
}

// ============================================================
// RUST SCAN ENGINE
// ============================================================


function onScanProgress(progress) {
    if (!scanInProgress) return;

    if (progress.phase === "enumerating") {
        setScanLabel("PREPARING");
        setScanSubtext(
            `Found ${Number(progress.done).toLocaleString()} files so far...`
        );
        return;
    }

    const reportedPercent = Number(progress.percent);

    if (Number.isFinite(reportedPercent)) {
        const nextProgress = Math.min(99, Math.max(0, reportedPercent));

        if (nextProgress > highestScanProgress) {
            highestScanProgress = nextProgress;
            setScanProgress(highestScanProgress, 120);
        }
    }

    if (progress.phase === "engine") {
        setScanLabel("ANALYZING");
        setScanSubtext(
            progress.current || "Running detection engines..."
        );
    } else {
        setScanLabel("SCANNING");
        setScanSubtext(
            `${Number(progress.done).toLocaleString()} of ` +
            `${Number(progress.total).toLocaleString()} files · ` +
            `${Number(progress.threats).toLocaleString()} threat(s)`
        );
    }

    updateScanStats(progress.done, progress.threats);
}

async function runScan(mode, path = null) {
    const unlisten = await listen("scan-progress", event => {
        onScanProgress(event.payload);
    });

    try {
        const data = await invoke("start_scan", { mode, path });
        return normalizeScanResult(data);
    } finally {
        unlisten();
    }
}

const QUARANTINE_CONFIRM_KEY = "sentinel.quarantineConfirmationToggle.enabled";

function setThreatActionResult(card, message, isError = false) {
    const feedback = card.querySelector(".threat-action-feedback");
    const prompt = card.querySelector(".threat-action-prompt");
    const actions = card.querySelector(".threat-card-actions");

    if (prompt && !isError) prompt.textContent = "Action selected";
    if (actions) actions.hidden = !isError;
    if (feedback) {
        feedback.textContent = message;
        feedback.hidden = false;
        feedback.classList.toggle("is-error", isError);
    }
    card.classList.toggle("is-resolved", !isError);
    updateThreatBulkActions();
}

function getThreatDetails(threat) {
    return {
        path: typeof threat === "string"
            ? threat
            : threat.path ?? threat.file_path ?? threat.file,
        name: typeof threat === "string"
            ? "Potential threat"
            : threat.name ?? threat.threat ?? "Potential threat",
        severity: typeof threat === "string"
            ? "Unknown"
            : threat.severity ?? "Unknown",
        sha256: typeof threat === "string" ? null : threat.sha256 ?? null
    };
}

function updateThreatBulkActions() {
    const bulkActions = results?.querySelector(".threat-bulk-actions");
    if (!bulkActions) return;

    const unresolved = results.querySelectorAll("[data-threat-index]:not(.is-resolved)");
    bulkActions.hidden = unresolved.length === 0;
}

async function handleBulkThreatAction(button) {
    const action = button.dataset.threatBulkAction;
    const cards = [...results.querySelectorAll("[data-threat-index]:not(.is-resolved)")];
    if (cards.length === 0) return;

    if (action === "quarantine" && getStoredBoolean(QUARANTINE_CONFIRM_KEY, false)) {
        let confirmed;
        try {
            confirmed = await ask(`Move all ${cards.length} detected files to quarantine?`, {
                title: "Sentinel",
                kind: "warning",
                okLabel: "Yes",
                cancelLabel: "Cancel"
            });
        } catch (error) {
            console.error("Could not confirm bulk quarantine:", error);
            return;
        }
        if (!confirmed) return;
    }

    if (action === "delete") {
        let confirmed;
        try {
            confirmed = await ask(`Permanently delete all ${cards.length} detected files?`, {
                title: "Sentinel",
                kind: "warning",
                okLabel: "Delete All",
                cancelLabel: "Cancel"
            });
        } catch (error) {
            console.error("Could not confirm bulk deletion:", error);
            return;
        }
        if (!confirmed) return;
    }

    const bulkButtons = [...results.querySelectorAll("[data-threat-bulk-action]")];
    bulkButtons.forEach(bulkButton => { bulkButton.disabled = true; });

    for (const card of cards) {
        const threat = currentThreats[Number(card.dataset.threatIndex)];
        if (!threat) continue;

        const details = getThreatDetails(threat);
        const actionButtons = [...card.querySelectorAll(".threat-action-button")];
        actionButtons.forEach(actionButton => { actionButton.disabled = true; });

        if (action === "allow") {
            setThreatActionResult(card, "Allowed for this scan. The file was left in place.");
            continue;
        }

        try {
            if (action === "quarantine") {
                await invoke("quarantine_threat", details);
                setThreatActionResult(card, "File moved to quarantine.");
            } else {
                await invoke("delete_detected_file", details);
                setThreatActionResult(card, "File permanently deleted.");
            }
        } catch (error) {
            console.error(`Could not ${action} threat`, details.path, error);
            setThreatActionResult(card, errorText(error), true);
            actionButtons.forEach(actionButton => { actionButton.disabled = false; });
        }
    }

    bulkButtons.forEach(bulkButton => { bulkButton.disabled = false; });
    updateThreatBulkActions();
}

async function handleThreatAction(event) {
    const bulkButton = event.target.closest("[data-threat-bulk-action]");
    if (bulkButton && results?.contains(bulkButton)) {
        await handleBulkThreatAction(bulkButton);
        return;
    }

    const button = event.target.closest("[data-threat-action]");
    if (!button || !results?.contains(button)) return;

    const card = button.closest("[data-threat-index]");
    const threat = currentThreats[Number(card?.dataset.threatIndex)];
    if (!card || !threat) return;

    const action = button.dataset.threatAction;
    const details = getThreatDetails(threat);
    const { path } = details;

    const buttons = [...card.querySelectorAll(".threat-action-button")];
    buttons.forEach(actionButton => { actionButton.disabled = true; });

    if (action === "allow") {
        setThreatActionResult(card, "Allowed for this scan. The file was left in place.");
        return;
    }

    if (action === "quarantine" && getStoredBoolean(QUARANTINE_CONFIRM_KEY, false)) {
        let confirmed;
        try {
            confirmed = await ask(`Move ${baseName(path)} to quarantine?`, {
                title: "Sentinel",
                kind: "warning",
                okLabel: "Yes",
                cancelLabel: "Cancel"
            });
        } catch (error) {
            setThreatActionResult(card, errorText(error), true);
            buttons.forEach(actionButton => { actionButton.disabled = false; });
            return;
        }
        if (!confirmed) {
            buttons.forEach(actionButton => { actionButton.disabled = false; });
            return;
        }
    }

    try {
        if (action === "quarantine") {
            await invoke("quarantine_threat", details);
            setThreatActionResult(card, "File moved to quarantine.");
        } else if (action === "delete") {
            await invoke("delete_detected_file", details);
            setThreatActionResult(card, "File permanently deleted.");
        }
    } catch (error) {
        console.error(`Could not ${action} threat`, path, error);
        setThreatActionResult(card, errorText(error), true);
        buttons.forEach(actionButton => { actionButton.disabled = false; });
    }
}

results?.addEventListener("click", handleThreatAction);

function setScanBusy(busy) {
    if (scanButton) {
        scanButton.disabled = busy;
        scanButton.textContent = busy ? "SCANNING..." : "Custom Scan";
    }
    if (backToScanOptionsButton) backToScanOptionsButton.disabled = busy;
    setModeButton(busy ? "running" : "idle");
}

function setScanFinalizing() {
    if (modeScanButton) {
        modeScanButton.disabled = true;
        modeScanButton.classList.remove("is-cancel");
        modeScanButton.textContent = "SCAN COMPLETE";
    }
    if (backToScanOptionsButton) backToScanOptionsButton.disabled = true;
}

async function runScanFlow(mode, path = null) {
    if (scanInProgress) return;
    if (mode === "custom" && !path) {
        await message("Choose a file or folder first.", {
            title: "Sentinel",
            kind: "info"
        });
        return;
    }

    currentMode = mode;
    const config = SCAN_MODES[mode];
    scanInProgress = true;
    highestScanProgress = 0;
    setScanBusy(true);
    showScanProgressView();
    if (results) results.hidden = true;

    if (getStoredBoolean(CLEAR_RESULTS_KEY, false)) setResultsEmpty();

    try {
        setLiveSecurityStatus("scanning");
        setCircularMessage(config.label, "Preparing files...");
        setScanLabel("PREPARING");
        setScanProgress(0, 120);
        updateScanStats(0, 0);

        const result = await runScan(mode, path);

        if (result.cancelled) {
            updateScanStats(result.filesScanned, result.threatCount);
            renderScanResults(result);
            if (results) results.hidden = false;
            //fix progress bar
            highestScanProgress = 0;
            setScanProgress(0, 0);
            displayedRingProgress = 0;
            setScanLabel("CANCELLED");
            setLiveSecurityStatus(result.threatCount > 0 ? "threat" : "unknown");
            setCircularMessage(
                "Scan Cancelled",
                `Stopped after ${result.filesScanned.toLocaleString()} file(s).`
            );
        } else {
            setScanProgress(100, 350);
            setScanLabel("COMPLETE");
            setScanFinalizing();
            setCircularMessage("Scan Complete", "100% scanned. Reviewing results...");
            await new Promise(resolve => setTimeout(resolve, 350));
            await new Promise(resolve => setTimeout(resolve, 2000));

            updateScanStats(result.filesScanned, result.threatCount);
            renderScanResults(result);
            if (results) results.hidden = false;
            showScanResultsView();
            setLiveSecurityStatus(result.threatCount > 0 ? "threat" : "clean");
            setCircularMessage(
                result.threatCount > 0 ? "Threats Detected" : "Scan Complete",
                result.threatCount > 0
                    ? `${result.threatCount} potential threat(s) detected.`
                    : `No known threats found in ${result.filesScanned.toLocaleString()} file(s).`
            );
            playScanSound(result.threatCount === 0);
            sendScanNotification(
                result.threatCount > 0 ? "Threats detected" : "Scan complete",
                result.threatCount > 0
                    ? `${result.threatCount} potential threat(s) found.`
                    : "No known threats found."
            );
        }

        updateLastScanTime(formatDate());
        saveScanHistory({
            date: new Date().toISOString(),
            mode,
            folder: mode === "custom" ? path : config.label,
            filesScanned: result.filesScanned,
            threatsFound: result.threatCount,
            status: result.cancelled
                ? "Cancelled"
                : result.threatCount > 0
                    ? "Threats detected"
                    : "Clean"
        });
    } catch (error) {
        console.error("Scan failed:", error);
        const detail = errorText(error, "The scan could not be completed.");
        if (results) results.hidden = false;
        setScanProgress(0, 200);
        setLiveSecurityStatus("error");
        setCircularError(detail);
        setResultsHtml(`
            <div class="result-item error-result">
                <div class="result-details">
                    <strong>Scan failed</strong>
                    <p>${escapeHtml(detail)}</p>
                </div>
            </div>
        `);
        playScanSound(false);
    } finally {
        scanInProgress = false;
        setScanBusy(false);
    }
}

async function handleCustomScan() {
    if (scanInProgress) return;

    if (!selectedFolder) {
        let wantsFolder;

        try {
            wantsFolder = await ask("What do you want to scan?", {
                title: "Sentinel",
                kind: "info",
                okLabel: "Folder",
                cancelLabel: "File"
            });
        } catch {
            return;
        }

        // Do not open the picker if the question dialog was dismissed.
        if (wantsFolder === null || wantsFolder === undefined) return;

        const picked = await pickPath(wantsFolder);
        if (!picked) return;
    }

    openScanSession("custom");
    await runScanFlow("custom", selectedFolder);
}

scanButton?.addEventListener("click", handleCustomScan);

// ============================================================
// QUARANTINE TNGINA busseng!!
// ============================================================

function setDeleteAllEnabled(enabled) {
    const button = document.querySelector("#deleteAllQuarantine");

    if (button) {
        button.disabled = !enabled;
    }
}

async function loadQuarantine() {
    const container = document.querySelector("#quarantineList");
    if (!container) return;
    setDeleteAllEnabled(false);

    try {
        const items = await invoke("list_quarantine");

        const countEl = document.querySelector("#quarantineCount");
        if (countEl) countEl.textContent = items.length;
        setDeleteAllEnabled(items.length > 0);

        if (items.length === 0) {
            container.innerHTML = `
                <div class="quarantine-empty">
                    <div class="quarantine-empty-icon">✓</div>
                    <h3>Quarantine is empty</h3>
                    <p>Sentinel hasn't isolated any files.</p>
                </div>`;
            return;
        }

        container.innerHTML = items.map(item => `
                <div class="result-item quarantine-item">
                    <div class="quarantine-file-icon">!</div>
                    <div class="quarantine-file-info">
                        <div class="quarantine-file-name">${escapeHtml(item.file_name)}</div>
                        <div class="quarantine-file-path" title="${escapeHtml(item.original_path)}">${escapeHtml(item.original_path)}</div>
                    </div>
                    <div class="quarantine-detection">
                        <div class="detection-label">DETECTION</div>
                        <div class="detection-name">${escapeHtml(item.detection_name)}</div>
                    </div>
                    <div class="quarantine-severity">
                        <span class="severity-badge">${escapeHtml(String(item.severity).toUpperCase())}</span>
                    </div>
                    <div class="quarantine-actions">
                        <button
                            type="button"
                            class="quarantine-action restore-button"
                            data-quarantine-action="restore"
                            data-quarantine-id="${escapeHtml(item.id)}">Restore</button>
                        <button
                            type="button"
                            class="quarantine-action delete-button"
                            data-quarantine-action="delete"
                            data-quarantine-id="${escapeHtml(item.id)}">Delete</button>
                    </div>
                </div>
            `).join("");
    } catch (error) {
        console.error("Failed to load quarantine:", error);
        container.innerHTML = `
            <div class="result-item error-result">
                <div class="result-details">
                    <strong>Could not load quarantine</strong>
                    <p>${escapeHtml(errorText(error))}</p>
                </div>
            </div>`;
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

        if (!["restore", "delete"].includes(action)) return;

        const confirmed = await ask(
            action === "delete"
                ? "Permanently delete this file? This cannot be undone."
                : "Restore this file to its original location? Only do this if you are sure it is safe.",
            {
                title: "Sentinel",
                kind: "warning",
                okLabel: action === "delete" ? "Delete" : "Restore",
                cancelLabel: "Cancel"
            }
        );
        if (!confirmed) {
            return;
        }

        button.disabled = true;

        try {
            await invoke(action === "delete" ? "delete_quarantine" : "restore_quarantine", { id });
            await loadQuarantine();
        } catch (error) {
            console.error("Quarantine action failed:", error);
            button.disabled = false;
            await message(errorText(error, "The quarantine action failed."), {
                title: "Sentinel",
                kind: "error"
            });
        }
    }
);

document.querySelector("#deleteAllQuarantine")?.addEventListener(
    "click",
    async () => {
        const confirmed = await ask("Permanently delete all quarantined items?", {
            title: "Sentinel",
            kind: "warning",
            okLabel: "Delete all",
            cancelLabel: "Cancel"
        });
        if (!confirmed) {
            return;
        }

        try {
            await invoke("delete_all_quarantine");
            await loadQuarantine();
        } catch (error) {
            console.error("Failed to clear quarantine:", error);
            await message(errorText(error, "Could not clear quarantine."), {
                title: "Sentinel",
                kind: "error"
            });
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

    // 2. Quarantine events stored by the native app
    let events = [];

    try {
        events = await invoke("list_history");
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

    const rows = [];
    scanHistory.forEach(entry => {
        rows.push({
            time: new Date(entry.date).getTime() || 0,
            html: `
                <div class="result-item history-item">
                    <div class="result-details">
                        <strong>${escapeHtml(entry.status || "Unknown")}</strong>
                        <p>${escapeHtml(entry.folder || "Unknown folder")}</p>
                        <small>${escapeHtml(entry.date ? new Date(entry.date).toLocaleString() : "Unknown date")}</small>
                        <small>Files scanned: ${Number(entry.filesScanned || 0)} · Threats: ${Number(entry.threatsFound || 0)}</small>
                    </div>
                </div>
            `
        });
    });

    const eventTitles = {
        quarantined: "Moved to quarantine",
        restored: "Restored from quarantine",
        deleted: "Deleted from quarantine"
    };

    events.forEach(event => {
        rows.push({
            time: new Date(event.date).getTime() || 0,
            html: `
                <div class="result-item history-item">
                    <div class="result-details">
                        <strong>${escapeHtml(eventTitles[event.action] ?? event.action)}</strong>
                        <p>${escapeHtml(event.file_name || "Unknown file")}</p>
                        <small>${escapeHtml(event.date ? new Date(event.date).toLocaleString() : "Unknown date")}</small>
                        <small>Detection: ${escapeHtml(event.detection_name || "Unknown")} · Severity: ${escapeHtml(event.severity || "Unknown")}</small>
                    </div>
                </div>
            `
        });
    });

    rows.sort((first, second) => second.time - first.time);
    container.innerHTML = rows.map(row => row.html).join("");
}

clearHistoryButton?.addEventListener("click", async () => {
    const confirmed = await ask("Clear your entire scan history?", {
        title: "Sentinel",
        kind: "warning",
        okLabel: "Clear",
        cancelLabel: "Cancel"
    });
    if (!confirmed) return;

    localStorage.removeItem(SCAN_HISTORY_KEY);
    updateLastScanTime("Never");

    try {
        await invoke("clear_history");
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
    // They do not change Rust scanner behavior unless the scanner
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
// SCAN EXCLUSIONS
// ============================================================

const excludeFolderButton = document.querySelector("#excludeFolderButton");
const excludeFileButton = document.querySelector("#excludeFileButton");
const exclusionsList = document.querySelector("#exclusionsList");

async function renderExclusions() {
    if (!exclusionsList) return;

    try {
        const paths = await invoke("list_exclusions");

        if (!paths.length) {
            exclusionsList.innerHTML =
                '<p class="exclusions-empty">No exclusions added.</p>';
            return;
        }

        exclusionsList.innerHTML = paths.map(path => `
            <div class="exclusion-item">
                <span class="exclusion-path" title="${escapeHtml(path)}">
                    ${escapeHtml(path)}
                </span>
                <button
                    class="exclusion-remove"
                    type="button"
                    data-exclusion-path="${escapeHtml(path)}"
                    title="Remove exclusion"
                >REMOVE</button>
            </div>
        `).join("");
    } catch (error) {
        exclusionsList.innerHTML =
            `<p class="exclusions-empty">${escapeHtml(errorText(error))}</p>`;
    }
}

async function addExclusion(directory) {
    try {
        const path = await open({
            multiple: false,
            directory,
            title: directory
                ? "Select a folder to exclude"
                : "Select a file to exclude"
        });

        if (!path) return;

        await invoke("add_exclusion", { path });
        await renderExclusions();
    } catch (error) {
        await message(errorText(error, "Could not add exclusion."), {
            title: "Sentinel",
            kind: "error"
        });
    }
}

excludeFolderButton?.addEventListener("click", () => addExclusion(true));
excludeFileButton?.addEventListener("click", () => addExclusion(false));

exclusionsList?.addEventListener("click", async event => {
    const button = event.target.closest("[data-exclusion-path]");
    if (!button) return;

    const path = button.dataset.exclusionPath;

    try {
        await invoke("remove_exclusion", { path });
        await renderExclusions();
    } catch (error) {
        await message(errorText(error, "Could not remove exclusion."), {
            title: "Sentinel",
            kind: "error"
        });
    }
});

renderExclusions();

// ============================================================
// INITIAL STATE
// ============================================================

updateCircularProgress(0);
setLiveSecurityStatus("unknown");
initializeLastScanTime();

if (scanButton) {
    scanButton.disabled = false;
}

if (selectedFolderText) {
    selectedFolderText.textContent = "No folder selected";
}

// Start on the dashboard.
showPage("dashboard");