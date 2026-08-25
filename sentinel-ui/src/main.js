const { open } = window.__TAURI__.dialog;
const { Command } = window.__TAURI__.shell;


// ============================================================
// ELEMENTS
// ============================================================

const scanButton = document.querySelector("#scanButton");
const selectFolderButton = document.querySelector("#selectFolderButton");

const filesScanned = document.querySelector("#filesScanned");
const threatsFound = document.querySelector("#threatsFound");

const scanState = document.querySelector("#scanState");
const results = document.querySelector("#results");

const protectionStatus = document.querySelector("#protectionStatus");
const statusDot = document.querySelector(".status-dot");

const securityIcon = document.querySelector("#securityIcon");
const securityTitle = document.querySelector("#securityTitle");
const securityDescription = document.querySelector("#securityDescription");

let selectedFolder = null;


// ============================================================
// SELECT FOLDER
// ============================================================

selectFolderButton.addEventListener("click", async () => {

    try {

        const folder = await open({
            directory: true,
            multiple: false,
            title: "Select folder to scan"
        });

        if (!folder) {
            scanState.textContent = "READY";
            return;
        }

        console.log("Selected folder:", folder);

        selectedFolder = folder;

        scanState.textContent = "FOLDER SELECTED";

        results.innerHTML = `
            <div class="empty-icon">✓</div>
            <span>${folder}</span>
        `;

    } catch (error) {

        console.error("Folder selection failed:", error);

        scanState.textContent = "ERROR";

        results.innerHTML = `
            <div class="empty-icon">!</div>
            <span>Unable to open folder selector.</span>
        `;
    }
});


// ============================================================
// PYTHON SCANNER
// ============================================================
async function scanFolder(folder) {
    console.log("=== SCANNER TEST ===");
    console.log("Selected folder:", folder);
    console.log("Command object:", Command);

    try {
        const command = Command.create("python", [
            "scanner.py",
            folder
        ]);

        console.log("Command created:", command);

        const output = await command.execute();

        console.log("=== PYTHON RESULT ===");
        console.log("Exit code:", output.code);
        console.log("STDOUT:", output.stdout);
        console.log("STDERR:", output.stderr);

        if (output.code !== 0) {
            console.error("PYTHON FAILED:", output.stderr);
            return null;
        }

        console.log("Python completed successfully.");

        return JSON.parse(output.stdout);

    } catch (error) {
        console.error("=== SCANNER ERROR ===");
        console.error(error);
        return null;
    }
}

// ============================================================
// QUARANTINE
// ============================================================

async function runQuarantine(args) {
    try {
        const command = Command.create("python", [
            "quarantine.py",
            ...args
        ]);
        const output = await command.execute();

        if (output.code !== 0) {
            console.error("QUARANTINE FAILED:", output.stderr);
            return null;
        }

        return JSON.parse(output.stdout);

    } catch (error) {
        console.error("QUARANTINE ERROR:", error);
        return null;
    }
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

async function loadQuarantine() {
    const data = await runQuarantine(["list"]);
    if (data === null) return;
    renderQuarantine(Array.isArray(data) ? data : []);
}

function renderQuarantine(items) {
    const list = document.querySelector("#quarantineList");
    const countEl = document.querySelector("#quarantineCount");
    const empty = document.querySelector("#quarantineEmpty");

    countEl.textContent = items.length;

    list.querySelectorAll(".quarantine-item").forEach(el => el.remove());

    if (items.length === 0) {
        if (empty) empty.style.display = "flex";
        return;
    }

    if (empty) empty.style.display = "none";

    const frag = document.createDocumentFragment();

    items.forEach(item => {
        const div = document.createElement("div");
        div.className = "quarantine-item";
        div.innerHTML = `
            <div class="quarantine-file-icon">!</div>
            <div class="quarantine-file-info">
                <div class="quarantine-file-name">${escapeHtml(item.file_name)}</div>
                <div class="quarantine-file-path">${escapeHtml(item.original_path)}</div>
            </div>
            <div class="quarantine-detection">
                <div class="detection-label">DETECTION</div>
                <div class="detection-name">${escapeHtml(item.detection_name)}</div>
            </div>
            <div class="quarantine-severity">
                <span class="severity-badge">${escapeHtml(item.severity.toUpperCase())}</span>
            </div>
            <div class="quarantine-actions">
                <button class="quarantine-action restore-button" data-id="${item.id}">Restore</button>
                <button class="quarantine-action delete-button" data-id="${item.id}">Delete</button>
            </div>
        `;
        frag.appendChild(div);
    });

    list.appendChild(frag);

    list.querySelectorAll(".restore-button").forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            restoreFile(btn.dataset.id);
        });
    });

    list.querySelectorAll(".delete-button").forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            deleteFile(btn.dataset.id);
        });
    });
}

async function restoreFile(id) {
    if (!confirm("Clear this threat from the quarantine log?")) return;
    const result = await runQuarantine(["restore", id]);
    if (result && result.success) {
        await loadQuarantine();
    } else {
        alert("Failed: " + (result?.error || "Unknown error"));
    }
}

async function deleteFile(id) {
    if (!confirm("Remove this threat from the quarantine log?")) return;
    const result = await runQuarantine(["delete", id]);
    if (result && result.success) {
        await loadQuarantine();
    } else {
        alert("Failed: " + (result?.error || "Unknown error"));
    }
}

async function deleteAllFiles() {
    const count = document.querySelector("#quarantineCount").textContent;
    if (count === "0") return;
    if (!confirm(`Clear all ${count} threats from the quarantine log?`)) return;
    const result = await runQuarantine(["delete-all"]);
    if (result && result.success) {
        await loadQuarantine();
    } else {
        alert("Failed: " + (result?.errors?.join(", ") || "Unknown error"));
    }
}

document.querySelector("#deleteAllQuarantine").addEventListener("click", deleteAllFiles);

// ============================================================
// START SCAN
// ============================================================

scanButton.addEventListener("click", async () => {

    if (!selectedFolder) {

        alert("Please select a folder first.");

        return;
    }

    scanState.textContent = "SCANNING...";

    scanButton.disabled = true;
    selectFolderButton.disabled = true;

    protectionStatus.textContent = "SCANNING";
    statusDot.classList.remove("danger");
    statusDot.classList.add("scanning");

    results.innerHTML = `
        <div class="empty-icon">⌕</div>
        <span>Scanning...</span>
    `;

    const result = await scanFolder(selectedFolder);

    if (!result) {

        scanState.textContent = "SCAN ERROR";

        results.innerHTML = `
            <div class="empty-icon">!</div>
            <span>Scanner failed to run.</span>
        `;

        scanButton.disabled = false;
        selectFolderButton.disabled = false;

        return;
    }

    console.log("Scanner result:", result);

    filesScanned.textContent = result.files_scanned;
    threatsFound.textContent = result.threats_found;

    // UPDATE PROTECTION STATUS
    if (result.threats_found > 0) {
        securityIcon.textContent = "!";
        securityTitle.textContent = "Threats Detected";
        securityDescription.textContent =
            `${result.threats_found} potential threat${result.threats_found !== 1 ? "s" : ""} detected on the selected system.`;
    } else {
        securityIcon.textContent = "✓";
        securityTitle.textContent = "System Secure";
        securityDescription.textContent =
            "No known threats have been detected.";
    }
    if (result.threats_found > 0) {
        protectionStatus.textContent = "THREAT DETECTED";
        statusDot.classList.remove("scanning");
        statusDot.classList.add("danger");
    } else {
        protectionStatus.textContent = "PROTECTED";
        statusDot.classList.remove("scanning", "danger");
    }

    if (result.threats_found === 0) {

        results.innerHTML = `
            <div class="empty-icon">✓</div>
            <span>No known threats detected.</span>
        `;

    } else {
      results.innerHTML = `
          <div class="threat-header">
              🚨 ${result.threats_found} THREAT${result.threats_found !== 1 ? "S" : ""} DETECTED
          </div>
          <div style="color: #fbbf24; font-size: 12px; margin-bottom: 14px; font-weight: 600;">
              ⚠ Threats have been logged to quarantine for review.
          </div>
          ${result.threats.map(threat => `
              <div class="threat">
                  <div>File: ${threat.file}</div>
                  <div>Detection: ${threat.name}</div>
                  <div>Severity: ${threat.severity}</div>
                  ${threat.log_error ? `<div style="color: #f87171; margin-top: 4px;">⚠ Log failed: ${threat.log_error}</div>` : ""}
              </div>
          `).join("")}
      `;
  }

    scanState.textContent = "SCAN COMPLETE";

    scanButton.disabled = false;
    selectFolderButton.disabled = false;

    await loadQuarantine();
});

// ============================================================
// SIDEBAR NAVIGATION
// ============================================================

const navItems = document.querySelectorAll(".nav-item");
const mainContent = document.querySelector("#mainContent");

const dashboardPage = document.querySelector("#dashboardPage");
const quarantinePage = document.querySelector("#quarantinePage");

// ============================================================
// PAGE SWITCHING
// ============================================================

function hideAllPages() {
    document.querySelectorAll(".page").forEach((page) => {
        page.classList.remove("active");
    });
}

function showDashboard() {
    hideAllPages();
    dashboardPage.classList.add("active");
}

function showQuarantine() {
    hideAllPages();
    quarantinePage.classList.add("active");
    loadQuarantine();
}

function showScan() {
    showDashboard();

    const scanSection = scanState.closest(".panel");

    if (scanSection) {
        scanSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }
}

function showHistory() {
    // Placeholder for now
    console.log("History page not implemented yet.");
}

function showSettings() {
    // Placeholder for now
    console.log("Settings page not implemented yet.");
}

//sidebar navigation
navItems.forEach((item) => {

    item.addEventListener("click", () => {

        // Remove active state from every button
        navItems.forEach((nav) => {
            nav.classList.remove("active");
        });

        // Activate clicked button
        item.classList.add("active");

        const page = item.dataset.page;

        // Change main content
        switch (page) {

            case "dashboard":
                showDashboard();
                break;

            case "scan":
                showScan();
                break;

            case "quarantine":
                showQuarantine();
                break;

            case "history":
                showHistory();
                break;

            case "settings":
                showSettings();
                break;
        }

    });

});