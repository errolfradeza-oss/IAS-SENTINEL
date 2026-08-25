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

          ${result.threats.map(threat => `
              <div class="threat">
                  <div>File: ${threat.file}</div>
                  <div>Detection: ${threat.name}</div>
                  <div>Severity: ${threat.severity}</div>
              </div>
          `).join("")}
      `;
  }

    scanState.textContent = "SCAN COMPLETE";

    scanButton.disabled = false;
    selectFolderButton.disabled = false;
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