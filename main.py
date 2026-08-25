import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import hashlib
import json
import threading


# ============================================================
# CONFIG
# ============================================================

SIGNATURE_FILE = "signatures.json"


# ============================================================
# APPEARANCE
# ============================================================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ============================================================
# SIGNATURE DATABASE
# ============================================================

def load_signatures():
    try:
        with open(SIGNATURE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data.get("signatures", {})

    except FileNotFoundError:
        messagebox.showerror(
            "Database Error",
            f"{SIGNATURE_FILE} was not found."
        )
        return {}

    except json.JSONDecodeError:
        messagebox.showerror(
            "Database Error",
            f"{SIGNATURE_FILE} contains invalid JSON."
        )
        return {}


# ============================================================
# HASHING
# ============================================================

def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            while True:

                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except (PermissionError, OSError):

        return None


# ============================================================
# GET FILES
# ============================================================

def get_files(folder):

    files = []

    for root, directories, filenames in os.walk(folder):

        for filename in filenames:

            file_path = os.path.join(
                root,
                filename
            )

            files.append(file_path)

    return files


# ============================================================
# MAIN APPLICATION
# ============================================================

class AntiMalwareApp(ctk.CTk):

    def __init__(self):

        super().__init__()

        # Window
        self.title("SENTINEL")
        self.geometry("950x650")
        self.minsize(800, 550)


        # Scanner state
        self.scanning = False
        self.files_scanned = 0
        self.threats_found = 0


        self.build_ui()


    # ========================================================
    # UI
    # ========================================================

    def build_ui(self):

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        header = ctk.CTkFrame(
            self,
            corner_radius=0
        )

        header.pack(
            fill="x"
        )


        title = ctk.CTkLabel(
            header,
            text="SENTINEL",
            font=ctk.CTkFont(
                size=26,
                weight="bold"
            )
        )

        title.pack(
            pady=(20, 2)
        )


        subtitle = ctk.CTkLabel(
            header,
            text="Anti-Malware Protection",
            text_color="gray"
        )

        subtitle.pack(
            pady=(0, 20)
        )


        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        status_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        status_frame.pack(
            fill="x",
            padx=30,
            pady=(25, 10)
        )


        self.status_label = ctk.CTkLabel(
            status_frame,
            text="● READY",
            font=ctk.CTkFont(
                size=15,
                weight="bold"
            )
        )

        self.status_label.pack(
            side="left"
        )


        # ----------------------------------------------------
        # BUTTONS
        # ----------------------------------------------------

        button_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        button_frame.pack(
            pady=10
        )


        self.scan_button = ctk.CTkButton(
            button_frame,
            text="SELECT FOLDER",
            width=180,
            height=40,
            command=self.select_folder
        )

        self.scan_button.pack(
            side="left",
            padx=5
        )


        self.stop_button = ctk.CTkButton(
            button_frame,
            text="STOP SCAN",
            width=180,
            height=40,
            fg_color="#8B1E1E",
            hover_color="#A52A2A",
            command=self.stop_scan,
            state="disabled"
        )

        self.stop_button.pack(
            side="left",
            padx=5
        )


        # ----------------------------------------------------
        # PROGRESS
        # ----------------------------------------------------

        self.progress = ctk.CTkProgressBar(
            self,
            width=800
        )

        self.progress.pack(
            padx=50,
            pady=(20, 5)
        )

        self.progress.set(0)


        # ----------------------------------------------------
        # CURRENT FILE
        # ----------------------------------------------------

        self.current_file = ctk.CTkLabel(
            self,
            text="No scan running",
            anchor="w"
        )

        self.current_file.pack(
            fill="x",
            padx=55,
            pady=5
        )


        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        stats_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        stats_frame.pack(
            pady=15
        )


        self.scanned_label = ctk.CTkLabel(
            stats_frame,
            text="Files scanned: 0",
            font=ctk.CTkFont(size=14)
        )

        self.scanned_label.pack(
            side="left",
            padx=30
        )


        self.threat_label = ctk.CTkLabel(
            stats_frame,
            text="Threats found: 0",
            font=ctk.CTkFont(size=14)
        )

        self.threat_label.pack(
            side="left",
            padx=30
        )


        # ----------------------------------------------------
        # RESULTS
        # ----------------------------------------------------

        results_title = ctk.CTkLabel(
            self,
            text="Scan Results",
            font=ctk.CTkFont(
                size=16,
                weight="bold"
            )
        )

        results_title.pack(
            anchor="w",
            padx=40,
            pady=(10, 5)
        )


        self.results_box = ctk.CTkTextbox(
            self,
            height=200,
            corner_radius=10
        )

        self.results_box.pack(
            fill="both",
            expand=True,
            padx=40,
            pady=(0, 25)
        )


        self.results_box.insert(
            "end",
            "No threats detected yet.\n"
        )

        self.results_box.configure(
            state="disabled"
        )


    # ========================================================
    # SELECT FOLDER
    # ========================================================

    def select_folder(self):

        if self.scanning:
            return


        folder = filedialog.askdirectory(
            title="Select folder to scan"
        )


        if not folder:
            return


        self.start_scan(folder)


    # ========================================================
    # START SCAN
    # ========================================================

    def start_scan(self, folder):

        self.scanning = True

        self.files_scanned = 0
        self.threats_found = 0


        self.progress.set(0)


        self.scanned_label.configure(
            text="Files scanned: 0"
        )

        self.threat_label.configure(
            text="Threats found: 0"
        )


        self.current_file.configure(
            text="Preparing scan..."
        )


        self.status_label.configure(
            text="● SCANNING"
        )


        self.scan_button.configure(
            state="disabled"
        )

        self.stop_button.configure(
            state="normal"
        )


        self.results_box.configure(
            state="normal"
        )

        self.results_box.delete(
            "1.0",
            "end"
        )

        self.results_box.insert(
            "end",
            f"Scanning:\n{folder}\n\n"
        )

        self.results_box.configure(
            state="disabled"
        )


        # Run scanner separately so UI doesn't freeze

        thread = threading.Thread(
            target=self.scan_folder,
            args=(folder,),
            daemon=True
        )

        thread.start()


    # ========================================================
    # SCAN
    # ========================================================

    def scan_folder(self, folder):

        signatures = load_signatures()

        files = get_files(folder)

        total = len(files)


        if total == 0:

            self.after(
                0,
                self.scan_finished
            )

            return


        for index, file_path in enumerate(files):

            if not self.scanning:
                break


            filename = os.path.basename(
                file_path
            )


            self.after(
                0,
                lambda name=filename:
                self.current_file.configure(
                    text=f"Scanning: {name}"
                )
            )


            file_hash = calculate_sha256(
                file_path
            )


            if file_hash:

                if file_hash in signatures:

                    detection = signatures[
                        file_hash
                    ]


                    self.threats_found += 1


                    self.after(
                        0,
                        self.add_threat,
                        file_path,
                        detection["name"],
                        detection["severity"]
                    )


            self.files_scanned += 1


            progress = (
                (index + 1)
                / total
            )


            self.after(
                0,
                self.update_progress,
                progress
            )


        self.after(
            0,
            self.scan_finished
        )


    # ========================================================
    # UPDATE PROGRESS
    # ========================================================

    def update_progress(self, progress):

        self.progress.set(
            progress
        )


        self.scanned_label.configure(
            text=f"Files scanned: {self.files_scanned}"
        )


        self.threat_label.configure(
            text=f"Threats found: {self.threats_found}"
        )


    # ========================================================
    # ADD THREAT
    # ========================================================

    def add_threat(
        self,
        file_path,
        threat_name,
        severity
    ):

        self.results_box.configure(
            state="normal"
        )


        self.results_box.insert(
            "end",
            "\n🚨 THREAT DETECTED\n"
            f"File: {file_path}\n"
            f"Detection: {threat_name}\n"
            f"Severity: {severity}\n"
            "----------------------------------------\n"
        )


        self.results_box.configure(
            state="disabled"
        )


    # ========================================================
    # STOP
    # ========================================================

    def stop_scan(self):

        self.scanning = False

        self.status_label.configure(
            text="● STOPPING..."
        )


    # ========================================================
    # FINISHED
    # ========================================================

    def scan_finished(self):

        self.scanning = False


        self.scan_button.configure(
            state="normal"
        )

        self.stop_button.configure(
            state="disabled"
        )


        self.progress.set(1)


        self.current_file.configure(
            text="Scan complete."
        )


        self.status_label.configure(
            text="● SCAN COMPLETE"
        )


        self.scanned_label.configure(
            text=f"Files scanned: {self.files_scanned}"
        )


        self.threat_label.configure(
            text=f"Threats found: {self.threats_found}"
        )


        if self.threats_found > 0:

            messagebox.showwarning(
                "Threats Detected",
                f"{self.threats_found} threat(s) detected."
            )

        else:

            messagebox.showinfo(
                "Scan Complete",
                "No known threats were detected."
            )


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    app = AntiMalwareApp()

    app.mainloop()