import os
import sys
import subprocess
import ctypes
import threading
import queue
import time
import traceback
import shutil
import glob
from pathlib import Path

import psutil

import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk


# =============================
# Configuration and Data
# =============================

APP_NAME = "CleanSweep"
APP_ICON_PATH = os.path.join("assets", "app.ico")  # configurable
UPDATE_INTERVAL_MS = 2000  # Status monitor refresh interval


# Cleaning targets. You can adjust these as needed.
# Each item:
#   - name: Display name
#   - category: Grouping in UI
#   - paths: List of path patterns (supports env vars and * globs)
#   - requires_admin: True if deletion typically requires admin privileges
#   - description: Optional hint shown in tooltip/text
FOLDERS = [
    {
        "name": "User Temp",
        "category": "System",
        "paths": [r"%TEMP%"],
        "requires_admin": False,
        "description": "Temporary files for current user"
    },
    {
        "name": "Windows Temp",
        "category": "System",
        "paths": [r"C:\\Windows\\Temp"],
        "requires_admin": True,
        "description": "System temporary files"
    },
    {
        "name": "Windows Update Cache",
        "category": "System",
        "paths": [r"C:\\Windows\\SoftwareDistribution\\Download"],
        "requires_admin": True,
        "description": "Windows Update downloaded packages"
    },
    {
        "name": "Windows Prefetch",
        "category": "System",
        "paths": [r"C:\\Windows\\Prefetch"],
        "requires_admin": True,
        "description": "Prefetch cache used by Windows"
    },
    {
        "name": "Windows Error Reporting Queue",
        "category": "System",
        "paths": [r"%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportQueue"],
        "requires_admin": False,
        "description": "Queued error reports"
    },
    {
        "name": "Discord Cache",
        "category": "Apps",
        "paths": [
            r"%APPDATA%\\discord\\Cache",
            r"%APPDATA%\\discord\\Code Cache",
        ],
        "requires_admin": False,
        "description": "Discord caches"
    },
    {
        "name": "Steam Caches and Logs",
        "category": "Apps",
        "paths": [
            r"%PROGRAMFILES(x86)%\\Steam\\appcache\\httpcache",
            r"%PROGRAMFILES(x86)%\\Steam\\logs",
        ],
        "requires_admin": False,
        "description": "Steam log files and app cache"
    },
    {
        "name": "Adobe Media Cache",
        "category": "Adobe",
        "paths": [
            r"%APPDATA%\\Adobe\\Common\\Media Cache Files",
            r"%LOCALAPPDATA%\\Adobe\\Common\\Media Cache Files",
        ],
        "requires_admin": False,
        "description": "Adobe media and preview caches"
    },
]


# =============================
# Utilities
# =============================

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin():
    try:
        params = " ".join([f'"{arg}"' if " " in arg else arg for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception as e:
        messagebox.showerror(APP_NAME, f"Failed to request admin privileges:\n{e}")


def run_elevated_command(executable: str, args: str = "") -> bool:
    try:
        hinst = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, args, None, 1)
        # Per docs, >32 indicates success
        return hinst > 32
    except Exception:
        return False


def human_size(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024.0


def expand_and_glob(path_pattern: str) -> list[Path]:
    # Expand env vars, user home, and glob pattern
    expanded = os.path.expandvars(os.path.expanduser(path_pattern))
    matches = glob.glob(expanded)
    # If no glob matches, still return the expanded path
    if not matches:
        return [Path(expanded)]
    return [Path(m) for m in matches]


def safe_dir_content_iter(path: Path):
    try:
        if path.is_dir():
            for p in path.iterdir():
                yield p
    except Exception:
        return


def compute_dir_size(path: Path) -> int:
    total = 0
    try:
        if not path.exists():
            return 0
        if path.is_file():
            try:
                return path.stat().st_size
            except Exception:
                return 0
        for root, dirs, files in os.walk(path, topdown=True):
            # Skip symlinks for safety
            try:
                root_path = Path(root)
                for name in files:
                    fp = root_path / name
                    try:
                        if not fp.is_symlink():
                            total += fp.stat().st_size
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    return total


def delete_dir_contents(path: Path) -> tuple[int, int]:
    """
    Delete contents of a directory (not the directory itself).
    Returns (deleted_files, freed_bytes).
    """
    files_deleted = 0
    bytes_freed = 0
    if not path.exists():
        return (0, 0)
    try:
        if path.is_file():
            try:
                size = path.stat().st_size
                path.unlink(missing_ok=True)
                return (1, size)
            except Exception:
                return (0, 0)

        # For directories, delete children only
        for child in list(path.iterdir()):
            try:
                if child.is_file() or child.is_symlink():
                    try:
                        size = child.stat().st_size if child.exists() else 0
                        child.unlink(missing_ok=True)
                        files_deleted += 1
                        bytes_freed += size
                    except Exception:
                        pass
                elif child.is_dir():
                    try:
                        size_before = compute_dir_size(child)
                        shutil.rmtree(child, ignore_errors=True)
                        files_deleted += 1  # count directory as one unit
                        bytes_freed += size_before
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    return (files_deleted, bytes_freed)


def any_requires_admin(items: list[dict]) -> bool:
    return any(i.get("requires_admin", False) for i in items)


def find_system_tool(exe_name: str) -> str | None:
    try:
        system_root = os.environ.get("SystemRoot", r"C:\\Windows")
        candidates = [
            os.path.join(system_root, "System32", exe_name),
            os.path.join(system_root, "Sysnative", exe_name),
            exe_name,
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
    except Exception:
        pass
    return None


# =============================
# UI Components
# =============================

class CleanerFrame(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.vars = {}  # name -> tk.IntVar
        self.items_by_name = {}
        self._worker = None
        self._q = queue.Queue()
        self._stop_event = threading.Event()
        self._build_ui()

    def _build_ui(self):
        # Header controls (minimal layout)
        controls = ctk.CTkFrame(self)
        controls.pack(fill="x", pady=(8, 6), padx=6)

        left = ctk.CTkFrame(controls)
        left.pack(side="left")
        right = ctk.CTkFrame(controls)
        right.pack(side="right")

        self.scan_btn = ctk.CTkButton(left, text="Scan", command=self.scan_selected, width=100)
        self.scan_btn.pack(side="left", padx=(0, 6))

        self.clean_btn = ctk.CTkButton(left, text="Clean", command=self.clean_selected, width=100)
        self.clean_btn.pack(side="left")

        self.select_all_btn = ctk.CTkButton(right, text="Select All", command=self.select_all, width=110)
        self.select_all_btn.pack(side="left", padx=(0, 6))

        self.deselect_all_btn = ctk.CTkButton(right, text="Deselect", command=self.deselect_all, width=110)
        self.deselect_all_btn.pack(side="left")

        # Scrollable area for checkboxes grouped by category
        self.scroll = ctk.CTkScrollableFrame(self)
        self.scroll.pack(fill="both", expand=True, padx=6, pady=4)

        # Group items by category
        categories = {}
        for item in FOLDERS:
            categories.setdefault(item["category"], []).append(item)

        for cat, items in categories.items():
            cat_label = ctk.CTkLabel(self.scroll, text=cat, font=ctk.CTkFont(size=13, weight="bold"))
            cat_label.pack(anchor="w", pady=(10, 4))
            for it in items:
                var = tk.IntVar(value=0)
                self.vars[it["name"]] = var
                self.items_by_name[it["name"]] = it
                cb_text = it["name"] + (" (admin)" if it.get("requires_admin") else "")
                cb = ctk.CTkCheckBox(self.scroll, text=cb_text, variable=var)
                cb.pack(anchor="w", padx=12, pady=4)

        # Status and progress
        self.total_label = ctk.CTkLabel(self, text="Total: 0 B", font=ctk.CTkFont(size=12))
        self.total_label.pack(anchor="w", padx=8, pady=(8, 2))

        self.progress = ctk.CTkProgressBar(self)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=8, pady=(2, 2))

        self.status_label = ctk.CTkLabel(self, text="Ready", font=ctk.CTkFont(size=12))
        self.status_label.pack(anchor="w", padx=8, pady=(2, 8))

        self.after(200, self._poll_queue)

    def select_all(self):
        for var in self.vars.values():
            var.set(1)

    def deselect_all(self):
        for var in self.vars.values():
            var.set(0)

    def _get_selected_items(self) -> list[dict]:
        selected = []
        for name, var in self.vars.items():
            if var.get() == 1:
                selected.append(self.items_by_name[name])
        return selected

    def _disable_actions(self, disabled: bool):
        state = "disabled" if disabled else "normal"
        self.scan_btn.configure(state=state)
        self.clean_btn.configure(state=state)
        self.select_all_btn.configure(state=state)
        self.deselect_all_btn.configure(state=state)

    def _start_worker(self, target, *args):
        if self._worker and self._worker.is_alive():
            return
        self._stop_event.clear()
        self._worker = threading.Thread(target=target, args=args, daemon=True)
        self._worker.start()

    def _poll_queue(self):
        try:
            while True:
                msg = self._q.get_nowait()
                kind = msg.get("type")
                if kind == "status":
                    self.status_label.configure(text=msg.get("text", ""))
                elif kind == "progress":
                    value = msg.get("value", 0.0)
                    self.progress.set(max(0.0, min(1.0, value)))
                elif kind == "total":
                    self.total_label.configure(text=f"Total: {human_size(msg.get('bytes', 0))}")
                elif kind == "done":
                    self._disable_actions(False)
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    # -------- Scan --------
    def scan_selected(self):
        items = self._get_selected_items()
        if not items:
            messagebox.showinfo(APP_NAME, "Select at least one item to scan.")
            return
        self._disable_actions(True)
        self.progress.set(0)
        self.status_label.configure(text="Scanning...")
        self._start_worker(self._scan_worker, items)

    def _scan_worker(self, items: list[dict]):
        try:
            total_items = max(1, len(items))
            combined_bytes = 0
            for idx, it in enumerate(items, start=1):
                name = it["name"]
                self._q.put({"type": "status", "text": f"Scanning {name}..."})
                item_bytes = 0
                for patt in it.get("paths", []):
                    for p in expand_and_glob(patt):
                        if p.exists():
                            item_bytes += compute_dir_size(p)
                combined_bytes += item_bytes
                self._q.put({"type": "progress", "value": idx / total_items})
            self._q.put({"type": "total", "bytes": combined_bytes})
            self._q.put({"type": "status", "text": f"Scan complete. {human_size(combined_bytes)} potential."})
        except Exception as e:
            self._q.put({"type": "status", "text": f"Scan error: {e}"})
        finally:
            self._q.put({"type": "done"})

    # -------- Clean --------
    def clean_selected(self):
        items = self._get_selected_items()
        if not items:
            messagebox.showinfo(APP_NAME, "Select at least one item to clean.")
            return

        requires = any_requires_admin(items)
        if requires and not is_admin():
            if messagebox.askyesno(APP_NAME, "Some selections require administrator privileges. Relaunch the app with admin rights now? You will need to click Clean again after relaunch."):
                relaunch_as_admin()
                return
            else:
                return

        if not messagebox.askyesno(APP_NAME, "This will permanently delete selected cache/temp files. Proceed?"):
            return

        self._disable_actions(True)
        self.progress.set(0)
        self.status_label.configure(text="Cleaning...")
        self._start_worker(self._clean_worker, items)

    def _clean_worker(self, items: list[dict]):
        files_deleted_total = 0
        bytes_freed_total = 0
        errors = []
        try:
            total_items = max(1, len(items))
            for idx, it in enumerate(items, start=1):
                name = it["name"]
                self._q.put({"type": "status", "text": f"Cleaning {name}..."})
                for patt in it.get("paths", []):
                    for p in expand_and_glob(patt):
                        try:
                            if not p.exists():
                                continue
                            # Safety: don't allow deleting root drives or Windows directory itself
                            if p.drive and p == Path(p.drive + os.sep):
                                continue
                            if p.resolve().as_posix().lower() == Path("C:/Windows").as_posix().lower():
                                continue

                            deleted, freed = delete_dir_contents(p)
                            files_deleted_total += deleted
                            bytes_freed_total += freed
                        except Exception as ex:
                            errors.append(f"{p}: {ex}")
                self._q.put({"type": "progress", "value": idx / total_items})

            msg = f"Clean complete. Deleted {files_deleted_total} items, freed {human_size(bytes_freed_total)}."
            if errors:
                msg += f"\nSome items could not be deleted (permissions/in-use)."
            self._q.put({"type": "status", "text": msg})
            # Update total label to reflect post-clean state
            self._q.put({"type": "total", "bytes": 0})
        except Exception as e:
            self._q.put({"type": "status", "text": f"Clean error: {e}"})
        finally:
            self._q.put({"type": "done"})


class ToolsFrame(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Buttons laid out vertically
        self.restore_btn = ctk.CTkButton(self, text="Create Restore Point", command=self.create_restore_point)
        self.restore_btn.pack(fill="x", padx=8, pady=(10, 6))

        self.optimize_btn = ctk.CTkButton(self, text="Optimize Drives", command=self.open_optimize_drives)
        self.optimize_btn.pack(fill="x", padx=8, pady=6)

        self.env_btn = ctk.CTkButton(self, text="Open Environment Variables", command=self.open_env_vars)
        self.env_btn.pack(fill="x", padx=8, pady=6)

        self.status_label = ctk.CTkLabel(self, text="Ready")
        self.status_label.pack(anchor="w", padx=8, pady=(8, 8))

    def create_restore_point(self):
        # Prefer running inside elevated app to capture output and handle enabling
        if not is_admin():
            if messagebox.askyesno(APP_NAME, "This requires administrator rights. Relaunch app as Admin now?"):
                relaunch_as_admin()
            return

        try:
            ps_script = (
                "$drive = (Get-WmiObject -Class Win32_OperatingSystem).SystemDrive; "
                "try { Enable-ComputerRestore -Drive $drive -ErrorAction SilentlyContinue } catch {}; "
                "Checkpoint-Computer -Description 'CleanSweep Restore Point' -RestorePointType 'MODIFY_SETTINGS'"
            )
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                self.status_label.configure(text="Restore point created.")
            else:
                stderr = result.stderr.strip()
                messagebox.showerror(APP_NAME, f"Restore point failed.\n\n{stderr or result.stdout}")
        except subprocess.TimeoutExpired:
            messagebox.showerror(APP_NAME, "Restore point timed out.")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Restore point error: {e}")

    def open_optimize_drives(self):
        try:
            path = find_system_tool("dfrgui.exe")
            if path:
                os.startfile(path)
                self.status_label.configure(text="Opened Optimize Drives.")
                return
        except Exception:
            pass
        # Fallback to defrag CLI in a new window
        try:
            subprocess.Popen(["cmd", "/c", "start", "", "defrag.exe"])
            self.status_label.configure(text="Opened Defrag CLI.")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not open Optimize/Defrag: {e}")

    def open_env_vars(self):
        try:
            # Open System Properties at Advanced tab where Environment Variables live
            subprocess.Popen(["control.exe", "sysdm.cpl,,3"])  # Works on modern Windows
            self.status_label.configure(text="Opened System Properties (Advanced).")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not open System Properties: {e}")


class StatusFrame(ctk.CTkFrame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.drive_widgets = {}
        self._build_ui()
        self._schedule_update()

    def _build_ui(self):
        # CPU & RAM section
        section_perf = ctk.CTkFrame(self)
        section_perf.pack(fill="x", padx=8, pady=(8, 4))

        title_perf = ctk.CTkLabel(section_perf, text="Performance", font=ctk.CTkFont(weight="bold"))
        title_perf.pack(anchor="w", pady=(6, 2))

        # CPU
        self.cpu_label = ctk.CTkLabel(section_perf, text="CPU: 0%")
        self.cpu_label.pack(anchor="w")
        self.cpu_bar = ctk.CTkProgressBar(section_perf)
        self.cpu_bar.set(0)
        self.cpu_bar.pack(fill="x", pady=(2, 6))

        # RAM
        self.ram_label = ctk.CTkLabel(section_perf, text="RAM: 0 / 0 (0%)")
        self.ram_label.pack(anchor="w")
        self.ram_bar = ctk.CTkProgressBar(section_perf)
        self.ram_bar.set(0)
        self.ram_bar.pack(fill="x", pady=(2, 6))

        # Drives section
        section_drives = ctk.CTkFrame(self)
        section_drives.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        title_drives = ctk.CTkLabel(section_drives, text="Drives", font=ctk.CTkFont(weight="bold"))
        title_drives.pack(anchor="w", pady=(6, 6))

        self.drives_container = ctk.CTkScrollableFrame(section_drives)
        self.drives_container.pack(fill="both", expand=True)

    def _schedule_update(self):
        self.after(UPDATE_INTERVAL_MS, self._update_metrics)

    def _update_metrics(self):
        # CPU
        try:
            cpu = psutil.cpu_percent(interval=None)
            self.cpu_label.configure(text=f"CPU: {cpu:.1f}%")
            self.cpu_bar.set(min(1.0, max(0.0, cpu / 100.0)))
        except Exception:
            pass

        # RAM
        try:
            vm = psutil.virtual_memory()
            used = vm.total - vm.available
            self.ram_label.configure(text=f"RAM: {human_size(used)} / {human_size(vm.total)} ({vm.percent:.1f}%)")
            self.ram_bar.set(min(1.0, max(0.0, vm.percent / 100.0)))
        except Exception:
            pass

        # Drives
        try:
            current = {}
            for p in psutil.disk_partitions(all=False):
                # Filter CD-ROM and non-ready mounts
                if "cdrom" in p.opts.lower():
                    continue
                mount = p.mountpoint
                try:
                    usage = psutil.disk_usage(mount)
                except Exception:
                    continue
                current[mount] = usage

            # Rebuild widgets if drives changed
            if set(current.keys()) != set(self.drive_widgets.keys()):
                for w in self.drives_container.winfo_children():
                    w.destroy()
                self.drive_widgets.clear()
                for mount in sorted(current.keys()):
                    row = ctk.CTkFrame(self.drives_container)
                    row.pack(fill="x", pady=4)
                    lbl = ctk.CTkLabel(row, text=f"{mount}")
                    lbl.pack(anchor="w")
                    bar = ctk.CTkProgressBar(row)
                    bar.pack(fill="x", pady=(2, 2))
                    txt = ctk.CTkLabel(row, text="")
                    txt.pack(anchor="w")
                    self.drive_widgets[mount] = (bar, txt)

            for mount, usage in current.items():
                bar, txt = self.drive_widgets[mount]
                used = usage.total - usage.free
                frac = used / usage.total if usage.total else 0.0
                bar.set(min(1.0, max(0.0, frac)))
                txt.configure(text=f"{human_size(used)} / {human_size(usage.total)} Used")
        except Exception:
            pass

        self._schedule_update()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("880x620")

        # Icon
        try:
            icon_path = Path(APP_ICON_PATH)
            if icon_path.exists():
                self.iconbitmap(default=str(icon_path))
        except Exception:
            pass

        # App appearance
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        # Top bar with compact theme switcher
        topbar = ctk.CTkFrame(self)
        topbar.pack(fill="x")

        ctk.CTkLabel(topbar, text=APP_NAME, font=ctk.CTkFont(size=16, weight="bold")).pack(side="left", padx=10, pady=8)

        self.appearance_segment = ctk.CTkSegmentedButton(topbar, values=["System", "Light", "Dark"], command=self.set_appearance)
        self.appearance_segment.set("System")
        self.appearance_segment.pack(side="right", padx=10, pady=8)

        # Tabs
        tabs = ctk.CTkTabview(self)
        tabs.pack(fill="both", expand=True, padx=8, pady=8)

        tab_cleaner = tabs.add("Cleaner")
        tab_tools = tabs.add("System Tools")
        tab_status = tabs.add("Status Monitor")

        self.cleaner = CleanerFrame(tab_cleaner, app=self)
        self.cleaner.pack(fill="both", expand=True)

        self.tools = ToolsFrame(tab_tools, app=self)
        self.tools.pack(fill="both", expand=True)

        self.status = StatusFrame(tab_status, app=self)
        self.status.pack(fill="both", expand=True)

    def set_appearance(self, mode: str):
        mode_lower = mode.lower()
        if mode_lower not in ("system", "light", "dark"):
            mode_lower = "system"
        ctk.set_appearance_mode(mode_lower)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Catch-all guard to avoid crashes
        messagebox.showerror(APP_NAME, f"Unexpected error:\n{e}\n\n{traceback.format_exc()}")
