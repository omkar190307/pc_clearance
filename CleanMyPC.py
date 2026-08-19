"""
CleanMyPC  —  Safe Junk File Remover
=====================================
Safety guarantees:
  • Files are moved to the RECYCLE BIN (not permanently deleted).
  • Images, Videos, Audio, Documents, Executables, etc. are NEVER touched.
  • Important system/user folders are NEVER scanned.
  • Only files older than MIN_AGE_DAYS are shown.
  • Only recognised junk extensions from well-known junk locations are listed.
"""

import os
import sys
import ctypes
import ctypes.wintypes
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import time

# ─────────────────────────────────────────────────────────────────
#  SAFETY: Minimum file age before showing in results (days)
# ─────────────────────────────────────────────────────────────────
MIN_AGE_DAYS = 3          # only files not modified in last 3 days

# ─────────────────────────────────────────────────────────────────
#  SAFETY: Extensions that are ALWAYS skipped (never touched)
# ─────────────────────────────────────────────────────────────────
SAFE_EXTENSIONS = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
    ".ico", ".tiff", ".tif", ".raw", ".heic", ".heif",
    ".cr2", ".nef", ".arw", ".dng", ".orf", ".rw2",
    ".psd", ".ai", ".eps", ".indd", ".xcf",
    # Videos
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv",
    ".webm", ".m4v", ".mpg", ".mpeg", ".3gp", ".ts",
    ".mts", ".m2ts", ".vob", ".rmvb", ".rm", ".ogv",
    # Audio
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma",
    ".m4a", ".opus", ".aiff", ".mid", ".midi",
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv", ".tsv",
    ".md", ".rst", ".tex", ".epub", ".mobi",
    # Code / project files
    ".py", ".js", ".ts", ".html", ".css", ".json", ".xml",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".java", ".kt", ".c", ".cpp", ".h", ".cs", ".go",
    ".rs", ".rb", ".php", ".sh", ".bat", ".ps1",
    ".sql", ".db", ".sqlite", ".sqlite3",
    # Executables / installers (may be intentional)
    ".exe", ".msi", ".dll", ".sys", ".drv",
    ".iso", ".img", ".vhd", ".vhdx",
    # Archives
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    # Keys / certs / credentials
    ".pem", ".crt", ".cer", ".key", ".p12", ".pfx",
    # Fonts
    ".ttf", ".otf", ".woff", ".woff2",
}

# ─────────────────────────────────────────────────────────────────
#  SAFETY: Recognised junk extensions
# ─────────────────────────────────────────────────────────────────
JUNK_EXTENSIONS = {
    ".tmp", ".temp",
    ".log",
    ".bak",
    ".old",
    ".chk",
    ".dmp", ".dump",
    ".gid",
    ".apk",
    ".crdownload", ".part", ".partial",
    ".swp", ".swo",
}

# ─────────────────────────────────────────────────────────────────
#  SAFETY: Junk file names (exact, case-insensitive)
# ─────────────────────────────────────────────────────────────────
JUNK_NAMES = {
    "thumbs.db",
    "desktop.ini",
    "ehthumbs.db",
    "ehthumbs_vista.db",
    ".ds_store",
}

# ─────────────────────────────────────────────────────────────────
#  SAFETY: Folders that must NEVER be scanned
# ─────────────────────────────────────────────────────────────────
_up   = os.environ.get("USERPROFILE", "C:\\Users\\User")
_lr   = os.environ.get("SystemRoot", "C:\\Windows")
_la   = os.environ.get("LOCALAPPDATA", "")
_ra   = os.environ.get("APPDATA", "")
_prog = os.environ.get("ProgramFiles", "C:\\Program Files")
_prog86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")

BLOCKED_DIRS = {p.lower() for p in [
    # User data
    os.path.join(_up, "Documents"),
    os.path.join(_up, "Pictures"),
    os.path.join(_up, "Videos"),
    os.path.join(_up, "Music"),
    os.path.join(_up, "Desktop"),
    os.path.join(_up, "OneDrive"),
    os.path.join(_up, "Dropbox"),
    os.path.join(_up, "Google Drive"),
    os.path.join(_up, "Saved Games"),
    # System
    os.path.join(_lr, "System32"),
    os.path.join(_lr, "SysWOW64"),
    os.path.join(_lr, "WinSxS"),
    os.path.join(_lr, "servicing"),
    os.path.join(_lr, "assembly"),
    # Apps
    _prog, _prog86,
    os.path.join(_la, "Programs"),
    os.path.join(_ra, "Microsoft"),
    os.path.join(_ra, "Adobe"),
] if p}

# ─────────────────────────────────────────────────────────────────
#  Scan locations — only well-known junk spots
# ─────────────────────────────────────────────────────────────────
SCAN_LOCATIONS = [
    os.path.join(os.environ.get("TEMP", ""),     ""),
    os.path.join(_lr, "Temp"),
    os.path.join(_la, "Temp"),
    os.path.join(_la, "Microsoft", "Windows", "INetCache"),
    os.path.join(_la, "Microsoft", "Windows", "Explorer"),
    os.path.join(_la, "CrashDumps"),
    os.path.join(_lr, "Prefetch"),
    os.path.join(_lr, "SoftwareDistribution", "Download"),
    os.path.join(_up, "Downloads"),   # APKs / old installers only by extension
    os.path.join(_la, "Google",    "Chrome", "User Data", "Default", "Cache"),
    os.path.join(_la, "Microsoft", "Edge",   "User Data", "Default", "Cache"),
    os.path.join(_ra, "Mozilla",   "Firefox", "Profiles"),
    os.path.join(_la, "Microsoft", "Windows", "WER"),   # Windows Error Reporting
]

# ─────────────────────────────────────────────────────────────────
#  Downloads folder: only these extensions are considered junk
#  (we don't want to touch .exe or .zip the user intentionally kept)
# ─────────────────────────────────────────────────────────────────
DOWNLOADS_JUNK_ONLY = {".apk", ".crdownload", ".part", ".partial", ".tmp"}

# ─────────────────────────────────────────────────────────────────
#  Category map
# ─────────────────────────────────────────────────────────────────
def categorize(ext, name):
    ext  = ext.lower()
    name = name.lower()
    if ext == ".apk":                    return "APK File"
    if ext in (".tmp", ".temp"):         return "Temp File"
    if ext == ".log":                    return "Log File"
    if ext in (".dmp", ".dump"):         return "Crash Dump"
    if ext in (".bak", ".old"):          return "Old Backup"
    if "cache" in name or "cache" in ext: return "Cache"
    if ext == ".chk":                    return "Check Disk"
    return "Junk"

CATEGORY_COLORS = {
    "Temp File"  : "#7c3aed",
    "Log File"   : "#0ea5e9",
    "APK File"   : "#f59e0b",
    "Crash Dump" : "#ef4444",
    "Cache"      : "#10b981",
    "Old Backup" : "#6366f1",
    "Check Disk" : "#ec4899",
    "Junk"       : "#8b5cf6",
}

def human_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

# ─────────────────────────────────────────────────────────────────
#  RECYCLE BIN helper  (Windows Shell — fully recoverable)
# ─────────────────────────────────────────────────────────────────
class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd",                  ctypes.wintypes.HWND),
        ("wFunc",                 ctypes.c_uint),
        ("pFrom",                 ctypes.c_wchar_p),
        ("pTo",                   ctypes.c_wchar_p),
        ("fFlags",                ctypes.c_ushort),
        ("fAnyOperationsAborted", ctypes.wintypes.BOOL),
        ("hNameMappings",         ctypes.c_void_p),
        ("lpszProgressTitle",     ctypes.c_wchar_p),
    ]

_FO_DELETE       = 3
_FOF_ALLOWUNDO   = 0x0040   # Move to Recycle Bin
_FOF_NOCONFIRM   = 0x0010
_FOF_SILENT      = 0x0004
_FOF_NOERRORUI   = 0x0400

def recycle(path: str) -> bool:
    """Move a file to the Windows Recycle Bin. Returns True on success."""
    op = _SHFILEOPSTRUCTW()
    op.hwnd  = 0
    op.wFunc = _FO_DELETE
    op.pFrom = path + "\0\0"       # double-null terminated
    op.pTo   = None
    op.fFlags = _FOF_ALLOWUNDO | _FOF_NOCONFIRM | _FOF_SILENT | _FOF_NOERRORUI
    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    return result == 0 and not op.fAnyOperationsAborted


# ─────────────────────────────────────────────────────────────────
#  SCANNER
# ─────────────────────────────────────────────────────────────────
class Scanner(threading.Thread):
    def __init__(self, on_file, on_done, on_progress):
        super().__init__(daemon=True)
        self.on_file     = on_file
        self.on_done     = on_done
        self.on_progress = on_progress
        self._stop       = threading.Event()

    def stop(self): self._stop.set()

    def _is_old_enough(self, path):
        try:
            mtime = os.path.getmtime(path)
            age   = time.time() - mtime
            return age >= MIN_AGE_DAYS * 86400
        except Exception:
            return False

    def _is_blocked(self, path):
        pl = path.lower()
        return any(pl.startswith(b) for b in BLOCKED_DIRS)

    def run(self):
        found     = []
        locations = [loc for loc in SCAN_LOCATIONS if os.path.isdir(loc)]
        total     = max(len(locations), 1)
        is_downloads = lambda p: os.path.join(_up, "Downloads").lower() in p.lower()

        for idx, location in enumerate(locations):
            if self._stop.is_set(): break
            self.on_progress(idx / total, f"Scanning: {location}")
            try:
                for root, dirs, files in os.walk(location, onerror=lambda e: None):
                    if self._stop.is_set(): break

                    # Prune blocked dirs
                    dirs[:] = [
                        d for d in dirs
                        if not self._is_blocked(os.path.join(root, d))
                        and d.lower() not in ("system32","syswow64","winsxs","servicing")
                    ]

                    for fname in files:
                        if self._stop.is_set(): break

                        ext  = Path(fname).suffix.lower()
                        # Hard skip: safe extensions
                        if ext in SAFE_EXTENSIONS:
                            continue

                        fullpath = os.path.join(root, fname)

                        # Hard skip: blocked directory
                        if self._is_blocked(fullpath):
                            continue

                        # Age filter
                        if not self._is_old_enough(fullpath):
                            continue

                        try:
                            size = os.path.getsize(fullpath)
                        except Exception:
                            continue

                        lname = fname.lower()

                        # Downloads folder: stricter — only known download-junk
                        if is_downloads(fullpath):
                            if ext not in DOWNLOADS_JUNK_ONLY:
                                continue

                        # Must be a recognised junk extension OR junk name
                        is_junk = (
                            ext  in JUNK_EXTENSIONS
                            or lname in JUNK_NAMES
                        )
                        if not is_junk:
                            continue

                        cat   = categorize(ext, fname)
                        entry = {
                            "path"    : fullpath,
                            "name"    : fname,
                            "size"    : size,
                            "size_hr" : human_size(size),
                            "category": cat,
                            "ext"     : ext,
                        }
                        found.append(entry)
                        self.on_file(entry)

            except PermissionError:
                pass

        self.on_progress(1.0, "Scan complete!")
        self.on_done(found)


# ─────────────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────────────
BG_DARK    = "#0d0d1a"
BG_CARD    = "#13132b"
BG_ROW     = "#1a1a35"
BG_ROW_ALT = "#151530"
ACCENT     = "#7c3aed"
ACCENT2    = "#4f46e5"
SUCCESS    = "#10b981"
DANGER     = "#ef4444"
TEXT_PRI   = "#f0f0ff"
TEXT_SEC   = "#8888aa"
BORDER     = "#2d2d5e"
SAFE_GRN   = "#064e3b"   # safety banner bg


# ─────────────────────────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────────────────────────
class CleanMyPC(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CleanMyPC  •  Safe Junk Remover")
        self.geometry("1160x750")
        self.minsize(900, 620)
        self.configure(bg=BG_DARK)

        self._all_files  = []
        self._rows       = {}       # path → iid
        self._check_vars = {}       # path → BooleanVar
        self._scanner    = None
        self._sort_col   = "size"
        self._sort_rev   = True
        self._filter_cat = "All"

        self._setup_styles()
        self._build_ui()
        self._animate_logo()

    # ── STYLES ────────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview",
                     background=BG_ROW, foreground=TEXT_PRI,
                     rowheight=30, fieldbackground=BG_ROW,
                     borderwidth=0, font=("Segoe UI", 9))
        s.configure("Treeview.Heading",
                     background=BG_CARD, foreground=TEXT_SEC,
                     borderwidth=0, font=("Segoe UI", 9, "bold"), relief="flat")
        s.map("Treeview",
              background=[("selected", ACCENT2)],
              foreground=[("selected", "#fff")])
        s.map("Treeview.Heading",
              background=[("active", BORDER)])
        s.configure("Horizontal.TProgressbar",
                     troughcolor=BG_ROW, background=ACCENT,
                     borderwidth=0, thickness=6)

    # ── BUILD UI ──────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self, bg=BG_CARD, height=68)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        self._logo = tk.Label(hdr, text="⚡ CleanMyPC",
                               bg=BG_CARD, fg=TEXT_PRI,
                               font=("Segoe UI", 21, "bold"))
        self._logo.place(x=22, rely=0.5, anchor="w")

        tk.Label(hdr, text="Safe Junk Remover — files go to Recycle Bin, not deleted forever",
                 bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).place(x=224, rely=0.5, anchor="w")

        sf = tk.Frame(hdr, bg=BG_CARD)
        sf.place(relx=1, rely=0.5, anchor="e", x=-18)
        self._badge_size  = self._badge(sf, "0 B to free",  SUCCESS)
        self._badge_size.pack(side="right", padx=3)
        self._badge_files = self._badge(sf, "0 files found", ACCENT)
        self._badge_files.pack(side="right", padx=3)

        # ── Safety banner ──
        banner = tk.Frame(self, bg="#052e16", pady=5)
        banner.pack(fill="x")
        tk.Label(banner,
                 text="🛡️  SAFE MODE  —  "
                      "Files moved to Recycle Bin (fully recoverable)  •  "
                      "Images / Videos / Documents / Audio / Executables NEVER touched  •  "
                      f"Only files older than {MIN_AGE_DAYS} days shown",
                 bg="#052e16", fg="#6ee7b7",
                 font=("Segoe UI", 8, "bold")).pack(pady=0)

        # ── Toolbar ──
        tb = tk.Frame(self, bg=BG_DARK, padx=18, pady=8)
        tb.pack(fill="x")

        self._btn_scan = self._btn(tb, "🔍  Scan Now",         self._start_scan,      ACCENT,  "#9333ea")
        self._btn_scan.pack(side="left")
        self._btn_del  = self._btn(tb, "♻️  Move to Recycle Bin", self._recycle_selected, DANGER, "#dc2626", state="disabled")
        self._btn_del.pack(side="left", padx=8)
        self._btn_open = self._btn(tb, "👁  Open / Preview",   self._open_selected,   BG_ROW,  BORDER)
        self._btn_open.pack(side="left")
        self._btn_loc  = self._btn(tb, "📂  Show in Explorer", self._reveal_in_explorer, BG_ROW, BORDER)
        self._btn_loc.pack(side="left", padx=6)

        # Category filter
        self._cat_var = tk.StringVar(value="All")
        cats = ["All", "Temp File", "Log File", "APK File",
                "Crash Dump", "Cache", "Old Backup", "Check Disk", "Junk"]
        dd = ttk.Combobox(tb, textvariable=self._cat_var, values=cats,
                           state="readonly", width=13, font=("Segoe UI", 9))
        dd.pack(side="left", padx=10)
        dd.bind("<<ComboboxSelected>>", self._apply_filter)

        self._selall_var = tk.BooleanVar(value=True)
        tk.Checkbutton(tb, text="Select All", variable=self._selall_var,
                       command=self._toggle_all,
                       bg=BG_DARK, fg=TEXT_PRI, selectcolor=BG_ROW,
                       activebackground=BG_DARK,
                       font=("Segoe UI", 9)).pack(side="left", padx=6)

        # Age filter label
        tk.Label(tb, text=f"  (Only files ≥ {MIN_AGE_DAYS} days old)",
                 bg=BG_DARK, fg=TEXT_SEC, font=("Segoe UI", 8)).pack(side="left")

        # ── Progress ──
        pf = tk.Frame(self, bg=BG_DARK, padx=18)
        pf.pack(fill="x")
        self._progress = ttk.Progressbar(pf, style="Horizontal.TProgressbar",
                                          mode="determinate", maximum=100)
        self._progress.pack(fill="x")
        self._status = tk.Label(pf, text="Press 'Scan Now' to start…",
                                 bg=BG_DARK, fg=TEXT_SEC,
                                 font=("Segoe UI", 8))
        self._status.pack(anchor="w", pady=(2, 4))

        # ── Table ──
        main = tk.Frame(self, bg=BG_DARK, padx=18, pady=2)
        main.pack(fill="both", expand=True)

        cols = ("sel", "name", "size", "category", "age", "path")
        self._tree = ttk.Treeview(main, columns=cols, show="headings",
                                   selectmode="browse")
        self._tree.heading("sel",      text="✓",           anchor="center")
        self._tree.heading("name",     text="File Name",   command=lambda: self._sort("name"))
        self._tree.heading("size",     text="Size ↓",      command=lambda: self._sort("size"))
        self._tree.heading("category", text="Category",    command=lambda: self._sort("category"))
        self._tree.heading("age",      text="Last Modified",command=lambda: self._sort("age"))
        self._tree.heading("path",     text="Full Path",   command=lambda: self._sort("path"))

        self._tree.column("sel",      width=36,  stretch=False, anchor="center")
        self._tree.column("name",     width=220, stretch=True)
        self._tree.column("size",     width=80,  stretch=False, anchor="e")
        self._tree.column("category", width=100, stretch=False, anchor="center")
        self._tree.column("age",      width=130, stretch=False, anchor="center")
        self._tree.column("path",     width=400, stretch=True)

        vsb = ttk.Scrollbar(main, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(main, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        main.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)

        for cat, col in CATEGORY_COLORS.items():
            self._tree.tag_configure(cat, foreground=col)
        self._tree.tag_configure("odd",  background=BG_ROW)
        self._tree.tag_configure("even", background=BG_ROW_ALT)

        self._tree.bind("<ButtonRelease-1>", self._on_click)
        self._tree.bind("<Double-1>",        lambda e: self._open_selected())

        # ── Footer ──
        ft = tk.Frame(self, bg=BG_CARD, height=28)
        ft.pack(fill="x")
        ft.pack_propagate(False)
        tk.Label(ft,
                 text="♻️ Files go to Recycle Bin — open & review before recycling  •  "
                      "Double-click row to preview  •  Click ✓ to toggle selection",
                 bg=BG_CARD, fg=TEXT_SEC,
                 font=("Segoe UI", 8)).place(relx=0.5, rely=0.5, anchor="center")

    # ── WIDGET HELPERS ────────────────────────────────────────────
    def _btn(self, p, text, cmd, bg, hbg, state="normal"):
        b = tk.Button(p, text=text, command=cmd,
                      bg=bg, fg=TEXT_PRI,
                      activebackground=hbg, activeforeground="white",
                      relief="flat", bd=0, padx=14, pady=7,
                      font=("Segoe UI", 9, "bold"),
                      cursor="hand2", state=state)
        b.bind("<Enter>", lambda e: b.config(bg=hbg) if b["state"]=="normal" else None)
        b.bind("<Leave>", lambda e: b.config(bg=bg)  if b["state"]=="normal" else None)
        return b

    def _badge(self, p, text, color):
        return tk.Label(p, text=text, bg=color, fg="white",
                         font=("Segoe UI", 8, "bold"), padx=9, pady=3)

    # ── SCAN ──────────────────────────────────────────────────────
    def _start_scan(self):
        if self._scanner and self._scanner.is_alive():
            self._scanner.stop()
            self._btn_scan.config(text="🔍  Scan Now")
            return
        self._clear_table()
        self._all_files.clear()
        self._btn_scan.config(text="⏹  Stop Scan")
        self._btn_del.config(state="disabled")
        self._progress["value"] = 0
        self._update_stats()
        self._scanner = Scanner(
            on_file    = lambda e: self.after(0, self._insert_row, e),
            on_done    = lambda _: self.after(0, self._finalize_scan),
            on_progress= lambda p, m: self.after(0, self._set_progress, p, m),
        )
        self._scanner.start()

    def _set_progress(self, pct, msg):
        self._progress["value"] = pct * 100
        self._status.config(text=msg)

    def _finalize_scan(self):
        self._btn_scan.config(text="🔍  Scan Now")
        self._btn_del.config(state="normal")
        self._update_stats()
        total_sz = sum(e["size"] for e in self._all_files)
        self._status.config(
            text=f"✅ Scan complete — {len(self._all_files)} junk files "
                 f"({human_size(total_sz)}) found. "
                 f"All important files were skipped.")

    # ── TABLE ─────────────────────────────────────────────────────
    def _clear_table(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._rows.clear()
        self._check_vars.clear()

    def _insert_row(self, entry):
        self._all_files.append(entry)
        if self._filter_cat == "All" or entry["category"] == self._filter_cat:
            self._draw_row(entry)

    def _draw_row(self, entry):
        path = entry["path"]
        idx  = len(self._rows)
        var  = tk.BooleanVar(value=True)
        self._check_vars[path] = var

        # Format age
        try:
            mtime  = os.path.getmtime(path)
            days   = int((time.time() - mtime) / 86400)
            age_str = f"{days}d ago"
        except Exception:
            age_str = "Unknown"

        entry["age_days"] = days if "days" in dir() else 9999

        tag_bg  = "odd" if idx % 2 == 0 else "even"
        tag_cat = entry["category"]
        iid = self._tree.insert("", "end",
                                values=("☑", entry["name"], entry["size_hr"],
                                        entry["category"], age_str, entry["path"]),
                                tags=(tag_bg, tag_cat))
        self._rows[path] = iid
        self._update_stats()

    def _rebuild_table(self):
        self._clear_table()
        for e in self._all_files:
            if self._filter_cat == "All" or e["category"] == self._filter_cat:
                self._draw_row(e)

    def _on_click(self, event):
        col = self._tree.identify_column(event.x)
        iid = self._tree.identify_row(event.y)
        if not iid or col != "#1":
            return
        path = self._path_of(iid)
        if path and path in self._check_vars:
            v = self._check_vars[path]
            v.set(not v.get())
            self._tree.set(iid, "sel", "☑" if v.get() else "☐")
            self._update_stats()

    def _path_of(self, iid):
        v = self._tree.item(iid, "values")
        return v[5] if v and len(v) >= 6 else None

    # ── FILTER / SORT ─────────────────────────────────────────────
    def _apply_filter(self, _=None):
        self._filter_cat = self._cat_var.get()
        self._rebuild_table()

    def _sort(self, col):
        km = {
            "name"    : lambda e: e["name"].lower(),
            "size"    : lambda e: e["size"],
            "category": lambda e: e["category"],
            "age"     : lambda e: e.get("age_days", 0),
            "path"    : lambda e: e["path"].lower(),
        }
        self._sort_rev = not self._sort_rev if self._sort_col == col else (col == "size")
        self._sort_col = col
        self._all_files.sort(key=km[col], reverse=self._sort_rev)
        self._rebuild_table()

    # ── SELECT ALL ────────────────────────────────────────────────
    def _toggle_all(self):
        val = self._selall_var.get()
        sym = "☑" if val else "☐"
        for path, var in self._check_vars.items():
            var.set(val)
            iid = self._rows.get(path)
            if iid and self._tree.exists(iid):
                self._tree.set(iid, "sel", sym)
        self._update_stats()

    # ── STATS ─────────────────────────────────────────────────────
    def _update_stats(self):
        count = size = 0
        for e in self._all_files:
            v = self._check_vars.get(e["path"])
            if v and v.get():
                count += 1
                size  += e["size"]
        self._badge_files.config(text=f"{count} files selected")
        self._badge_size.config( text=f"{human_size(size)} to free")

    # ── OPEN FILE ─────────────────────────────────────────────────
    def _open_selected(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Select a Row", "Click on a file row first.")
            return
        path = self._path_of(sel[0])
        if not path or not os.path.exists(path):
            messagebox.showerror("Not Found", "File no longer exists.")
            return
        try:
            os.startfile(path)
        except Exception:
            subprocess.Popen(["explorer", "/select,", path])

    def _reveal_in_explorer(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Select a Row", "Click on a file row first.")
            return
        path = self._path_of(sel[0])
        if path and os.path.exists(path):
            subprocess.Popen(["explorer", "/select,", path])

    # ── RECYCLE ───────────────────────────────────────────────────
    def _recycle_selected(self):
        to_recycle = [e for e in self._all_files
                      if self._check_vars.get(e["path"], tk.BooleanVar(value=False)).get()]

        if not to_recycle:
            messagebox.showinfo("Nothing Selected",
                                "Tick the ☑ checkboxes on files you want to recycle.")
            return

        total = sum(e["size"] for e in to_recycle)
        ok = messagebox.askyesno(
            "Move to Recycle Bin?",
            f"♻️  Move to Recycle Bin:\n\n"
            f"   {len(to_recycle)} files  ({human_size(total)})\n\n"
            f"✅ These files are JUNK files only.\n"
            f"✅ Important files were NEVER selected.\n"
            f"✅ You can RESTORE them from the Recycle Bin if needed.\n\n"
            f"Proceed?"
        )
        if not ok:
            return

        recycled = failed = 0
        freed    = 0
        failed_names = []

        for e in to_recycle:
            if not os.path.exists(e["path"]):
                continue
            if recycle(e["path"]):
                recycled += 1
                freed    += e["size"]
                iid = self._rows.pop(e["path"], None)
                if iid and self._tree.exists(iid):
                    self._tree.delete(iid)
                self._check_vars.pop(e["path"], None)
            else:
                failed += 1
                failed_names.append(e["name"])

        self._all_files = [e for e in self._all_files if e["path"] in self._rows]

        msg = f"✅ Moved {recycled} files to Recycle Bin — {human_size(freed)} freed!\n\n" \
              f"You can restore them from the Recycle Bin anytime."
        if failed:
            msg += f"\n\n⚠️ {failed} files could not be moved (in use or protected):\n"
            msg += "\n".join(f"  • {n}" for n in failed_names[:5])
        messagebox.showinfo("Done — Files in Recycle Bin", msg)
        self._update_stats()
        self._status.config(text=f"♻️ Recycled {recycled} files · {human_size(freed)} freed · Restore via Recycle Bin anytime.")

    # ── LOGO ANIMATION ────────────────────────────────────────────
    def _animate_logo(self):
        pal = [ACCENT, "#6d28d9", "#5b21b6", "#7c3aed", ACCENT2, "#4338ca"]
        idx = [0]
        def step():
            self._logo.config(fg=pal[idx[0] % len(pal)])
            idx[0] += 1
            self.after(900, step)
        self.after(900, step)


# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = CleanMyPC()
    app.mainloop()
