"""
RansomWall: Honey Files & Trap Layer
=====================================
Based on: "RansomWall: A Layered Defense System against Cryptographic
Ransomware Attacks using Machine Learning" (COMSNETS 2018)
IIT Delhi - Shaukat & Ribeiro

Architecture:
  HoneyFileManager  -> deploys decoy files & directories (Section III-B-2)
  TrapMonitor       -> watches file ops via watchdog (Section III-D-2)
  BehaviorDetector  -> detects crypto APIs, bcdedit, vssadmin, registry (Section III-D-2)
  FeatureCollector  -> aggregates triggered features -> suspicion score (Section IV-A)
  RansomWallLogger  -> structured event log
  TrapLayer         -> orchestrates everything; exposes get_status()

Paper mapping for each component is documented inline.
"""

import os
import sys
import time
import stat
import json
import shutil
import logging
import hashlib
import platform
import threading
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, UTC
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from collections import defaultdict

# --------------------------------------------------------------------------- #
# watchdog is required for file-system monitoring                             #
# --------------------------------------------------------------------------- #
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
except ImportError:
    print("[!] watchdog not installed. Run:  pip install watchdog")
    sys.exit(1)

# Optional psutil – used for real process name lookups
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════ #
# §1  CONSTANTS & CONFIGURATION                                               #
# ═══════════════════════════════════════════════════════════════════════════ #

# Paper §III-D-2: "Honey Files with user data file extensions mostly attacked
# by Ransomware"
HONEY_EXTENSIONS = [
    ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".pdf", ".txt", ".jpg", ".jpeg", ".png", ".bmp",
    ".mp4", ".avi", ".mov", ".zip", ".rar", ".csv",
    ".db",  ".sql", ".py",  ".js",  ".html", ".xml",
]

# Paper §III-D-2: "Honey Files and Honey Directories are deployed in
# critical user data folders"
def get_honey_directories() -> List[Path]:
    home = Path.home()
    print(f"[Config] Home directory: {home}")
    candidates = [
        home / "Documents",
        home / "Desktop",
        home / "Pictures",
        home / "Downloads",
        home / "Videos",
        home / "Music",
        # Fallback: always include a temp subfolder so tests work anywhere
        Path(tempfile.gettempdir()) / "ransomwall_honey",
    ]
    dirs = []
    for d in candidates:
        try:
            d.mkdir(parents=True, exist_ok=True)
            dirs.append(d)
        except PermissionError:
            pass
    return dirs

# Paper §III-D-2b: Windows Crypto DLLs that Ransomware abuses heavily
CRYPTO_DLLS = {
    "rsaenh.dll", "cryptsp.dll", "cryptbase.dll",
    "bcrypt.dll", "crypt32.dll", "cryptdll.dll",
    "cryptsvc.dll", "dssenh.dll",
}

# Paper §III-D-2c / §III-D-2d: Defense-disabling binaries
DEFENSE_BINARIES = {
    "bcdedit.exe",   # disables safe-mode boot
    "vssadmin.exe",  # deletes Volume Shadow Copies
    "wmic.exe",      # also used to delete VSS
    "wbadmin.exe",   # backup deletion
    "powershell.exe",# often used for VSS deletion via script
}

# Suspicious registry keys (paper §III-D-2e)
SUSPICIOUS_REGISTRY_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SYSTEM\CurrentControlSet\Control\SafeBoot",
]

# Suspicion score weights – maps feature name -> weight
# Paper §IV-A: "if Feature Collector observes presence of 6 or more feature
# indicators in the Compact Feature Set, the process is tagged as suspicious"
FEATURE_WEIGHTS: Dict[str, float] = {
    "honey_file_write":       2.0,   # very strong indicator
    "honey_file_rename":      2.0,
    "honey_file_delete":      2.0,
    "honey_dir_modified":     1.5,
    "crypto_api_usage":       1.5,   # massive use of Windows Crypto APIs
    "safe_mode_disabled":     3.0,   # bcdedit -> near-certain ransomware
    "vss_deletion":           3.0,   # vssadmin/wmic -> near-certain ransomware
    "registry_persistence":   1.0,
    "entropy_spike":          1.5,   # high Shannon entropy on writes
}

SUSPICION_THRESHOLD = 6.0   # triggers "suspicious" tag (maps to paper's ≥6 features)


# ═══════════════════════════════════════════════════════════════════════════ #
# §2  LOGGER                                                                  #
# ═══════════════════════════════════════════════════════════════════════════ #

class RansomWallLogger:
    """
    Structured event logger.
    Each event records: timestamp, pid, operation, file, feature, score.
    """
    def __init__(self, log_path: str = "ransomwall_trap.log"):
        self.log_path = log_path
        self._lock = threading.Lock()

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [RANSOMWALL] %(levelname)s  %(message)s",
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger("RansomWall.TrapLayer")

    def event(self, pid: int, operation: str, target: str,
              feature: str, score: float, extra: str = ""):
        entry = {
            "ts":        datetime.now(UTC).isoformat(),
            "pid":       pid,
            "operation": operation,
            "target":    target,
            "feature":   feature,
            "score":     round(score, 2),
        }
        if extra:
            entry["detail"] = extra
        with self._lock:
            self.logger.warning(json.dumps(entry))

    def info(self, msg: str):
        self.logger.info(msg)


# ═══════════════════════════════════════════════════════════════════════════ #
# §3  HONEY FILE MANAGER                                                      #
#     Paper §III-B-2: "Honey Files and Honey Directories are deployed in      #
#     critical user data folders … not expected to be modified by the user    #
#     during normal operation."                                               #
# ═══════════════════════════════════════════════════════════════════════════ #

class HoneyFileManager:
    """
    Creates and tracks honey (decoy) files across watched directories.

    Design notes from paper:
    - Files use real-world extensions that ransomware targets (.docx, .pdf …)
    - Directories are placed before actual user files to be hit first
      (paper: "placed such that Ransomware attacks them earlier than the
      critical files … many variants use Depth First Search while enlisting
      files for encryption")
    - We record SHA-256 of each honey file at creation so we can detect
      content modification even without inotify events.
    """

    HONEY_PREFIX = "__rw_honey__"   # internal marker – invisible to casual user

    def __init__(self, logger: RansomWallLogger):
        self.logger = logger
        self.honey_files: Set[str] = set()   # absolute paths
        self.honey_dirs:  Set[str] = set()
        self.checksums:   Dict[str, str] = {}   # path -> sha256

    # ---------------------------------------------------------------------- #
    def deploy(self, directories: Optional[List[Path]] = None) -> int:
        """
        Deploy honey files into each watched directory.
        Returns count of files created.
        """
        if directories is None:
            directories = get_honey_directories()

        count = 0
        for base_dir in directories:
            # Paper: also create Honey Directories inside the watched folder
            honey_dir = base_dir / (self.HONEY_PREFIX + "dir")
            try:
                honey_dir.mkdir(exist_ok=True)
                self.honey_dirs.add(str(honey_dir))
            except PermissionError:
                continue

            # Create one honey file per extension in the directory itself
            for ext in HONEY_EXTENSIONS:
                fpath = base_dir / (self.HONEY_PREFIX + "file" + ext)
                try:
                    self._write_honey_file(fpath)
                    count += 1
                except PermissionError:
                    pass

            # Create a few inside the honey directory too
            for ext in [".docx", ".pdf", ".jpg", ".txt"]:
                fpath = honey_dir / (self.HONEY_PREFIX + "nested" + ext)
                try:
                    self._write_honey_file(fpath)
                    count += 1
                except PermissionError:
                    pass

        self.logger.info(
            f"[HoneyFileManager] Deployed {count} honey files across "
            f"{len(directories)} directories."
        )
        return count

    # ---------------------------------------------------------------------- #
    def _write_honey_file(self, path: Path):
        """Write a realistic-looking decoy file and record its checksum."""
        content = (
            f"This is a RansomWall honey file.\n"
            f"Created: {datetime.now(UTC).isoformat()}\n"
            f"Path: {path}\n"
            f"{'x' * 512}\n"   # padding to look non-trivial
        ).encode()
        path.write_bytes(content)
        self.honey_files.add(str(path))
        self.checksums[str(path)] = self._sha256(path)

    # ---------------------------------------------------------------------- #
    def is_honey(self, path: str) -> bool:
        """Return True if the given path is a known honey file or inside a honey dir."""
        if path in self.honey_files:
            return True
        if any(path.startswith(d) for d in self.honey_dirs):
            return True
        return False

    # ---------------------------------------------------------------------- #
    def verify_integrity(self) -> List[str]:
        """
        Scan honey files for content changes (catches writes that watchdog missed).
        Returns list of tampered paths.
        """
        tampered = []
        for fpath, original_hash in list(self.checksums.items()):
            p = Path(fpath)
            if not p.exists():
                tampered.append(fpath)   # deleted
                continue
            if self._sha256(p) != original_hash:
                tampered.append(fpath)   # content changed
        return tampered

    # ---------------------------------------------------------------------- #
    def cleanup(self):
        """Remove all deployed honey files (call on shutdown)."""
        for fpath in list(self.honey_files):
            try:
                Path(fpath).unlink(missing_ok=True)
            except Exception:
                pass
        for dpath in list(self.honey_dirs):
            try:
                shutil.rmtree(dpath, ignore_errors=True)
            except Exception:
                pass
        self.logger.info("[HoneyFileManager] Cleanup complete.")

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


# ═══════════════════════════════════════════════════════════════════════════ #
# §4  FEATURE COLLECTOR                                                       #
#     Paper §IV-A: accumulates per-process feature values; tags a process    #
#     as suspicious when ≥6 indicators fire.                                  #
# ═══════════════════════════════════════════════════════════════════════════ #

@dataclass
class ProcessRecord:
    pid:               int
    name:              str = "unknown"
    suspicion_score:   float = 0.0
    triggered_features: Dict[str, int] = field(default_factory=dict)
    events:            List[dict]       = field(default_factory=list)
    flagged_suspicious: bool            = False
    first_seen:        str              = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )


class FeatureCollector:
    """
    Central store for per-process suspicion state.
    Thread-safe accumulation of feature hits and scoring.
    """
    def __init__(self, logger: RansomWallLogger):
        self.logger = logger
        self._records: Dict[int, ProcessRecord] = {}
        self._lock = threading.Lock()

    # ---------------------------------------------------------------------- #
    def record_feature(self, pid: int, feature: str,
                       target: str = "", extra: str = "") -> ProcessRecord:
        """
        Register one feature hit for `pid`.
        Returns the updated ProcessRecord.
        """
        weight = FEATURE_WEIGHTS.get(feature, 1.0)

        with self._lock:
            if pid not in self._records:
                name = self._resolve_name(pid)
                self._records[pid] = ProcessRecord(pid=pid, name=name)
            rec = self._records[pid]

            rec.triggered_features[feature] = (
                rec.triggered_features.get(feature, 0) + 1
            )
            rec.suspicion_score += weight
            rec.events.append({
                "ts":      datetime.now(UTC).isoformat(),
                "feature": feature,
                "target":  target,
                "extra":   extra,
            })

            # Paper §IV-A threshold logic
            if (not rec.flagged_suspicious
                    and rec.suspicion_score >= SUSPICION_THRESHOLD):
                rec.flagged_suspicious = True
                self.logger.info(
                    f"[FeatureCollector] PID {pid} ({rec.name}) FLAGGED SUSPICIOUS  "
                    f"score={rec.suspicion_score:.1f}  "
                    f"features={list(rec.triggered_features.keys())}"
                )

        self.logger.event(pid, feature, target, feature,
                          rec.suspicion_score, extra)
        return rec

    # ---------------------------------------------------------------------- #
    def get_status(self, pid: Optional[int] = None) -> dict:
        """
        Return detection status.
        If pid is given -> single-process dict.
        Otherwise -> dict of all suspicious processes.
        """
        with self._lock:
            if pid is not None:
                rec = self._records.get(pid)
                if rec is None:
                    return {}
                return self._serialize(rec)
            return {
                p: self._serialize(r)
                for p, r in self._records.items()
                if r.flagged_suspicious
            }

    # ---------------------------------------------------------------------- #
    @staticmethod
    def _serialize(rec: ProcessRecord) -> dict:
        return {
            "process_id":         rec.pid,
            "process_name":       rec.name,
            "suspicion_score":    round(rec.suspicion_score, 2),
            "triggered_features": rec.triggered_features,
            "flagged_suspicious": rec.flagged_suspicious,
            "first_seen":         rec.first_seen,
            "event_count":        len(rec.events),
        }

    @staticmethod
    def _resolve_name(pid: int) -> str:
        if PSUTIL_AVAILABLE:
            try:
                return psutil.Process(pid).name()
            except Exception:
                pass
        return "unknown"


# ═══════════════════════════════════════════════════════════════════════════ #
# §5  TRAP MONITOR (watchdog handler)                                         #
#     Paper §III-D-2a: "Write, Rename and Delete operations on Honey          #
#     Files/Directories are tracked for malicious activities."                #
# ═══════════════════════════════════════════════════════════════════════════ #

class TrapEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler.
    Fires when any filesystem event occurs under watched directories.
    We check whether the affected path is a honey file / honey directory,
    then record the appropriate feature.
    """

    def __init__(self, honey_mgr: HoneyFileManager,
                 collector: FeatureCollector,
                 logger: RansomWallLogger):
        super().__init__()
        self.honey_mgr = honey_mgr
        self.collector = collector
        self.logger    = logger

    # ---------------------------------------------------------------------- #
    def _pid_from_event(self, event: FileSystemEvent) -> int:
        """
        Watchdog does not expose PIDs on most platforms.
        On Linux we probe /proc for recently modified entries;
        on Windows / macOS we return 0 (unknown) – a real implementation
        would use a kernel filter driver (paper §IV-B).
        """
        if platform.system() == "Linux":
            return self._linux_guess_pid(event.src_path)
        return 0   # unknown PID on non-Linux without kernel driver

    # ---------------------------------------------------------------------- #
    @staticmethod
    def _linux_guess_pid(path: str) -> int:
        """
        Heuristic: scan /proc/*/fd for open handles to this file.
        This is a simulation of what a kernel IRP filter does natively.
        """
        try:
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                fd_dir = f"/proc/{entry.name}/fd"
                try:
                    for fd in os.scandir(fd_dir):
                        try:
                            if os.readlink(fd.path) == path:
                                return int(entry.name)
                        except OSError:
                            pass
                except PermissionError:
                    pass
        except Exception:
            pass
        return 0

    # ---------------------------------------------------------------------- #
    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            if self.honey_mgr.is_honey(event.src_path):
                self._fire(event.src_path, "honey_dir_modified", event)
            return
        if self.honey_mgr.is_honey(event.src_path):
            self._fire(event.src_path, "honey_file_write", event)

    def on_deleted(self, event: FileSystemEvent):
        path = event.src_path
        if self.honey_mgr.is_honey(path):
            self._fire(path, "honey_file_delete", event)

    def on_moved(self, event):
        # watchdog sends FileMovedEvent for renames
        src = event.src_path
        dst = getattr(event, "dest_path", "")
        if self.honey_mgr.is_honey(src) or self.honey_mgr.is_honey(dst):
            self._fire(src, "honey_file_rename", event,
                       extra=f"-> {dst}")

    def on_created(self, event: FileSystemEvent):
        # A new file inside a honey directory is also suspicious
        if not event.is_directory:
            if self.honey_mgr.is_honey(event.src_path):
                self._fire(event.src_path, "honey_file_write", event,
                           extra="new file in honey dir")

    # ---------------------------------------------------------------------- #
    def _fire(self, path: str, feature: str,
              event: FileSystemEvent, extra: str = ""):
        pid = self._pid_from_event(event)
        self.logger.info(
            f"[TrapMonitor] {feature.upper()}  path={path}  pid={pid}"
        )
        self.collector.record_feature(pid, feature, target=path, extra=extra)


# ═══════════════════════════════════════════════════════════════════════════ #
# §6  BEHAVIOR DETECTOR                                                       #
#     Covers paper §III-D-2b / §III-D-2c / §III-D-2d / §III-D-2e:           #
#       • Suspicious Windows Crypto API usage                                 #
#       • Disabling safe-mode boot (bcdedit)                                  #
#       • Deletion of Volume Shadow Copies (vssadmin / wmic)                  #
#       • Suspicious Registry modifications                                   #
# ═══════════════════════════════════════════════════════════════════════════ #

class BehaviorDetector:
    """
    Polls running processes for:
      1. Loaded Crypto DLLs (Windows) / linked crypto libs (Linux sim)
      2. Defense-disabling processes (bcdedit, vssadmin, wmic …)
      3. Registry persistence patterns (Windows only)
      4. Shannon entropy of recently written files (high entropy ≈ encryption)
    """

    def __init__(self, collector: FeatureCollector, logger: RansomWallLogger):
        self.collector  = collector
        self.logger     = logger
        self._seen_pids: Set[int] = set()   # avoid double-counting per pid
        self._stop      = threading.Event()
        self._thread    = None

    # ---------------------------------------------------------------------- #
    def start(self, interval: float = 2.0):
        self._thread = threading.Thread(
            target=self._poll_loop,
            args=(interval,),
            daemon=True,
            name="BehaviorDetector",
        )
        self._thread.start()
        self.logger.info("[BehaviorDetector] Started polling loop.")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ---------------------------------------------------------------------- #
    def _poll_loop(self, interval: float):
        while not self._stop.is_set():
            self._scan_processes()
            time.sleep(interval)

    # ---------------------------------------------------------------------- #
    def _scan_processes(self):
        """
        Iterate running processes; flag those exhibiting suspicious behavior.
        With psutil this is a real scan; without it we simulate.
        """
        if not PSUTIL_AVAILABLE:
            self._simulate_scan()
            return

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid  = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()

                # §III-D-2c  bcdedit usage -> safe-mode disabling
                if "bcdedit" in name or "bcdedit" in cmdline:
                    if "bootstatuspolicy" in cmdline or "safeboot" in cmdline:
                        self._fire(pid, "safe_mode_disabled",
                                   target=name, extra=cmdline[:120])

                # §III-D-2d  vssadmin / wmic -> VSS deletion
                if name in ("vssadmin.exe", "wmic.exe", "wbadmin.exe"):
                    if any(kw in cmdline for kw in
                           ("delete", "shadowcopy", "shadows")):
                        self._fire(pid, "vss_deletion",
                                   target=name, extra=cmdline[:120])

                # §III-D-2b  Crypto API DLL loading (Windows only)
                if platform.system() == "Windows":
                    try:
                        dlls = set()
                        for m in proc.memory_maps():
                            path = getattr(m, "path", "") or ""
                            dll_name = os.path.basename(path).lower()
                            if dll_name:
                                dlls.add(dll_name)
                        hits = dlls & CRYPTO_DLLS
                        if hits and pid not in self._seen_pids:
                            # Only flag if MULTIPLE crypto DLLs loaded together
                            if len(hits) >= 3:
                                self._fire(pid, "crypto_api_usage",
                                           target=name,
                                           extra=",".join(sorted(hits)))
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                # §III-D-2e  Registry persistence (Windows only)
                if platform.system() == "Windows":
                    self._check_registry(pid, proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    psutil.ZombieProcess):
                pass

    # ---------------------------------------------------------------------- #
    def _check_registry(self, pid: int, proc):
        """
        Simulate registry monitoring on Windows.
        A real implementation would use RegNotifyChangeKeyValue or
        a kernel callback (paper §IV-B).
        Here we check proc's open handles for registry paths.
        """
        try:
            for h in proc.open_files():
                for key in SUSPICIOUS_REGISTRY_KEYS:
                    if key.lower() in h.path.lower():
                        self._fire(pid, "registry_persistence",
                                   target=h.path)
                        break
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    # ---------------------------------------------------------------------- #
    def _simulate_scan(self):
        """
        Fallback simulation when psutil is unavailable.
        Parses `ps` output (Linux/macOS) for suspicious binary names.
        """
        if platform.system() == "Windows":
            return
        try:
            out = subprocess.check_output(
                ["ps", "-eo", "pid,comm,args"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in out.splitlines()[1:]:
                parts = line.split(None, 2)
                if len(parts) < 2:
                    continue
                pid  = int(parts[0])
                name = parts[1].lower()
                args = parts[2].lower() if len(parts) > 2 else ""
                if "bcdedit" in name:
                    self._fire(pid, "safe_mode_disabled", target=name)
                if "vssadmin" in name and "delete" in args:
                    self._fire(pid, "vss_deletion", target=name)
        except Exception:
            pass

    # ---------------------------------------------------------------------- #
    def check_file_entropy(self, path: str, pid: int = 0) -> Optional[float]:
        """
        Paper §III-D-3g: "Entropy of data buffer in memory modified during
        file write operation to a value around 8 indicates encryption."
        We approximate by reading the file and computing Shannon entropy.
        Returns entropy value; fires feature if > 7.5.
        """
        try:
            data = Path(path).read_bytes()
            if not data:
                return None
            entropy = self._shannon_entropy(data)
            if entropy > 7.5:
                self.logger.info(
                    f"[BehaviorDetector] High entropy ({entropy:.2f}) "
                    f"in {path}  pid={pid}"
                )
                self.collector.record_feature(
                    pid, "entropy_spike", target=path,
                    extra=f"entropy={entropy:.2f}"
                )
            return entropy
        except Exception:
            return None

    # ---------------------------------------------------------------------- #
    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        from math import log2
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        length = len(data)
        return -sum(
            (c / length) * log2(c / length)
            for c in freq.values()
            if c > 0
        )

    # ---------------------------------------------------------------------- #
    def _fire(self, pid: int, feature: str,
              target: str = "", extra: str = ""):
        """Record feature only once per pid to avoid score inflation."""
        key = (pid, feature)
        if key not in self._seen_pids:
            self._seen_pids.add(key)
            self.collector.record_feature(pid, feature,
                                          target=target, extra=extra)


# ═══════════════════════════════════════════════════════════════════════════ #
# §7  INTEGRITY POLLER                                                        #
#     Periodic checksum verification catches writes that bypass inotify.      #
# ═══════════════════════════════════════════════════════════════════════════ #

class IntegrityPoller:
    """
    Periodically calls HoneyFileManager.verify_integrity() to detect
    content changes not caught by watchdog (e.g., direct disk writes).
    """
    def __init__(self, honey_mgr: HoneyFileManager,
                 collector: FeatureCollector,
                 logger: RansomWallLogger,
                 interval: float = 5.0):
        self.honey_mgr = honey_mgr
        self.collector = collector
        self.logger    = logger
        self.interval  = interval
        self._stop     = threading.Event()
        self._thread   = None

    def start(self):
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="IntegrityPoller"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while not self._stop.is_set():
            tampered = self.honey_mgr.verify_integrity()
            for path in tampered:
                self.logger.info(
                    f"[IntegrityPoller] Tampered honey file detected: {path}"
                )
                self.collector.record_feature(
                    0, "honey_file_write", target=path,
                    extra="integrity-check tamper"
                )
            time.sleep(self.interval)


# ═══════════════════════════════════════════════════════════════════════════ #
# §8  TRAP LAYER  –  main orchestrator                                        #
# ═══════════════════════════════════════════════════════════════════════════ #

class TrapLayer:
    """
    RansomWall Honey Files & Trap Layer

    Orchestrates:
      • HoneyFileManager  – deploy / track honey files
      • TrapEventHandler  – watchdog filesystem monitoring
      • BehaviorDetector  – process-level behavior scanning
      • IntegrityPoller   – periodic checksum validation
      • FeatureCollector  – per-process scoring & flagging

    Public API:
      start()             – deploy honey files, start all monitors
      stop()              – clean shutdown (optionally removes honey files)
      get_status(pid)     – returns detection result dict
    """

    def __init__(self,
                 watch_dirs: Optional[List[Path]] = None,
                 log_path:   str                  = "ransomwall_trap.log",
                 cleanup_on_exit: bool            = True):

        self.watch_dirs      = watch_dirs or get_honey_directories()
        self.cleanup_on_exit = cleanup_on_exit

        # Core components
        self.logger    = RansomWallLogger(log_path)
        self.collector = FeatureCollector(self.logger)
        self.honey_mgr = HoneyFileManager(self.logger)
        self.behavior  = BehaviorDetector(self.collector, self.logger)
        self.poller    = IntegrityPoller(self.honey_mgr, self.collector,
                                         self.logger)

        # watchdog
        self._observer = Observer()
        self._handler  = TrapEventHandler(self.honey_mgr,
                                          self.collector, self.logger)
        self._running  = False

    # ---------------------------------------------------------------------- #
    def start(self):
        if self._running:
            return
        self._running = True

        # 1. Deploy honey files
        self.honey_mgr.deploy(self.watch_dirs)

        # 2. Schedule watchdog observers for each directory
        for d in self.watch_dirs:
            if d.exists():
                self._observer.schedule(self._handler, str(d), recursive=True)

        self._observer.start()
        self.logger.info(
            f"[TrapLayer] Watchdog monitoring {len(self.watch_dirs)} dirs."
        )

        # 3. Behavior scanner (process-level)
        self.behavior.start(interval=2.0)

        # 4. Integrity poller (fallback checksum verification)
        self.poller.start()

        self.logger.info("[TrapLayer] All subsystems active. Monitoring…")

    # ---------------------------------------------------------------------- #
    def stop(self):
        self.logger.info("[TrapLayer] Shutting down…")
        self._observer.stop()
        self._observer.join()
        self.behavior.stop()
        self.poller.stop()
        if self.cleanup_on_exit:
            self.honey_mgr.cleanup()
        self._running = False
        self.logger.info("[TrapLayer] Shutdown complete.")

    # ---------------------------------------------------------------------- #
    def get_status(self, pid: Optional[int] = None) -> dict:
        """
        Paper §IV-A integration hook:
        Returns { process_id, suspicion_score, triggered_features }
        for a given pid, or all suspicious pids if pid is None.
        """
        return self.collector.get_status(pid)

    # ---------------------------------------------------------------------- #
    def inject_test_event(self, feature: str, pid: int = 9999,
                          target: str = "test"):
        """
        Manually inject a feature event for testing / unit-test harness.
        Simulates what a kernel IRP filter would report.
        """
        self.collector.record_feature(pid, feature, target=target,
                                      extra="injected-test")

    # ---------------------------------------------------------------------- #
    def run_forever(self):
        """Blocking loop; prints status every 10 seconds."""
        self.start()
        try:
            while True:
                time.sleep(10)
                suspects = self.get_status()
                if suspects:
                    print("\n" + "═" * 60)
                    print("  ⚠  SUSPICIOUS PROCESSES DETECTED")
                    print("═" * 60)
                    for pid, info in suspects.items():
                        print(f"  PID {pid:>6}  |  {info['process_name']:<20}  "
                              f"|  score={info['suspicion_score']:.1f}  "
                              f"|  features={list(info['triggered_features'].keys())}")
                    print("═" * 60 + "\n")
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user.")
        finally:
            self.stop()


# ═══════════════════════════════════════════════════════════════════════════ #
# §9  DEMO / SELF-TEST                                                        #
# ═══════════════════════════════════════════════════════════════════════════ #

def run_demo():
    """
    Demonstrates the Trap Layer without needing actual ransomware.
    Simulates each feature trigger type and prints the resulting status.
    """
    print("\n" + "═" * 65)
    print("  RansomWall – Honey Files & Trap Layer  (Demo / Self-Test)")
    print("  Based on COMSNETS 2018 paper by Shaukat & Ribeiro, IIT Delhi")
    print("═" * 65 + "\n")

    # Use a temp directory so we don't touch real user files
    demo_dir = Path(tempfile.mkdtemp(prefix="rw_demo_"))
    trap = TrapLayer(
        watch_dirs=[demo_dir],
        log_path=str(demo_dir / "ransomwall_trap.log"),
        cleanup_on_exit=True,
    )

    print(f"[Demo] Watch directory: {demo_dir}")
    trap.start()
    time.sleep(1)   # let watchdog settle

    print("\n[Demo] Simulating Ransomware attack events …\n")

    sim_pid = 1337   # fake ransomware PID

    # — Honey file write (paper §III-D-2a)
    print("  [1/5] Honey file write")
    trap.inject_test_event("honey_file_write", pid=sim_pid,
                           target=str(demo_dir / "__rw_honey__file.docx"))
    time.sleep(0.3)

    # — Honey file rename (paper §III-D-2a)
    print("  [2/5] Honey file rename")
    trap.inject_test_event("honey_file_rename", pid=sim_pid,
                           target=str(demo_dir / "__rw_honey__file.docx"))
    time.sleep(0.3)

    # — Safe-mode disabling via bcdedit (paper §III-D-2c)
    print("  [3/5] Safe-mode boot disable (bcdedit)")
    trap.inject_test_event("safe_mode_disabled", pid=sim_pid,
                           target="bcdedit.exe")
    time.sleep(0.3)

    # — VSS deletion via vssadmin (paper §III-D-2d)
    print("  [4/5] Volume Shadow Copy deletion (vssadmin)")
    trap.inject_test_event("vss_deletion", pid=sim_pid,
                           target="vssadmin.exe")
    time.sleep(0.3)

    # — Crypto API usage (paper §III-D-2b)
    print("  [5/5] Suspicious Crypto API usage")
    trap.inject_test_event("crypto_api_usage", pid=sim_pid,
                           target="rsaenh.dll,bcrypt.dll,crypt32.dll")
    time.sleep(0.5)

    # — Now also trigger a REAL watchdog event by modifying a honey file
    honey_files = list(trap.honey_mgr.honey_files)
    if honey_files:
        print("\n[Demo] Physically writing to a honey file to test watchdog …")
        Path(honey_files[0]).write_text("ENCRYPTED_DATA_SIMULATION")
        time.sleep(1.5)   # watchdog needs a moment

    # Print results
    print("\n" + "═" * 65)
    print("  DETECTION RESULTS")
    print("═" * 65)
    status = trap.get_status(sim_pid)
    if status:
        print(f"  Process ID     : {status['process_id']}")
        print(f"  Process Name   : {status['process_name']}")
        print(f"  Suspicion Score: {status['suspicion_score']}")
        print(f"  Flagged        : {status['flagged_suspicious']}")
        print(f"  Features Hit   :")
        for feat, count in status["triggered_features"].items():
            w = FEATURE_WEIGHTS.get(feat, 1.0)
            print(f"    • {feat:<28} ×{count}  (weight={w})")
    else:
        print("  No suspicious activity recorded for demo PID.")

    all_suspects = trap.get_status()
    print(f"\n  Total suspicious processes: {len(all_suspects)}")
    print("═" * 65)

    trap.stop()
    shutil.rmtree(demo_dir, ignore_errors=True)
    print("\n[Demo] Complete. Log saved to ransomwall_trap.log\n")


# ═══════════════════════════════════════════════════════════════════════════ #
# Entry point                                                                 #
# ═══════════════════════════════════════════════════════════════════════════ #

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--monitor":
        # Real monitoring mode
        trap = TrapLayer()
        trap.run_forever()
    else:
        # Self-test / demo mode
        run_demo()
