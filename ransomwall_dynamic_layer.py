"""
RansomWall: Dynamic Analysis Engine
=====================================
Based on: "RansomWall: A Layered Defense System against Cryptographic
Ransomware Attacks using Machine Learning" (COMSNETS 2018)
IIT Delhi - Shaukat & Ribeiro

Paper §III-B-3 / §III-D-3 (Dynamic Analysis Layer):
  "The Dynamic Analysis Engine monitors file system operations (IRPs) in
   real-time: Read, Write, Rename, Delete, and Directory Query operations.
   It also detects entropy spikes in written data and file fingerprint
   mismatches (extension vs. magic-byte content)."

Feature set tracked (paper §III-D-3):
  file_read             – IRP_MJ_READ count per bucket
  file_write            – IRP_MJ_WRITE count per bucket
  file_rename           – IRP_MJ_SET_INFORMATION (rename) count
  file_delete           – IRP_MJ_SET_INFORMATION (delete) count
  dir_query             – IRP_MJ_DIRECTORY (enum) count
  fingerprint_mismatch  – extension does not match magic bytes

Integration:
  DynamicEngine is started by main.py alongside TrapLayer.
  get_status(pid) returns a dict compatible with FeatureAggregator in main.py.
  inject_irp(op, pid, ...) is the testing / dataset-generation interface.
"""

import os
import sys
import math
import time
import logging
import hashlib
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("RansomWall.DynamicLayer")

# ── Optional watchdog ─────────────────────────────────────────────────────────
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    log.debug("[DynamicLayer] watchdog not available; filesystem events disabled.")

# ── Optional psutil ───────────────────────────────────────────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ── Magic-byte map for fingerprint mismatch detection ─────────────────────────
# Maps file extension -> expected leading magic bytes (hex prefix)
MAGIC_BYTES: Dict[str, bytes] = {
    ".pdf":  b"%PDF",
    ".png":  b"\x89PNG",
    ".jpg":  bytes([0xFF, 0xD8, 0xFF]),
    ".jpeg": bytes([0xFF, 0xD8, 0xFF]),
    ".zip":  b"PK\x03\x04",
    ".docx": b"PK\x03\x04",   # DOCX is a ZIP
    ".xlsx": b"PK\x03\x04",   # XLSX is a ZIP
    ".pptx": b"PK\x03\x04",   # PPTX is a ZIP
    ".exe":  b"MZ",
    ".dll":  b"MZ",
    ".mp4":  bytes([0x00, 0x00, 0x00]),  # ftyp boxes vary; just check non-empty
    ".gif":  b"GIF",
    ".bmp":  b"BM",
}

# Entropy threshold for detecting encrypted / compressed writes (paper §III-D-3g)
ENTROPY_THRESHOLD = 7.2

# Suspicion score per dynamic feature (weights calibrated to paper §IV-A)
DYN_FEATURE_WEIGHTS = {
    "file_write":           0.15,
    "file_rename":          0.25,
    "file_delete":          0.20,
    "file_read":            0.05,
    "dir_query":            0.05,
    "fingerprint_mismatch": 1.50,
    "entropy_spike":        1.00,
}

# Thresholds – counts above which a feature contributes to suspicion
COUNT_THRESHOLDS = {
    "file_write":   10,
    "file_rename":  5,
    "file_delete":  5,
    "file_read":    15,
    "dir_query":    10,
}


# ════════════════════════════════════════════════════════════════════════════ #
# PER-PROCESS STATE
# ════════════════════════════════════════════════════════════════════════════ #

@dataclass
class ProcessState:
    """Accumulated IRP counts and derived flags for a single monitored PID."""
    pid:                int
    read_count:         int   = 0
    write_count:        int   = 0
    rename_count:       int   = 0
    delete_count:       int   = 0
    dir_query_count:    int   = 0
    fingerprint_mismatch: int = 0
    entropy_spike_count:  int = 0

    # Files recently touched by this PID (for backup layer integration)
    modified_files: List[str] = field(default_factory=list)

    # Suspicion score derived from dynamic features only
    suspicion_score: float = 0.0

    def feature_vector(self) -> dict:
        """Return feature dict for MLModel / FeatureAggregator."""
        return {
            "read_count":           self.read_count,
            "write_count":          self.write_count,
            "rename_count":         self.rename_count,
            "delete_count":         self.delete_count,
            "dir_query_count":      self.dir_query_count,
            "fingerprint_mismatch": self.fingerprint_mismatch,
        }

    def recompute_score(self) -> float:
        """
        Paper §IV-A: dynamic layer contributes to combined suspicion score.
        Count-based thresholds map to binary indicators; then weighted sum.
        """
        score = 0.0
        counts = {
            "file_write":  self.write_count,
            "file_rename": self.rename_count,
            "file_delete": self.delete_count,
            "file_read":   self.read_count,
            "dir_query":   self.dir_query_count,
        }
        for feat, count in counts.items():
            threshold = COUNT_THRESHOLDS.get(feat, 5)
            if count >= threshold:
                score += DYN_FEATURE_WEIGHTS[feat] * min(count / threshold, 5)

        if self.fingerprint_mismatch:
            score += DYN_FEATURE_WEIGHTS["fingerprint_mismatch"] * self.fingerprint_mismatch
        if self.entropy_spike_count:
            score += DYN_FEATURE_WEIGHTS["entropy_spike"] * self.entropy_spike_count

        self.suspicion_score = round(score, 3)
        return self.suspicion_score


# ════════════════════════════════════════════════════════════════════════════ #
# WATCHDOG HANDLER (filesystem event -> IRP simulation)
# ════════════════════════════════════════════════════════════════════════════ #

if WATCHDOG_AVAILABLE:
    class _DynamicEventHandler(FileSystemEventHandler):
        """
        Translates watchdog filesystem events into DynamicEngine IRP injections.
        Since watchdog doesn't expose PIDs, we use PID=0 (unknown) for real
        filesystem events — the kernel filter driver would supply the real PID.
        """

        def __init__(self, engine: "DynamicEngine"):
            super().__init__()
            self.engine = engine

        def on_modified(self, event: FileSystemEvent):
            if not event.is_directory:
                self.engine.inject_irp("write", pid=0, path=event.src_path)

        def on_deleted(self, event: FileSystemEvent):
            self.engine.inject_irp("delete", pid=0, path=event.src_path)

        def on_moved(self, event):
            dst = getattr(event, "dest_path", "")
            self.engine.inject_irp("rename", pid=0,
                                   path=event.src_path, dst_path=dst)

        def on_created(self, event: FileSystemEvent):
            if not event.is_directory:
                self.engine.inject_irp("write", pid=0, path=event.src_path)


# ════════════════════════════════════════════════════════════════════════════ #
# DYNAMIC ENGINE — main class
# ════════════════════════════════════════════════════════════════════════════ #

class DynamicEngine:
    """
    RansomWall Dynamic Analysis Engine.

    Tracks per-process file I/O rates and detects:
      • Mass file write/rename/delete (bulk encryption pattern)
      • Directory enumeration (ransomware scans before encrypting)
      • Fingerprint mismatch (extension changed without magic-byte match)
      • High Shannon entropy in written data (encryption indicator)

    Public API (matches what main.py and generate_dataset.py expect):
      start()                   – begin real filesystem monitoring
      stop()                    – graceful shutdown
      get_status(pid=None)      – return status dict for a PID or all PIDs
      inject_irp(op, pid, ...)  – inject a synthetic IRP (testing/dataset gen)
    """

    def __init__(self,
                 watch_dirs: Optional[List[Path]] = None,
                 log_path: str = "ransomwall_dynamic.log"):

        self._watch_dirs: List[Path] = [Path(d) for d in (watch_dirs or [])]
        self._states: Dict[int, ProcessState] = {}
        self._lock = threading.Lock()
        self._running = False

        # Watchdog observer
        self._observer = Observer() if WATCHDOG_AVAILABLE else None
        self._handler  = _DynamicEventHandler(self) if WATCHDOG_AVAILABLE else None

        # Configure file logging
        if not logging.getLogger("RansomWall.DynamicLayer").handlers:
            fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
            fh.setFormatter(logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(name)s  |  %(message)s",
                datefmt="%H:%M:%S",
            ))
            log.addHandler(fh)

        log.info(f"[DynamicEngine] Initialized. Watch dirs: {self._watch_dirs}")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True

        if WATCHDOG_AVAILABLE and self._observer and self._handler:
            for d in self._watch_dirs:
                if d.exists():
                    self._observer.schedule(self._handler, str(d), recursive=True)
            self._observer.start()
            log.info(
                f"[DynamicEngine] Watchdog monitoring "
                f"{len(self._watch_dirs)} directories."
            )
        else:
            log.info("[DynamicEngine] Running in inject-only mode (no watchdog).")

    def stop(self):
        self._running = False
        if WATCHDOG_AVAILABLE and self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
        log.info("[DynamicEngine] Stopped.")

    # ── IRP injection (testing + dataset generation interface) ─────────────────

    def inject_irp(self,
                   op:       str,
                   pid:      int,
                   path:     str = "",
                   dst_path: str = "") -> None:
        """
        Inject a synthetic IRP event for PID.

        op values (paper §III-D-3):
          "read"      – IRP_MJ_READ
          "write"     – IRP_MJ_WRITE
          "rename"    – IRP_MJ_SET_INFORMATION (FileRenameInformation)
          "delete"    – IRP_MJ_SET_INFORMATION (FileDispositionInformation)
          "dir_query" – IRP_MJ_DIRECTORY

        Automatically computes:
          - fingerprint_mismatch (if dst_path extension != magic bytes)
          - entropy_spike (if path exists and written data has high entropy)
        """
        with self._lock:
            if pid not in self._states:
                self._states[pid] = ProcessState(pid=pid)
            state = self._states[pid]

            op = op.lower().strip()

            if op in ("read", "r"):
                state.read_count += 1

            elif op in ("write", "w"):
                state.write_count += 1
                if path:
                    if path not in state.modified_files:
                        state.modified_files.append(path)
                    # Check entropy of written file
                    self._check_entropy(state, path)

            elif op in ("rename", "mv", "move"):
                state.rename_count += 1
                if path and dst_path:
                    # Fingerprint mismatch check (paper §III-D-3f)
                    if self._is_fingerprint_mismatch(path, dst_path):
                        state.fingerprint_mismatch += 1
                        log.info(
                            f"[DynamicEngine] Fingerprint mismatch  "
                            f"PID={pid}  {path} -> {dst_path}"
                        )
                if path and path not in state.modified_files:
                    state.modified_files.append(path)

            elif op in ("delete", "del", "rm"):
                state.delete_count += 1
                if path and path not in state.modified_files:
                    state.modified_files.append(path)

            elif op in ("dir_query", "dir", "enum", "query"):
                state.dir_query_count += 1

            else:
                log.debug(f"[DynamicEngine] Unknown IRP op '{op}' for PID={pid}")
                return

            # Recompute dynamic suspicion score after each IRP
            state.recompute_score()

        log.debug(
            f"[DynamicEngine] IRP  op={op:<10}  PID={pid}  "
            f"path={path[:40] if path else ''}  "
            f"score={state.suspicion_score:.2f}"
        )

    # ── Status query ──────────────────────────────────────────────────────────

    def get_status(self, pid: Optional[int] = None) -> dict:
        """
        Return dynamic layer status in a format compatible with
        FeatureAggregator.build() in main.py.

        Single PID:
          Returns dict with keys: suspicion_score, feature_vector, modified_files

        All PIDs (pid=None):
          Returns {pid: status_dict, ...} for ALL tracked PIDs
          (main.py filters by suspicion threshold itself).
        """
        with self._lock:
            if pid is not None:
                state = self._states.get(pid)
                if state is None:
                    return {}
                return self._serialize(state)

            return {p: self._serialize(s) for p, s in self._states.items()}

    @staticmethod
    def _serialize(state: ProcessState) -> dict:
        return {
            "pid":             state.pid,
            "suspicion_score": state.suspicion_score,
            "feature_vector":  state.feature_vector(),
            "modified_files":  list(state.modified_files),
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_fingerprint_mismatch(src: str, dst: str) -> bool:
        """
        Paper §III-D-3f: Check if the destination extension implies a different
        file type than the actual magic bytes of the source file.

        Example: data.docx renamed to data.docx.encrypted  =>  mismatch
                 data.pdf  renamed to data.pdf.locked       =>  mismatch
        """
        src_ext = Path(src).suffix.lower()
        dst_ext = Path(dst).suffix.lower()

        # If extension changed AND destination has a suspicious suffix
        ransomware_suffixes = {
            ".locked", ".encrypted", ".enc", ".crypt", ".crypto",
            ".zepto", ".locky", ".cerber", ".wcry", ".wncry",
        }

        if dst_ext in ransomware_suffixes:
            return True  # classic rename-to-.locked pattern

        if src_ext and dst_ext and src_ext != dst_ext:
            # Extension changed; check if src file content matches src_ext magic
            magic = MAGIC_BYTES.get(src_ext)
            if magic and os.path.isfile(src):
                try:
                    with open(src, "rb") as f:
                        header = f.read(len(magic) + 2)
                    if not header.startswith(magic):
                        return True
                except OSError:
                    pass

        return False

    @staticmethod
    def _check_entropy(state: ProcessState, path: str) -> None:
        """
        Paper §III-D-3g: High Shannon entropy in a written file indicates
        encryption. Threshold ~ 7.2 bits/byte (encrypted data approaches 8.0).
        Only checks files that actually exist on disk.
        """
        if not path or not os.path.isfile(path):
            return
        try:
            data = Path(path).read_bytes()
            if len(data) < 64:
                return  # too small to measure meaningfully
            entropy = _shannon_entropy(data)
            if entropy > ENTROPY_THRESHOLD:
                state.entropy_spike_count += 1
                log.info(
                    f"[DynamicEngine] Entropy spike  path={path}  "
                    f"entropy={entropy:.2f}  PID={state.pid}"
                )
        except OSError:
            pass

    # ── Convenience reset (for unit tests / demo) ──────────────────────────────

    def reset_pid(self, pid: int) -> None:
        with self._lock:
            self._states.pop(pid, None)
        log.debug(f"[DynamicEngine] State reset for PID={pid}")

    def all_pids(self) -> List[int]:
        with self._lock:
            return list(self._states.keys())


# ════════════════════════════════════════════════════════════════════════════ #
# UTILITY
# ════════════════════════════════════════════════════════════════════════════ #

def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in freq.values()
        if c > 0
    )


# ════════════════════════════════════════════════════════════════════════════ #
# SELF-TEST / DEMO
# ════════════════════════════════════════════════════════════════════════════ #

def _demo():
    import tempfile, shutil

    print("\n" + "=" * 60)
    print("  RansomWall — Dynamic Analysis Engine  (Demo)")
    print("=" * 60)

    tmp = Path(tempfile.mkdtemp(prefix="rw_dyn_demo_"))
    engine = DynamicEngine(watch_dirs=[tmp])
    engine.start()
    time.sleep(0.3)

    SIM_PID = 2222
    print(f"\n[Demo] Simulating ransomware-like IRP sequence for PID={SIM_PID}\n")

    # 1. Directory scan
    for _ in range(20):
        engine.inject_irp("dir_query", SIM_PID)

    # 2. Mass read
    for i in range(30):
        engine.inject_irp("read", SIM_PID, path=f"document_{i}.docx")

    # 3. Mass write
    for i in range(25):
        engine.inject_irp("write", SIM_PID, path=f"document_{i}.docx")

    # 4. Rename to .locked
    for i in range(20):
        engine.inject_irp("rename", SIM_PID,
                          path=f"document_{i}.docx",
                          dst_path=f"document_{i}.docx.locked")

    # 5. Delete originals
    for i in range(12):
        engine.inject_irp("delete", SIM_PID, path=f"document_{i}.docx")

    status = engine.get_status(SIM_PID)
    print("  Feature Vector:")
    for k, v in status["feature_vector"].items():
        print(f"    {k:<25} = {v}")
    print(f"\n  Suspicion Score: {status['suspicion_score']:.3f}")
    print(f"  Modified Files : {len(status['modified_files'])} tracked")

    engine.stop()
    shutil.rmtree(tmp, ignore_errors=True)
    print("\n[Demo] DynamicEngine demo complete.\n")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  |  %(message)s",
    )
    _demo()
