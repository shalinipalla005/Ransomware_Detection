"""
RansomWall: Dynamic Analysis Engine
=====================================
Based on: "RansomWall: A Layered Defense System against Cryptographic
Ransomware Attacks using Machine Learning" (COMSNETS 2018)
IIT Delhi – Shaukat & Ribeiro

Paper §III-B-3: "Dynamic analysis monitors behavior of the sample during
actual execution. Cryptographic Ransomware performs extensive encryption
of user data files. This layer monitors file system operations and entropy
modifications for tracking massive encryption activities."

Paper §IV-A: File System activities are monitored by analyzing IRPs
(I/O Request Packets). The IRP Filter forwards IRP messages for file
operations on ONLY user data files to the Dynamic Analysis Engine.

Architecture:
  FileOperationTracker  → per-process counters for DINFO/READ/WRITE/RENAME/DELETE
  EntropyAnalyzer       → Shannon entropy computation on written file content
  FingerprintChecker    → magic-byte vs extension mismatch detection
  SlidingWindowBuffer   → 1-second buckets, 3-bucket moving average (§IV-C)
  DynamicAnalyzer       → orchestrator; watchdog handler + pattern scoring
  DynamicEngine         → top-level entry point; exposes get_status()

IRP simulation note:
  On Windows the paper uses a kernel minifilter driver (§IV-B) to intercept
  IRP_MJ_READ, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION (rename/delete), and
  IRP_MJ_DIRECTORY_CONTROL messages.  Here we replicate that logic using
  watchdog filesystem events and inotify (Linux) / ReadDirectoryChangesW
  (Windows) as the closest user-space equivalent.
"""

import os
import sys
import time
import math
import json
import shutil
import logging
import platform
import tempfile
import threading
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler, FileModifiedEvent,
        FileDeletedEvent, FileMovedEvent, FileCreatedEvent,
        DirModifiedEvent,
    )
except ImportError:
    print("[!] watchdog not installed.  Run:  pip install watchdog")
    sys.exit(1)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════ #
# §1  CONSTANTS                                                               #
# ═══════════════════════════════════════════════════════════════════════════ #

# Paper §III-D-3: "only user data files with target extensions are tracked"
USER_DATA_EXTENSIONS: frozenset = frozenset({
    ".docx", ".doc",  ".xlsx", ".xls",  ".pptx", ".ppt",
    ".pdf",  ".txt",  ".jpg",  ".jpeg", ".png",  ".bmp",
    ".gif",  ".tiff", ".mp4",  ".avi",  ".mov",  ".mkv",
    ".mp3",  ".wav",  ".zip",  ".rar",  ".7z",   ".tar",
    ".csv",  ".db",   ".sql",  ".xml",  ".html", ".js",
    ".py",   ".rb",   ".java", ".cpp",  ".c",    ".h",
    ".eml",  ".pst",  ".vcf",  ".odt",  ".rtf",  ".tex",
})

# Paper §III-D-3d: extensions that Ransomware renames files TO
# (non-data, characteristic of specific families)
RANSOMWARE_EXTENSIONS: frozenset = frozenset({
    ".encrypted", ".enc",    ".locked",   ".crypto",   ".crypt",
    ".crypz",     ".cerber", ".cerber2",  ".cerber3",  ".locky",
    ".zepto",     ".odin",   ".aesir",    ".thor",     ".zzzzz",
    ".exx",       ".ezz",    ".ecc",      ".abc",      ".xyz",
    ".vvv",       ".ccc",    ".zzz",      ".micro",    ".ttt",
    ".mp3",       ".evil",   ".darkness", ".fucked",   ".pay2me",
    ".xtbl",      ".cbf",    ".breaking_bad", ".coded", ".surprise",
})

# Paper §III-D-3g: entropy threshold for encryption detection
ENTROPY_THRESHOLD   = 7.5   # bits/byte  (max = 8.0 for random/encrypted data)
ENTROPY_SPIKE_VALUE = 7.8   # strong spike

# Paper §IV-C: sliding window parameters
BUCKET_SIZE_SECS = 1        # 1-second time buckets
WINDOW_BUCKETS   = 3        # 3-bucket moving average

# Thresholds for pattern detection (tuned to paper's Fig. 4 plots)
THRESHOLDS = {
    "dir_query_count":         15,   # §III-D-3a
    "read_count":              20,   # §III-D-3b
    "write_count":             15,   # §III-D-3c
    "rename_count":            10,   # §III-D-3d
    "delete_count":             8,   # §III-D-3e
    "fingerprint_mismatch":     2,   # §III-D-3f  (strong indicator)
    "entropy_spikes":           3,   # §III-D-3g
}

# Score weights for composite suspicion score
SCORE_WEIGHTS = {
    "dir_query_count":        0.5,
    "read_count":             0.8,
    "write_count":            1.0,
    "rename_count":           1.5,
    "delete_count":           1.2,
    "fingerprint_mismatch":   3.0,   # very strong indicator
    "entropy_spikes":         2.0,
}

SUSPICION_THRESHOLD = 5.0   # score to flag a process


# ═══════════════════════════════════════════════════════════════════════════ #
# §2  MAGIC BYTES DATABASE                                                    #
#     Paper §III-D-3f: "file signature in header uniquely identifies its     #
#     extension … modification which does not match its extension in a write  #
#     operation indicates suspicious behavior"                                #
# ═══════════════════════════════════════════════════════════════════════════ #

# Maps extension → list of valid magic byte prefixes (bytes)
MAGIC_BYTES: Dict[str, List[bytes]] = {
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".png":  [b"\x89PNG"],
    ".gif":  [b"GIF87a", b"GIF89a"],
    ".bmp":  [b"BM"],
    ".pdf":  [b"%PDF"],
    ".zip":  [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    ".rar":  [b"Rar!"],
    ".7z":   [b"7z\xbc\xaf\x27\x1c"],
    ".tar":  [b"ustar"],
    ".docx": [b"PK\x03\x04"],   # OOXML = zip container
    ".xlsx": [b"PK\x03\x04"],
    ".pptx": [b"PK\x03\x04"],
    ".doc":  [b"\xd0\xcf\x11\xe0"],  # OLE2
    ".xls":  [b"\xd0\xcf\x11\xe0"],
    ".ppt":  [b"\xd0\xcf\x11\xe0"],
    ".mp4":  [b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x1cftyp",
              b"ftyp"],
    ".mp3":  [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"],
    ".wav":  [b"RIFF"],
    ".avi":  [b"RIFF"],
    ".mkv":  [b"\x1a\x45\xdf\xa3"],
    ".txt":  [],   # no reliable magic – skip fingerprint check
    ".csv":  [],
    ".xml":  [b"<?xml", b"\xef\xbb\xbf<?xml"],
    ".html": [b"<!DOCTYPE", b"<html", b"\xef\xbb\xbf<!"],
}


# ═══════════════════════════════════════════════════════════════════════════ #
# §3  SLIDING WINDOW BUFFER                                                   #
#     Paper §IV-C: "Feature Collector fetch the values at regular            #
#     time-intervals known as Buckets. Bucket Size = 1 second.               #
#     Feature values are smoothed by taking average over 3 time-intervals    #
#     (1 Current and 2 Previous)."                                           #
# ═══════════════════════════════════════════════════════════════════════════ #

@dataclass
class Bucket:
    """One 1-second time bucket of raw feature counts."""
    timestamp:          float = field(default_factory=time.time)
    dir_query_count:    int   = 0
    read_count:         int   = 0
    write_count:        int   = 0
    rename_count:       int   = 0
    delete_count:       int   = 0
    entropy_sum:        float = 0.0
    entropy_samples:    int   = 0
    entropy_spikes:     int   = 0
    fingerprint_mismatch: int = 0

    def as_dict(self) -> dict:
        avg_e = (self.entropy_sum / self.entropy_samples
                 if self.entropy_samples else 0.0)
        return {
            "dir_query_count":      self.dir_query_count,
            "read_count":           self.read_count,
            "write_count":          self.write_count,
            "rename_count":         self.rename_count,
            "delete_count":         self.delete_count,
            "entropy_avg":          round(avg_e, 4),
            "entropy_spikes":       self.entropy_spikes,
            "fingerprint_mismatch": self.fingerprint_mismatch,
        }


class SlidingWindowBuffer:
    """
    Maintains a deque of N buckets (default 3) and exposes a moving-average
    feature vector.  A new bucket is created automatically each second.

    Paper §IV-C implementation:
      avg_feature = (bucket_t + bucket_t-1 + bucket_t-2) / 3
    """

    def __init__(self, window: int = WINDOW_BUCKETS,
                 bucket_secs: float = BUCKET_SIZE_SECS):
        self.window      = window
        self.bucket_secs = bucket_secs
        self._buckets: deque = deque(maxlen=window)
        self._current: Optional[Bucket] = None
        self._lock = threading.Lock()
        self._ensure_bucket()

    # ---------------------------------------------------------------------- #
    def _ensure_bucket(self) -> Bucket:
        """Return current bucket; rotate if its time slot has expired."""
        now = time.time()
        if (self._current is None
                or now - self._current.timestamp >= self.bucket_secs):
            if self._current is not None:
                self._buckets.append(self._current)
            self._current = Bucket(timestamp=now)
        return self._current

    # ---------------------------------------------------------------------- #
    def record(self, field_name: str, value: float = 1.0):
        with self._lock:
            b = self._ensure_bucket()
            if field_name in ("entropy_sum", "entropy_samples",
                              "entropy_spikes", "fingerprint_mismatch"):
                setattr(b, field_name,
                        getattr(b, field_name) + value)
            else:
                setattr(b, field_name,
                        getattr(b, field_name) + int(value))

    # ---------------------------------------------------------------------- #
    def moving_average(self) -> dict:
        """
        Paper §IV-C: compute 3-bucket moving average.
        Returns smoothed feature vector.
        """
        with self._lock:
            self._ensure_bucket()   # flush current bucket into deque first
            all_buckets = list(self._buckets) + ([self._current]
                                                  if self._current else [])
            if not all_buckets:
                return Bucket().as_dict()

            # Accumulate
            keys = ["dir_query_count", "read_count", "write_count",
                    "rename_count", "delete_count",
                    "entropy_spikes", "fingerprint_mismatch"]
            sums = defaultdict(float)
            entropy_sum     = 0.0
            entropy_samples = 0

            for b in all_buckets:
                for k in keys:
                    sums[k] += getattr(b, k)
                entropy_sum     += b.entropy_sum
                entropy_samples += b.entropy_samples

            n = len(all_buckets)
            avg = {k: round(sums[k] / n, 3) for k in keys}
            avg["entropy_avg"] = round(
                (entropy_sum / entropy_samples) if entropy_samples else 0.0,
                4
            )
            return avg

    # ---------------------------------------------------------------------- #
    def cumulative_totals(self) -> dict:
        """
        Total counts across all retained buckets (for threshold evaluation).
        """
        with self._lock:
            self._ensure_bucket()
            all_buckets = list(self._buckets) + ([self._current]
                                                  if self._current else [])
            totals = defaultdict(int)
            es = es_n = 0.0
            for b in all_buckets:
                totals["dir_query_count"]      += b.dir_query_count
                totals["read_count"]           += b.read_count
                totals["write_count"]          += b.write_count
                totals["rename_count"]         += b.rename_count
                totals["delete_count"]         += b.delete_count
                totals["entropy_spikes"]       += b.entropy_spikes
                totals["fingerprint_mismatch"] += b.fingerprint_mismatch
                es   += b.entropy_sum
                es_n += b.entropy_samples
            totals["entropy_avg"] = round(
                (es / es_n) if es_n else 0.0, 4
            )
            return dict(totals)


# ═══════════════════════════════════════════════════════════════════════════ #
# §4  PER-PROCESS STATE                                                       #
# ═══════════════════════════════════════════════════════════════════════════ #

@dataclass
class ProcessState:
    pid:            int
    name:           str             = "unknown"
    window:         SlidingWindowBuffer = field(
        default_factory=SlidingWindowBuffer
    )
    suspicion_score: float          = 0.0
    is_suspicious:  bool            = False
    triggered_thresholds: List[str] = field(default_factory=list)
    first_seen:     str             = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_updated:   str             = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ═══════════════════════════════════════════════════════════════════════════ #
# §5  ENTROPY ANALYZER                                                        #
#     Paper §III-D-3g: "Entropy of data buffer in memory modified during     #
#     file write operation to a value around 8 indicates encryption."         #
# ═══════════════════════════════════════════════════════════════════════════ #

class EntropyAnalyzer:
    """
    Computes Shannon entropy of a file's content after a write event.
    Returns (entropy_value, is_spike).

    In the paper's kernel implementation this reads directly from the
    IRP data buffer in memory.  Here we read the file from disk immediately
    after the watchdog write event fires (next best alternative).
    """

    @staticmethod
    def compute(path: str, max_bytes: int = 65536) -> Optional[float]:
        """
        Read up to max_bytes from file and compute Shannon entropy.
        Returns None on read error.
        """
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
            if not data:
                return None
            return EntropyAnalyzer._shannon(data)
        except (PermissionError, FileNotFoundError, OSError):
            return None

    @staticmethod
    def _shannon(data: bytes) -> float:
        freq: Dict[int, int] = defaultdict(int)
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum(
            (c / n) * math.log2(c / n)
            for c in freq.values() if c > 0
        )

    @staticmethod
    def is_spike(entropy: Optional[float]) -> bool:
        return entropy is not None and entropy >= ENTROPY_THRESHOLD


# ═══════════════════════════════════════════════════════════════════════════ #
# §6  FINGERPRINT CHECKER                                                     #
#     Paper §III-D-3f: "Modification of file signature in header of a user   #
#     data file to a new signature which does not match its extension in a   #
#     write operation indicates suspicious behavior."                         #
# ═══════════════════════════════════════════════════════════════════════════ #

class FingerprintChecker:
    """
    Reads the first 16 bytes of a file and validates them against the
    expected magic bytes for the file's declared extension.

    Returns (is_mismatch, detail_string).

    Paper note: "In normal write operation file signature should match its
    extension. Moreover, in normal operation a file rename should result in
    file signature modification instead of a write operation."
    """

    HEADER_READ_BYTES = 16

    @classmethod
    def check(cls, path: str) -> Tuple[bool, str]:
        ext = Path(path).suffix.lower()
        expected_magics = MAGIC_BYTES.get(ext)

        if expected_magics is None or len(expected_magics) == 0:
            # No magic-byte rule for this extension – skip
            return False, "no_rule"

        try:
            with open(path, "rb") as f:
                header = f.read(cls.HEADER_READ_BYTES)
        except (OSError, PermissionError):
            return False, "read_error"

        if not header:
            return False, "empty_file"

        for magic in expected_magics:
            if header[:len(magic)] == magic:
                return False, "ok"

        # No magic matched → mismatch
        actual_hex = header[:8].hex()
        return True, f"ext={ext} expected_magic≠actual({actual_hex})"


# ═══════════════════════════════════════════════════════════════════════════ #
# §7  FILE OPERATION TRACKER                                                  #
#     Paper §III-D-3a–e: counts DINFO / READ / WRITE / RENAME / DELETE      #
#     per process via IRP simulation (watchdog events).                       #
# ═══════════════════════════════════════════════════════════════════════════ #

class FileOperationTracker:
    """
    Maintains per-process SlidingWindowBuffers.
    The Dynamic Analysis Engine calls these methods from its watchdog handler.

    IRP mapping:
      IRP_MJ_DIRECTORY_CONTROL  →  record_dir_query()
      IRP_MJ_READ               →  record_read()
      IRP_MJ_WRITE              →  record_write()
      IRP_MJ_SET_INFORMATION (rename) → record_rename()
      IRP_MJ_SET_INFORMATION (delete) → record_delete()
    """

    def __init__(self):
        self._states: Dict[int, ProcessState] = {}
        self._lock   = threading.Lock()

    # ---------------------------------------------------------------------- #
    def _get_or_create(self, pid: int) -> ProcessState:
        if pid not in self._states:
            name = "unknown"
            if PSUTIL_AVAILABLE:
                try:
                    import psutil
                    name = psutil.Process(pid).name()
                except Exception:
                    pass
            self._states[pid] = ProcessState(pid=pid, name=name)
        return self._states[pid]

    # ---------------------------------------------------------------------- #
    # IRP_MJ_DIRECTORY_CONTROL simulation
    def record_dir_query(self, pid: int):
        with self._lock:
            self._get_or_create(pid).window.record("dir_query_count")

    # IRP_MJ_READ simulation
    def record_read(self, pid: int, path: str):
        with self._lock:
            self._get_or_create(pid).window.record("read_count")

    # IRP_MJ_WRITE simulation
    def record_write(self, pid: int, path: str,
                     entropy: Optional[float], fp_mismatch: bool):
        with self._lock:
            s = self._get_or_create(pid)
            s.window.record("write_count")
            if entropy is not None:
                s.window.record("entropy_sum",     entropy)
                s.window.record("entropy_samples", 1)
                if EntropyAnalyzer.is_spike(entropy):
                    s.window.record("entropy_spikes")
            if fp_mismatch:
                s.window.record("fingerprint_mismatch")

    # IRP_MJ_SET_INFORMATION (FileRenameInformation)
    def record_rename(self, pid: int, src: str, dst: str):
        with self._lock:
            self._get_or_create(pid).window.record("rename_count")

    # IRP_MJ_SET_INFORMATION (FileDispositionInformation)
    def record_delete(self, pid: int, path: str):
        with self._lock:
            self._get_or_create(pid).window.record("delete_count")

    # ---------------------------------------------------------------------- #
    def get_state(self, pid: int) -> Optional[ProcessState]:
        return self._states.get(pid)

    def all_states(self) -> Dict[int, ProcessState]:
        return dict(self._states)


# ═══════════════════════════════════════════════════════════════════════════ #
# §8  PATTERN SCORER                                                          #
#     Paper §III-D-3: composite detection logic from the 7 dynamic features. #
# ═══════════════════════════════════════════════════════════════════════════ #

class PatternScorer:
    """
    Evaluates whether a process's moving-average feature vector crosses
    ransomware behavioral thresholds and computes a composite suspicion score.

    Behavioral patterns (paper Fig. 4):
      • High DINFO + high READ → ransomware enumerating and reading files
      • High WRITE + high ENTROPY → encryption in progress
      • High RENAME → post-encryption renaming to .encrypted / .locky etc.
      • FINGERPRINT mismatch → content overwritten with ciphertext
    """

    @staticmethod
    def evaluate(totals: dict) -> Tuple[float, List[str]]:
        """
        Returns (suspicion_score, [list_of_triggered_threshold_names]).
        Uses cumulative totals rather than per-second averages for
        threshold evaluation, because ransomware activity is bursty.
        """
        score     = 0.0
        triggered = []

        for feature, threshold in THRESHOLDS.items():
            value = totals.get(feature, 0)
            if value >= threshold:
                weight = SCORE_WEIGHTS.get(feature, 1.0)
                score += weight
                triggered.append(feature)

        # Compound bonuses – paper's behavioral pattern combinations
        # "High read + high write → encryption pattern"
        if (totals.get("read_count", 0)  >= THRESHOLDS["read_count"] and
                totals.get("write_count", 0) >= THRESHOLDS["write_count"]):
            score += 1.5
            if "compound:read+write" not in triggered:
                triggered.append("compound:read+write_encryption_pattern")

        # "High entropy + writes → strong indicator"
        if (totals.get("entropy_spikes", 0) >= THRESHOLDS["entropy_spikes"] and
                totals.get("write_count", 0)  >= THRESHOLDS["write_count"]):
            score += 2.0
            triggered.append("compound:entropy+write_encryption_pattern")

        # "High rename burst → ransomware pattern"
        if totals.get("rename_count", 0) >= THRESHOLDS["rename_count"] * 2:
            score += 1.0
            triggered.append("compound:rename_burst")

        # "Fingerprint mismatch → very strong indicator"
        if totals.get("fingerprint_mismatch", 0) >= 1:
            score += 2.0
            triggered.append("compound:fingerprint_mismatch_critical")

        return round(score, 2), triggered


# ═══════════════════════════════════════════════════════════════════════════ #
# §9  WATCHDOG EVENT HANDLER                                                  #
#     Simulates the IRP Filter Driver described in §IV-B.                    #
#     On Windows: IRP_MJ_* callbacks in a kernel minifilter driver.          #
#     Here: watchdog FileSystemEventHandler running in user space.           #
# ═══════════════════════════════════════════════════════════════════════════ #

class DynamicEventHandler(FileSystemEventHandler):
    """
    Translates watchdog events into IRP-style calls on FileOperationTracker.

    Only user data file extensions are processed (paper §IV-A:
    "IRP Filter forwards IRP messages for file operations on ONLY user data
    files to Dynamic … Layers").
    """

    def __init__(self, tracker: FileOperationTracker,
                 entropy_analyzer: EntropyAnalyzer,
                 fp_checker: FingerprintChecker,
                 logger: logging.Logger):
        super().__init__()
        self.tracker  = tracker
        self.entropy  = entropy_analyzer
        self.fp       = fp_checker
        self.logger   = logger

    # ---------------------------------------------------------------------- #
    @staticmethod
    def _is_user_data(path: str) -> bool:
        """IRP filter: pass only user data file extensions."""
        return Path(path).suffix.lower() in USER_DATA_EXTENSIONS

    @staticmethod
    def _pid_hint() -> int:
        """
        Placeholder PID – watchdog does not expose PIDs.
        A real kernel minifilter receives the PID from the IRP's IoStackLocation.
        We return 0 (unknown) and let the caller override when possible.
        """
        return 0

    # ---------------------------------------------------------------------- #
    # IRP_MJ_WRITE simulation
    def on_modified(self, event):
        if event.is_directory:
            # IRP_MJ_DIRECTORY_CONTROL: directory listing changed
            self.tracker.record_dir_query(self._pid_hint())
            self.logger.debug(f"[DYN] DIR_QUERY  {event.src_path}")
            return

        path = event.src_path
        if not self._is_user_data(path):
            return

        pid = self._pid_hint()

        # Entropy check (§III-D-3g)
        entropy = self.entropy.compute(path)
        is_spike = EntropyAnalyzer.is_spike(entropy)
        if is_spike:
            self.logger.warning(
                f"[DYN] ENTROPY_SPIKE  pid={pid}  entropy={entropy:.3f}"
                f"  path={path}"
            )

        # Fingerprint check (§III-D-3f)
        mismatch, detail = self.fp.check(path)
        if mismatch:
            self.logger.warning(
                f"[DYN] FINGERPRINT_MISMATCH  pid={pid}  {detail}"
                f"  path={path}"
            )

        self.tracker.record_write(pid, path, entropy, mismatch)
        self.logger.debug(
            f"[DYN] WRITE  pid={pid}  entropy={entropy}  "
            f"fp_mismatch={mismatch}  path={path}"
        )

    # ---------------------------------------------------------------------- #
    # IRP_MJ_SET_INFORMATION (FileRenameInformation) simulation
    def on_moved(self, event):
        src = event.src_path
        dst = getattr(event, "dest_path", "")

        # Track directory-level rename as dir query
        if event.is_directory:
            self.tracker.record_dir_query(self._pid_hint())
            return

        pid = self._pid_hint()

        # §III-D-3d: detect data → non-data extension rename
        src_ext = Path(src).suffix.lower()
        dst_ext = Path(dst).suffix.lower()

        is_data_to_ransom = (
            src_ext in USER_DATA_EXTENSIONS and
            dst_ext in RANSOMWARE_EXTENSIONS
        )
        is_data_to_unknown = (
            src_ext in USER_DATA_EXTENSIONS and
            dst_ext not in USER_DATA_EXTENSIONS and
            dst_ext not in ("", ".tmp", ".bak")
        )

        if is_data_to_ransom:
            self.logger.warning(
                f"[DYN] RENAME_DATA→RANSOM  pid={pid}  "
                f"{src_ext}→{dst_ext}  {src} → {dst}"
            )
        elif is_data_to_unknown:
            self.logger.warning(
                f"[DYN] RENAME_DATA→UNKNOWN  pid={pid}  "
                f"{src_ext}→{dst_ext}  {src}"
            )

        self.tracker.record_rename(pid, src, dst)

    # ---------------------------------------------------------------------- #
    # IRP_MJ_SET_INFORMATION (FileDispositionInformation) simulation
    def on_deleted(self, event):
        if event.is_directory:
            return
        path = event.src_path
        if not self._is_user_data(path):
            return
        pid = self._pid_hint()
        self.tracker.record_delete(pid, path)
        self.logger.debug(f"[DYN] DELETE  pid={pid}  path={path}")

    # ---------------------------------------------------------------------- #
    # IRP_MJ_CREATE (new file = ransomware creating encrypted copy)
    def on_created(self, event):
        if event.is_directory:
            self.tracker.record_dir_query(self._pid_hint())
            return
        path = event.src_path
        ext  = Path(path).suffix.lower()
        # Count creation of ransomware-extension files as a write
        if ext in RANSOMWARE_EXTENSIONS:
            self.logger.warning(
                f"[DYN] RANSOM_EXT_FILE_CREATED  path={path}"
            )
            self.tracker.record_write(self._pid_hint(), path, None, False)


# ═══════════════════════════════════════════════════════════════════════════ #
# §10  DYNAMIC ANALYZER  –  main orchestrator                                 #
# ═══════════════════════════════════════════════════════════════════════════ #

class DynamicAnalyzer:
    """
    Combines tracker, entropy, fingerprint, and pattern scorer into a
    single monitoring loop.

    Two operating modes:
      • passive watchdog mode  – watches directories for file events
      • inject_irp()           – test harness that simulates IRP events
    """

    def __init__(self, logger: logging.Logger):
        self.logger    = logger
        self.tracker   = FileOperationTracker()
        self.entropy   = EntropyAnalyzer()
        self.fp        = FingerprintChecker()
        self.scorer    = PatternScorer()
        self._handler  = DynamicEventHandler(
            self.tracker, self.entropy, self.fp, logger
        )
        self._observer = Observer()
        self._scorer_thread = None
        self._stop      = threading.Event()

    # ---------------------------------------------------------------------- #
    def watch(self, directories: List[Path]):
        for d in directories:
            if d.exists():
                self._observer.schedule(self._handler, str(d), recursive=True)
        self._observer.start()
        self.logger.info(
            f"[DynamicAnalyzer] Watching {len(directories)} directories."
        )

    def start_scoring_loop(self, interval: float = 1.0):
        """Background thread that re-scores all processes every second."""
        self._scorer_thread = threading.Thread(
            target=self._score_loop,
            args=(interval,),
            daemon=True,
            name="DynScorer",
        )
        self._scorer_thread.start()

    def stop(self):
        self._stop.set()
        self._observer.stop()
        self._observer.join()
        if self._scorer_thread:
            self._scorer_thread.join(timeout=3)

    # ---------------------------------------------------------------------- #
    def _score_loop(self, interval: float):
        while not self._stop.is_set():
            time.sleep(interval)
            for pid, state in list(self.tracker.all_states().items()):
                self._rescore(state)

    def _rescore(self, state: ProcessState):
        totals = state.window.cumulative_totals()
        score, triggered = self.scorer.evaluate(totals)
        state.suspicion_score   = score
        state.triggered_thresholds = triggered
        state.last_updated = datetime.now(timezone.utc).isoformat()
        if score >= SUSPICION_THRESHOLD and not state.is_suspicious:
            state.is_suspicious = True
            self.logger.warning(
                f"[DynamicAnalyzer] *** SUSPICIOUS ***  pid={state.pid}"
                f"  name={state.name}  score={score}"
                f"  triggers={triggered}"
            )

    # ---------------------------------------------------------------------- #
    def inject_irp(self, irp_type: str, pid: int,
                   path: str = "", dst_path: str = ""):
        """
        Test harness: simulate an IRP event directly without watchdog.
        irp_type: one of 'dir_query','read','write','rename','delete'
        """
        if irp_type == "dir_query":
            self.tracker.record_dir_query(pid)

        elif irp_type == "read":
            self.tracker.record_read(pid, path)

        elif irp_type == "write":
            entropy    = self.entropy.compute(path) if path else None
            fp_mismatch, detail = (
                self.fp.check(path) if path else (False, "")
            )
            if EntropyAnalyzer.is_spike(entropy):
                self.logger.warning(
                    f"[DYN/inject] ENTROPY_SPIKE  pid={pid}  "
                    f"entropy={entropy:.3f}  path={path}"
                )
            if fp_mismatch:
                self.logger.warning(
                    f"[DYN/inject] FINGERPRINT_MISMATCH  pid={pid}  "
                    f"{detail}  path={path}"
                )
            self.tracker.record_write(pid, path, entropy, fp_mismatch)

        elif irp_type == "rename":
            self.tracker.record_rename(pid, path, dst_path)
            src_ext = Path(path).suffix.lower()
            dst_ext = Path(dst_path).suffix.lower()
            if dst_ext in RANSOMWARE_EXTENSIONS:
                self.logger.warning(
                    f"[DYN/inject] RENAME_DATA→RANSOM  pid={pid}  "
                    f"{src_ext}→{dst_ext}"
                )

        elif irp_type == "delete":
            self.tracker.record_delete(pid, path)

        # Re-score immediately after injection
        state = self.tracker.get_state(pid)
        if state:
            self._rescore(state)

    # ---------------------------------------------------------------------- #
    def get_status(self, pid: Optional[int] = None) -> dict:
        """
        Returns per-process detection result:
          { process_id, feature_vector, suspicion_score, is_suspicious }
        """
        if pid is not None:
            state = self.tracker.get_state(pid)
            return self._serialize(state) if state else {}
        # All suspicious processes
        return {
            p: self._serialize(s)
            for p, s in self.tracker.all_states().items()
            if s.is_suspicious
        }

    @staticmethod
    def _serialize(s: ProcessState) -> dict:
        ma  = s.window.moving_average()
        tot = s.window.cumulative_totals()
        return {
            "process_id":          s.pid,
            "process_name":        s.name,
            "feature_vector":      ma,
            "cumulative_totals":   tot,
            "suspicion_score":     round(s.suspicion_score, 2),
            "is_suspicious":       s.is_suspicious,
            "triggered_thresholds": s.triggered_thresholds,
            "first_seen":          s.first_seen,
            "last_updated":        s.last_updated,
        }


# ═══════════════════════════════════════════════════════════════════════════ #
# §11  DYNAMIC ENGINE  –  top-level entry point                               #
# ═══════════════════════════════════════════════════════════════════════════ #

class DynamicEngine:
    """
    Public API that the rest of RansomWall calls.

    Usage:
        engine = DynamicEngine(watch_dirs=[...])
        engine.start()
        status = engine.get_status(pid=1234)
        engine.stop()
    """

    def __init__(self,
                 watch_dirs: Optional[List[Path]] = None,
                 log_path:   str                  = "ransomwall_dynamic.log"):
        self.watch_dirs = watch_dirs or _default_watch_dirs()
        self.logger     = _setup_logger(log_path)
        self.analyzer   = DynamicAnalyzer(self.logger)

    def start(self):
        self.analyzer.watch(self.watch_dirs)
        self.analyzer.start_scoring_loop(interval=1.0)
        self.logger.info("[DynamicEngine] Started.")

    def stop(self):
        self.analyzer.stop()
        self.logger.info("[DynamicEngine] Stopped.")

    def get_status(self, pid: Optional[int] = None) -> dict:
        return self.analyzer.get_status(pid)

    def inject_irp(self, irp_type: str, pid: int,
                   path: str = "", dst_path: str = ""):
        """Expose inject_irp for the demo / integration tests."""
        self.analyzer.inject_irp(irp_type, pid, path, dst_path)

    def run_forever(self):
        self.start()
        try:
            while True:
                time.sleep(10)
                suspects = self.get_status()
                if suspects:
                    print("\n" + "═" * 70)
                    print("  ⚠  DYNAMIC ENGINE – SUSPICIOUS PROCESSES")
                    print("═" * 70)
                    for pid, info in suspects.items():
                        fv = info["feature_vector"]
                        print(
                            f"  PID {pid:>6}  {info['process_name']:<18}  "
                            f"score={info['suspicion_score']:.1f}  "
                            f"W={fv['write_count']:.1f}  "
                            f"R={fv['read_count']:.1f}  "
                            f"REN={fv['rename_count']:.1f}  "
                            f"ENT={fv['entropy_avg']:.2f}  "
                            f"FP={fv['fingerprint_mismatch']:.0f}"
                        )
                    print("═" * 70)
        except KeyboardInterrupt:
            print("\n[*] Interrupted.")
        finally:
            self.stop()


# ═══════════════════════════════════════════════════════════════════════════ #
# §12  HELPERS                                                                #
# ═══════════════════════════════════════════════════════════════════════════ #

def _default_watch_dirs() -> List[Path]:
    home = Path.home()
    dirs = [home / d for d in
            ("Documents", "Desktop", "Pictures", "Downloads")]
    dirs.append(Path(tempfile.gettempdir()) / "rw_dynamic_watch")
    result = []
    for d in dirs:
        try:
            d.mkdir(parents=True, exist_ok=True)
            result.append(d)
        except PermissionError:
            pass
    return result


def _setup_logger(log_path: str) -> logging.Logger:
    logger = logging.getLogger("RansomWall.DynamicEngine")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [DYNAMIC] %(levelname)s  %(message)s"
    )
    fh = logging.FileHandler(log_path)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


# ═══════════════════════════════════════════════════════════════════════════ #
# §13  DEMO / SELF-TEST                                                       #
# ═══════════════════════════════════════════════════════════════════════════ #

def run_demo():
    print("\n" + "═" * 70)
    print("  RansomWall – Dynamic Analysis Engine  (Demo / Self-Test)")
    print("  Based on COMSNETS 2018 – Shaukat & Ribeiro, IIT Delhi")
    print("═" * 70 + "\n")

    demo_dir = Path(tempfile.mkdtemp(prefix="rw_dyn_demo_"))
    log_path = str(demo_dir / "ransomwall_dynamic.log")

    engine = DynamicEngine(watch_dirs=[demo_dir], log_path=log_path)
    engine.start()
    time.sleep(0.5)

    sim_pid = 4242   # simulated ransomware PID

    print(f"[Demo] Watch directory : {demo_dir}")
    print(f"[Demo] Simulated PID   : {sim_pid}")
    print()

    # ── Create test files that look like real user data ──────────────────── #
    test_files = []
    for ext in [".docx", ".pdf", ".jpg", ".txt", ".xlsx"]:
        p = demo_dir / f"user_document{ext}"
        p.write_bytes(b"A" * 1024)   # benign content initially
        test_files.append(p)

    time.sleep(0.3)

    # ── Simulate ransomware attack sequence ──────────────────────────────── #
    print("[Demo] Step 1/7 – Directory enumeration (DINFO queries)")
    for _ in range(20):   # ransomware scans many directories
        engine.inject_irp("dir_query", sim_pid)
    time.sleep(0.2)

    print("[Demo] Step 2/7 – Mass file reads (preparing to encrypt)")
    for f in test_files * 5:   # reads each file multiple times
        engine.inject_irp("read", sim_pid, path=str(f))
    time.sleep(0.2)

    print("[Demo] Step 3/7 – Mass file writes with encrypted content")
    for f in test_files:
        # Overwrite with high-entropy (simulated ciphertext) data
        random_like = bytes(
            [(i ^ 0xAB) & 0xFF for i in range(512)] * 4
        )   # XOR pattern ≈ high entropy
        f.write_bytes(random_like)
        engine.inject_irp("write", sim_pid, path=str(f))
        time.sleep(0.05)
    time.sleep(0.5)

    print("[Demo] Step 4/7 – File fingerprint mismatch check")
    # Write non-JPEG content into a .jpg file
    jpg_file = demo_dir / "vacation_photo.jpg"
    jpg_file.write_bytes(b"\x00\x01\x02\x03" * 256)  # not a valid JPEG header
    engine.inject_irp("write", sim_pid, path=str(jpg_file))
    time.sleep(0.2)

    print("[Demo] Step 5/7 – Bulk rename: .docx → .encrypted")
    for f in test_files:
        dst = f.with_suffix(".encrypted")
        engine.inject_irp("rename", sim_pid,
                          path=str(f), dst_path=str(dst))
    time.sleep(0.2)

    print("[Demo] Step 6/7 – Original file deletion (after encrypted copy)")
    for f in test_files[:3]:
        engine.inject_irp("delete", sim_pid, path=str(f))
    time.sleep(0.2)

    print("[Demo] Step 7/7 – Additional write burst (entropy spike)")
    for _ in range(10):
        engine.inject_irp("write", sim_pid,
                          path=str(test_files[0]))
    time.sleep(1.2)   # let scoring loop process

    # ── Print results ─────────────────────────────────────────────────────── #
    print("\n" + "═" * 70)
    print("  DETECTION RESULTS")
    print("═" * 70)

    status = engine.get_status(sim_pid)
    if status:
        fv  = status["feature_vector"]
        tot = status["cumulative_totals"]
        print(f"  PID             : {status['process_id']}")
        print(f"  Process Name    : {status['process_name']}")
        print(f"  Suspicious      : {'YES ⚠' if status['is_suspicious'] else 'NO'}")
        print(f"  Suspicion Score : {status['suspicion_score']}")
        print()
        print("  ── Moving-Average Feature Vector (3-bucket window) ──")
        for k, v in fv.items():
            print(f"    {k:<28} {v}")
        print()
        print("  ── Cumulative Totals ──")
        for k, v in tot.items():
            thr = THRESHOLDS.get(k, "–")
            flag = " ⚠" if isinstance(thr, int) and v >= thr else ""
            print(f"    {k:<28} {v}  (threshold={thr}){flag}")
        print()
        print("  ── Triggered Thresholds ──")
        for t in status["triggered_thresholds"]:
            print(f"    • {t}")
    else:
        print("  No data recorded for demo PID.")

    print("═" * 70)

    engine.stop()
    shutil.rmtree(demo_dir, ignore_errors=True)
    print(f"\n[Demo] Complete. Log saved to: {log_path}\n")


# ─────────────────────────────────────────────────────────────────────────── #
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--monitor":
        engine = DynamicEngine()
        engine.run_forever()
    else:
        run_demo()