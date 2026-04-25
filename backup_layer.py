"""
RansomWall: File Backup Layer
=====================================
Based on: "RansomWall: A Layered Defense System against Cryptographic
Ransomware Attacks using Machine Learning" (COMSNETS 2018)
IIT Delhi - Shaukat & Ribeiro

Paper §III-B-4 (File Backup Layer):
  "Files modified by the suspicious process are backed up in a separate
   folder to preserve user data until the process is classified as
   Ransomware or Benign by Machine Learning Layer."

  "RansomWall maintains list of files that are backed up along with their
   original locations and Process ID of the suspicious process."

  "If Machine Learning Layer classifies as Ransomware:
     -> process is killed AND files modified by it are restored."
  "If classified as Benign:
     -> files are deleted from the backup folder."

  Paper §IV-A (IRP Filter integration):
  "Filtered IRPs are forwarded to File Backup Layer. If it observes a
   file modification request by the suspicious process, then the file
   is backed up in a backup folder."

Fixes applied vs original:
  FIX-1  datetime.UTC -> timezone.utc  (Python 3.10 compatibility)
  FIX-2  _save_manifest no longer re-acquires the lock held by backup();
          entries snapshot passed in as argument instead
  FIX-3  _safe_backup_name index now accounts for already-backed entries
          so filenames are unique across repeated backup() calls per PID
  FIX-4  cleanup() only runs after ALL restores succeed; partial failures
          retain the backup directory so data is not permanently lost
  FIX-5  os.makedirs guard for bare filenames (dirname returns "")
"""

import os
import json
import shutil
import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# FIX-1: compatible alias for Python 3.10 and earlier
UTC = timezone.utc

log = logging.getLogger("RansomWall.BackupLayer")


# ════════════════════════════════════════════════════════════════════════════ #
class BackupLayer:
    """
    Manages per-PID file backups.

    Directory structure:
      rw_backup/
        <pid>/
          manifest.json          ← { original_path: backup_filename, ... }
          <backup_filename>      ← actual backed-up file

    Thread-safe: multiple suspicious PIDs processed concurrently.
    """

    MANIFEST_FILE = "manifest.json"

    def __init__(self, backup_dir: str = "rw_backup"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # In-memory map:  pid -> [(original_path, backup_path), ...]
        # Persisted to manifest.json per PID for crash recovery.
        self._backup_map: Dict[int, List[Tuple[str, str]]] = defaultdict(list)
        self._lock = threading.Lock()

        log.info(f"[BackupLayer] Initialized. Backup dir: {self.backup_dir}")

    # ────────────────────────────────────────────────────────────────────────
    def backup(self, pid: int, files: List[str]) -> int:
        """
        Paper §III-B-4: Back up all files in `files` for `pid`.
        Skips files that don't exist or were already backed up.
        Returns number of files successfully backed up.
        """
        if not files:
            return 0

        pid_dir = self.backup_dir / str(pid)
        pid_dir.mkdir(parents=True, exist_ok=True)

        # FIX-3: capture both already-backed set AND existing count
        # while holding the lock, so the index is globally unique per PID.
        with self._lock:
            already_backed  = {orig for orig, _ in self._backup_map[pid]}
            existing_count  = len(self._backup_map[pid])

        backed_count = 0
        new_entries: List[Tuple[str, str]] = []

        for f in files:
            f = str(f)
            if not os.path.isfile(f):
                continue
            if f in already_backed:
                continue

            try:
                # FIX-3: index = existing + already queued this call
                # guarantees uniqueness even across repeated backup() calls
                safe_name = _safe_backup_name(f, existing_count + len(new_entries))
                dst = str(pid_dir / safe_name)
                shutil.copy2(f, dst)
                new_entries.append((f, dst))
                backed_count += 1
                log.debug(f"[BackupLayer] Backed up: {f} -> {dst}")
            except Exception as e:
                log.warning(f"[BackupLayer] Could not back up {f}: {e}")

        if new_entries:
            # FIX-2: take snapshot inside lock, then call _save_manifest
            # outside the lock so _save_manifest never needs to re-acquire it.
            with self._lock:
                self._backup_map[pid].extend(new_entries)
                entries_snapshot = list(self._backup_map[pid])

            self._save_manifest(pid, entries_snapshot)
            log.info(
                f"[BACKUP] PID={pid}  backed_up={backed_count}  "
                f"total_for_pid={len(entries_snapshot)}"
            )

        return backed_count

    # ────────────────────────────────────────────────────────────────────────
    def restore(self, pid: int) -> int:
        """
        Paper §III-B-4: "If classified as Ransomware, the process is killed
        and files modified by it are restored to their original locations."
        Returns number of files successfully restored.

        FIX-4: cleanup() is only called when ALL restores succeed.
        If any restore fails the backup directory is retained so that
        the operator can manually recover — data is never silently lost.
        """
        with self._lock:
            entries = list(self._backup_map.get(pid, []))

        if not entries:
            log.info(f"[BackupLayer] No backed-up files found for PID {pid}.")
            return 0

        restored = 0
        failed   = 0

        for original, backup_path in entries:
            try:
                if os.path.isfile(backup_path):
                    # FIX-5: guard against dirname("") raising FileNotFoundError
                    parent = os.path.dirname(original)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    shutil.copy2(backup_path, original)
                    restored += 1
                    log.debug(f"[BackupLayer] Restored: {backup_path} -> {original}")
                else:
                    log.warning(f"[BackupLayer] Backup file missing: {backup_path}")
                    failed += 1
            except Exception as e:
                log.error(f"[BackupLayer] Restore failed {original}: {e}")
                failed += 1

        log.info(
            f"[RESTORE] PID={pid}  restored={restored}/{len(entries)}  "
            f"failed={failed}"
        )

        # FIX-4: only wipe backup dir when every file was restored successfully
        if failed == 0:
            self.cleanup(pid)
        else:
            log.warning(
                f"[BackupLayer] {failed} restore(s) failed for PID={pid}. "
                f"Backup directory retained at: {self.backup_dir / str(pid)}"
            )

        return restored

    # ────────────────────────────────────────────────────────────────────────
    def cleanup(self, pid: int):
        """
        Paper §III-B-4: "If classified as Benign, files backed up due to the
        suspicious process are deleted."
        Also called after a fully successful restore.
        """
        pid_dir = self.backup_dir / str(pid)
        shutil.rmtree(pid_dir, ignore_errors=True)

        with self._lock:
            removed = self._backup_map.pop(pid, [])

        log.info(f"[CLEANUP] PID={pid}  removed {len(removed)} backup entries.")

    # ────────────────────────────────────────────────────────────────────────
    def get_backed_up_files(self, pid: int) -> List[Tuple[str, str]]:
        """Return list of (original, backup) tuples for a PID."""
        with self._lock:
            return list(self._backup_map.get(pid, []))

    # ────────────────────────────────────────────────────────────────────────
    def status(self) -> dict:
        """Summary of current backup state across all PIDs."""
        with self._lock:
            return {
                pid: {"files_backed_up": len(entries)}
                for pid, entries in self._backup_map.items()
            }

    # ────────────────────────────────────────────────────────────────────────
    def _save_manifest(self, pid: int, entries: List[Tuple[str, str]]):
        """
        Persist the backup map for `pid` to manifest.json.
        Enables recovery after an unexpected crash.

        FIX-2: accepts entries as a parameter (snapshot taken by caller
        inside the lock) so this method never needs to acquire self._lock.
        """
        pid_dir       = self.backup_dir / str(pid)
        manifest_path = pid_dir / self.MANIFEST_FILE
        try:
            data = {
                "pid":      pid,
                "saved_at": datetime.now(UTC).isoformat(),
                "files":    [{"original": o, "backup": b} for o, b in entries],
            }
            with open(manifest_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.warning(f"[BackupLayer] Could not save manifest for PID {pid}: {e}")

    # ────────────────────────────────────────────────────────────────────────
    def load_manifest(self, pid: int) -> bool:
        """
        Recover backup state from manifest.json after a crash.
        Returns True if manifest was loaded successfully.
        """
        manifest_path = self.backup_dir / str(pid) / self.MANIFEST_FILE
        try:
            with open(manifest_path) as f:
                data = json.load(f)
            entries = [(e["original"], e["backup"]) for e in data.get("files", [])]
            with self._lock:
                self._backup_map[pid] = entries
            log.info(f"[BackupLayer] Recovered {len(entries)} entries for PID {pid}")
            return True
        except Exception:
            return False


# ════════════════════════════════════════════════════════════════════════════ #
def _safe_backup_name(original_path: str, index: int) -> str:
    """
    Generate a unique, safe filename for a backup copy.
    Format: <index>_<basename>

    The index is globally unique per PID across all backup() calls
    (FIX-3: caller passes existing_count + offset, not just offset).
    """
    basename = os.path.basename(original_path)
    # Replace filesystem-unsafe characters
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in basename)
    return f"{index:04d}_{safe}"