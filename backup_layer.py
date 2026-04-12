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
"""

import os
import json
import shutil
import logging
import threading
from collections import defaultdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

        # Already backed up originals (avoid duplicates)
        with self._lock:
            already_backed = {orig for orig, _ in self._backup_map[pid]}

        backed_count = 0
        new_entries: List[Tuple[str, str]] = []

        for f in files:
            f = str(f)
            if not os.path.isfile(f):
                continue
            if f in already_backed:
                continue

            try:
                # Use a unique name to avoid basename collisions
                safe_name = _safe_backup_name(f, len(new_entries))
                dst = str(pid_dir / safe_name)
                shutil.copy2(f, dst)
                new_entries.append((f, dst))
                backed_count += 1
                log.debug(f"[BackupLayer] Backed up: {f} -> {dst}")
            except Exception as e:
                log.warning(f"[BackupLayer] Could not back up {f}: {e}")

        if new_entries:
            with self._lock:
                self._backup_map[pid].extend(new_entries)
            self._save_manifest(pid)
            log.info(
                f"[BACKUP] PID={pid}  backed_up={backed_count}  "
                f"total_for_pid={len(self._backup_map[pid])}"
            )

        return backed_count

    # ────────────────────────────────────────────────────────────────────────
    def restore(self, pid: int) -> int:
        """
        Paper §III-B-4: "If classified as Ransomware, the process is killed
        and files modified by it are restored to their original locations."
        Returns number of files successfully restored.
        """
        with self._lock:
            entries = list(self._backup_map.get(pid, []))

        if not entries:
            log.info(f"[BackupLayer] No backed-up files found for PID {pid}.")
            return 0

        restored = 0
        for original, backup_path in entries:
            try:
                if os.path.isfile(backup_path):
                    # Recreate parent directory if ransomware deleted it
                    os.makedirs(os.path.dirname(original), exist_ok=True)
                    shutil.copy2(backup_path, original)
                    restored += 1
                    log.debug(f"[BackupLayer] Restored: {backup_path} -> {original}")
                else:
                    log.warning(f"[BackupLayer] Backup file missing: {backup_path}")
            except Exception as e:
                log.error(f"[BackupLayer] Restore failed {original}: {e}")

        log.info(f"[RESTORE] PID={pid}  restored={restored}/{len(entries)}")
        self.cleanup(pid)
        return restored

    # ────────────────────────────────────────────────────────────────────────
    def cleanup(self, pid: int):
        """
        Paper §III-B-4: "If classified as Benign, files backed up due to the
        suspicious process are deleted."
        Also called after restore to remove the backup copies.
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
    def _save_manifest(self, pid: int):
        """
        Persist the backup map for `pid` to manifest.json.
        Enables recovery after an unexpected crash.
        """
        pid_dir = self.backup_dir / str(pid)
        manifest_path = pid_dir / self.MANIFEST_FILE
        try:
            with self._lock:
                entries = list(self._backup_map[pid])
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
    Format: <index>_<basename>  (index avoids collisions from same basename)
    """
    basename = os.path.basename(original_path)
    # Replace filesystem-unsafe chars
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in basename)
    return f"{index:04d}_{safe}"