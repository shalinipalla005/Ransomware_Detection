import os
import json
import shutil
import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

UTC = timezone.utc

log = logging.getLogger("RansomWall.BackupLayer")

class BackupLayer:
    MANIFEST_FILE = "manifest.json"

    def __init__(self, backup_dir: str = "rw_backup"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._backup_map: Dict[int, List[Tuple[str, str]]] = defaultdict(list)
        self._lock = threading.Lock()

        log.info(f"[BackupLayer] Initialized. Backup dir: {self.backup_dir}")

    def backup(self, pid: int, files: List[str]) -> int:
        if not files:
            return 0

        pid_dir = self.backup_dir / str(pid)
        pid_dir.mkdir(parents=True, exist_ok=True)

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
                safe_name = _safe_backup_name(f, existing_count + len(new_entries))
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
                entries_snapshot = list(self._backup_map[pid])

            self._save_manifest(pid, entries_snapshot)
            log.info(
                f"[BACKUP] PID={pid}  backed_up={backed_count}  "
                f"total_for_pid={len(entries_snapshot)}"
            )

        return backed_count

    def restore(self, pid: int) -> int:

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

        if failed == 0:
            self.cleanup(pid)
        else:
            log.warning(
                f"[BackupLayer] {failed} restore(s) failed for PID={pid}. "
                f"Backup directory retained at: {self.backup_dir / str(pid)}"
            )

        return restored

    def cleanup(self, pid: int):
        pid_dir = self.backup_dir / str(pid)
        shutil.rmtree(pid_dir, ignore_errors=True)

        with self._lock:
            removed = self._backup_map.pop(pid, [])

        log.info(f"[CLEANUP] PID={pid}  removed {len(removed)} backup entries.")

    def get_backed_up_files(self, pid: int) -> List[Tuple[str, str]]:
        with self._lock:
            return list(self._backup_map.get(pid, []))

    def status(self) -> dict:
        with self._lock:
            return {
                pid: {"files_backed_up": len(entries)}
                for pid, entries in self._backup_map.items()
            }

    def _save_manifest(self, pid: int, entries: List[Tuple[str, str]]):

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

    def load_manifest(self, pid: int) -> bool:
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


def _safe_backup_name(original_path: str, index: int) -> str:
    basename = os.path.basename(original_path)
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in basename)
    return f"{index:04d}_{safe}"