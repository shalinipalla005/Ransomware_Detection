"""
RansomWall: BackupLayer Test Suite
====================================
Tests every public method and validates all 5 bug fixes.

Run:
  python3 test_backup_layer.py
  python3 test_backup_layer.py -v      # verbose output

No external dependencies beyond the standard library.
"""

import os
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from backup_layer import BackupLayer, _safe_backup_name


# ════════════════════════════════════════════════════════════════════════════ #
# HELPERS
# ════════════════════════════════════════════════════════════════════════════ #

def _make_file(directory: Path, name: str, content: str = "hello") -> str:
    """Create a real file and return its path as a string."""
    p = directory / name
    p.write_text(content)
    return str(p)


def _read(path: str) -> str:
    return Path(path).read_text()


# ════════════════════════════════════════════════════════════════════════════ #
# TEST CASES
# ════════════════════════════════════════════════════════════════════════════ #

class TestBackupBasic(unittest.TestCase):
    """Core backup / restore / cleanup flow."""

    def setUp(self):
        self.tmp      = Path(tempfile.mkdtemp())
        self.src_dir  = self.tmp / "source"
        self.bak_dir  = self.tmp / "backup"
        self.src_dir.mkdir()
        self.layer = BackupLayer(backup_dir=str(self.bak_dir))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── backup() ─────────────────────────────────────────────────────────────

    def test_backup_creates_copy(self):
        f = _make_file(self.src_dir, "doc.txt", "secret")
        count = self.layer.backup(pid=1, files=[f])
        self.assertEqual(count, 1)
        entries = self.layer.get_backed_up_files(1)
        self.assertEqual(len(entries), 1)
        orig, bak = entries[0]
        self.assertEqual(orig, f)
        self.assertTrue(Path(bak).exists(), "Backup file must exist on disk")
        self.assertEqual(_read(bak), "secret", "Backup content must match original")

    def test_backup_multiple_files(self):
        files = [_make_file(self.src_dir, f"f{i}.txt", f"data{i}") for i in range(5)]
        count = self.layer.backup(pid=2, files=files)
        self.assertEqual(count, 5)
        self.assertEqual(len(self.layer.get_backed_up_files(2)), 5)

    def test_backup_skips_nonexistent(self):
        count = self.layer.backup(pid=3, files=["/nonexistent/ghost.txt"])
        self.assertEqual(count, 0)
        self.assertEqual(len(self.layer.get_backed_up_files(3)), 0)

    def test_backup_skips_empty_list(self):
        count = self.layer.backup(pid=4, files=[])
        self.assertEqual(count, 0)

    def test_backup_no_duplicate(self):
        """Same file backed up twice must only be stored once."""
        f = _make_file(self.src_dir, "dup.txt", "x")
        self.layer.backup(pid=5, files=[f])
        self.layer.backup(pid=5, files=[f])
        self.assertEqual(len(self.layer.get_backed_up_files(5)), 1)

    def test_backup_manifest_written(self):
        f = _make_file(self.src_dir, "m.txt")
        self.layer.backup(pid=6, files=[f])
        manifest = self.bak_dir / "6" / "manifest.json"
        self.assertTrue(manifest.exists(), "manifest.json must be created")
        data = json.loads(manifest.read_text())
        self.assertEqual(data["pid"], 6)
        self.assertEqual(len(data["files"]), 1)

    # ── restore() ────────────────────────────────────────────────────────────

    def test_restore_recovers_file(self):
        f = _make_file(self.src_dir, "important.txt", "original_content")
        self.layer.backup(pid=10, files=[f])
        # Simulate ransomware overwriting the file
        Path(f).write_text("ENCRYPTED_GARBAGE")
        restored = self.layer.restore(pid=10)
        self.assertEqual(restored, 1)
        self.assertEqual(_read(f), "original_content")

    def test_restore_recreates_deleted_file(self):
        f = _make_file(self.src_dir, "gone.txt", "precious")
        self.layer.backup(pid=11, files=[f])
        os.remove(f)   # simulate ransomware deleting original
        restored = self.layer.restore(pid=11)
        self.assertEqual(restored, 1)
        self.assertTrue(Path(f).exists())
        self.assertEqual(_read(f), "precious")

    def test_restore_cleans_up_backup_on_success(self):
        f = _make_file(self.src_dir, "clean.txt")
        self.layer.backup(pid=12, files=[f])
        self.layer.restore(pid=12)
        # After successful restore backup dir for PID should be gone
        self.assertFalse((self.bak_dir / "12").exists())
        self.assertEqual(self.layer.get_backed_up_files(12), [])

    def test_restore_no_files_returns_zero(self):
        result = self.layer.restore(pid=999)
        self.assertEqual(result, 0)

    # ── cleanup() ────────────────────────────────────────────────────────────

    def test_cleanup_removes_backup_dir(self):
        f = _make_file(self.src_dir, "tmp.txt")
        self.layer.backup(pid=20, files=[f])
        self.assertTrue((self.bak_dir / "20").exists())
        self.layer.cleanup(pid=20)
        self.assertFalse((self.bak_dir / "20").exists())
        self.assertEqual(self.layer.get_backed_up_files(20), [])

    def test_cleanup_nonexistent_pid_safe(self):
        """cleanup() on a PID never seen must not raise."""
        try:
            self.layer.cleanup(pid=888)
        except Exception as e:
            self.fail(f"cleanup() raised unexpectedly: {e}")

    # ── status() ─────────────────────────────────────────────────────────────

    def test_status_reflects_active_pids(self):
        f1 = _make_file(self.src_dir, "a.txt")
        f2 = _make_file(self.src_dir, "b.txt")
        self.layer.backup(pid=30, files=[f1])
        self.layer.backup(pid=31, files=[f1, f2])
        s = self.layer.status()
        self.assertEqual(s[30]["files_backed_up"], 1)
        self.assertEqual(s[31]["files_backed_up"], 2)

    def test_status_empty_initially(self):
        self.assertEqual(self.layer.status(), {})


# ════════════════════════════════════════════════════════════════════════════ #

class TestFix1_DatetimeUTC(unittest.TestCase):
    """FIX-1: datetime.UTC replaced with timezone.utc (Python 3.10 compat)."""

    def test_import_succeeds(self):
        """If the module imports without error, FIX-1 is in place."""
        try:
            import backup_layer  # noqa: F401
        except ImportError as e:
            self.fail(f"backup_layer import failed: {e}")

    def test_manifest_saved_at_is_iso_format(self):
        tmp     = Path(tempfile.mkdtemp())
        src     = tmp / "src"; src.mkdir()
        bak     = tmp / "bak"
        layer   = BackupLayer(backup_dir=str(bak))
        f       = _make_file(src, "iso.txt")
        layer.backup(pid=100, files=[f])
        manifest = json.loads((bak / "100" / "manifest.json").read_text())
        # Must be parseable as ISO-8601
        from datetime import datetime
        try:
            datetime.fromisoformat(manifest["saved_at"])
        except ValueError:
            self.fail("saved_at is not a valid ISO-8601 timestamp")
        shutil.rmtree(tmp, ignore_errors=True)


# ════════════════════════════════════════════════════════════════════════════ #

class TestFix2_NoDeadlock(unittest.TestCase):
    """FIX-2: _save_manifest must not re-acquire the lock held by backup()."""

    def test_concurrent_backup_no_deadlock(self):
        """
        Fire 10 threads each backing up different files for different PIDs.
        If FIX-2 is absent the test hangs (deadlock); with the fix it
        completes well within the timeout.
        """
        tmp   = Path(tempfile.mkdtemp())
        src   = tmp / "src"; src.mkdir()
        bak   = tmp / "bak"
        layer = BackupLayer(backup_dir=str(bak))

        errors = []

        def worker(pid):
            try:
                f = _make_file(src, f"file_{pid}.txt", f"data_{pid}")
                layer.backup(pid=pid, files=[f])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)

        alive = [t for t in threads if t.is_alive()]
        self.assertEqual(alive, [], f"{len(alive)} thread(s) are still alive — possible deadlock")
        self.assertEqual(errors, [], f"Thread errors: {errors}")
        shutil.rmtree(tmp, ignore_errors=True)


# ════════════════════════════════════════════════════════════════════════════ #

class TestFix3_UniqueFilenames(unittest.TestCase):
    """FIX-3: backup filenames must be unique across repeated backup() calls."""

    def test_no_filename_collision_across_calls(self):
        tmp   = Path(tempfile.mkdtemp())
        src   = tmp / "src"; src.mkdir()
        bak   = tmp / "bak"
        layer = BackupLayer(backup_dir=str(bak))

        # Call backup() twice with DIFFERENT files that share the same basename
        sub1 = src / "a"; sub1.mkdir()
        sub2 = src / "b"; sub2.mkdir()
        f1   = _make_file(sub1, "report.txt", "v1")
        f2   = _make_file(sub2, "report.txt", "v2")   # same basename, different dir

        layer.backup(pid=200, files=[f1])
        layer.backup(pid=200, files=[f2])

        pid_dir = bak / "200"
        backup_files = [p.name for p in pid_dir.iterdir() if p.name != "manifest.json"]

        # Must have 2 distinct backup files
        self.assertEqual(len(backup_files), 2, f"Expected 2 backup files, got: {backup_files}")
        self.assertEqual(len(set(backup_files)), 2, f"Duplicate filenames: {backup_files}")

        shutil.rmtree(tmp, ignore_errors=True)

    def test_safe_backup_name_index_zero(self):
        name = _safe_backup_name("/some/path/file.txt", 0)
        self.assertTrue(name.startswith("0000_"))

    def test_safe_backup_name_index_offset(self):
        name = _safe_backup_name("/some/path/file.txt", 5)
        self.assertTrue(name.startswith("0005_"))

    def test_safe_backup_name_sanitises_special_chars(self):
        name = _safe_backup_name("/path/my file (1).txt", 0)
        self.assertNotIn(" ", name)
        self.assertNotIn("(", name)
        self.assertNotIn(")", name)


# ════════════════════════════════════════════════════════════════════════════ #

class TestFix4_PartialRestoreRetainsBackup(unittest.TestCase):
    """FIX-4: backup dir must be RETAINED when any restore fails."""

    def test_backup_retained_on_partial_failure(self):
        tmp   = Path(tempfile.mkdtemp())
        src   = tmp / "src"; src.mkdir()
        bak   = tmp / "bak"
        layer = BackupLayer(backup_dir=str(bak))

        # Back up two files
        f1 = _make_file(src, "good.txt", "good")
        f2 = _make_file(src, "bad.txt",  "bad")
        layer.backup(pid=300, files=[f1, f2])

        # Corrupt one backup file so restore() will fail for it
        entries = layer.get_backed_up_files(300)
        # Remove the backup copy of f2 to simulate a missing backup
        for orig, bak_path in entries:
            if "bad" in orig:
                os.remove(bak_path)
                break

        restored = layer.restore(pid=300)

        # One restored, one failed -> backup dir must still exist
        pid_dir = bak / "300"
        self.assertTrue(
            pid_dir.exists(),
            "Backup directory must be retained when restores partially fail"
        )
        # In-memory map must also be intact
        self.assertGreater(
            len(layer.get_backed_up_files(300)), 0,
            "In-memory backup map must not be cleared on partial failure"
        )
        shutil.rmtree(tmp, ignore_errors=True)

    def test_full_success_cleans_up(self):
        tmp   = Path(tempfile.mkdtemp())
        src   = tmp / "src"; src.mkdir()
        bak   = tmp / "bak"
        layer = BackupLayer(backup_dir=str(bak))
        f     = _make_file(src, "ok.txt", "data")
        layer.backup(pid=301, files=[f])
        layer.restore(pid=301)
        self.assertFalse((bak / "301").exists(), "Backup dir must be removed on full success")
        shutil.rmtree(tmp, ignore_errors=True)


# ════════════════════════════════════════════════════════════════════════════ #

class TestFix5_BareDirname(unittest.TestCase):
    """FIX-5: restore() must not crash when original has no directory component."""

    def test_restore_bare_filename(self):
        """
        Simulate a backup entry whose 'original' path has no parent directory
        (dirname returns "").  restore() must not raise FileNotFoundError.
        """
        tmp   = Path(tempfile.mkdtemp())
        src   = tmp / "src"; src.mkdir()
        bak   = tmp / "bak"
        layer = BackupLayer(backup_dir=str(bak))

        # Create a real file and back it up normally
        f = _make_file(src, "normal.txt", "data")
        layer.backup(pid=400, files=[f])

        # Patch the in-memory map to use a bare filename (no directory)
        # This mimics the edge case that triggered the bug
        entries = layer.get_backed_up_files(400)
        bare_original = "bare_file.txt"
        with layer._lock:
            orig, bak_path = layer._backup_map[400][0]
            layer._backup_map[400][0] = (bare_original, bak_path)

        # Should not raise — just attempt the restore
        try:
            layer.restore(pid=400)
        except FileNotFoundError as e:
            self.fail(f"restore() raised FileNotFoundError for bare filename: {e}")
        finally:
            # Clean up any file written to cwd
            if Path(bare_original).exists():
                os.remove(bare_original)
            shutil.rmtree(tmp, ignore_errors=True)


# ════════════════════════════════════════════════════════════════════════════ #

class TestManifestPersistence(unittest.TestCase):
    """load_manifest() crash-recovery round-trip."""

    def test_load_manifest_round_trip(self):
        tmp   = Path(tempfile.mkdtemp())
        src   = tmp / "src"; src.mkdir()
        bak   = tmp / "bak"

        layer1 = BackupLayer(backup_dir=str(bak))
        f      = _make_file(src, "persist.txt", "data")
        layer1.backup(pid=500, files=[f])

        # Simulate crash: create a fresh instance and recover
        layer2 = BackupLayer(backup_dir=str(bak))
        success = layer2.load_manifest(pid=500)
        self.assertTrue(success)
        entries = layer2.get_backed_up_files(500)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], f)

        shutil.rmtree(tmp, ignore_errors=True)

    def test_load_manifest_missing_returns_false(self):
        tmp   = Path(tempfile.mkdtemp())
        layer = BackupLayer(backup_dir=str(tmp / "bak"))
        result = layer.load_manifest(pid=9999)
        self.assertFalse(result)
        shutil.rmtree(tmp, ignore_errors=True)


# ════════════════════════════════════════════════════════════════════════════ #

class TestThreadSafety(unittest.TestCase):
    """Concurrent writes from multiple threads must not corrupt state."""

    def test_concurrent_backup_same_pid(self):
        tmp   = Path(tempfile.mkdtemp())
        src   = tmp / "src"; src.mkdir()
        bak   = tmp / "bak"
        layer = BackupLayer(backup_dir=str(bak))

        files = [_make_file(src, f"t{i}.txt", f"x{i}") for i in range(20)]
        errors = []

        def worker(f):
            try:
                layer.backup(pid=600, files=[f])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f,)) for f in files]
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)

        self.assertEqual(errors, [], f"Thread errors: {errors}")
        # All 20 unique files should be backed up exactly once
        entries = layer.get_backed_up_files(600)
        self.assertEqual(len(entries), 20)
        originals = [e[0] for e in entries]
        self.assertEqual(len(set(originals)), 20, "Duplicate originals in backup map")

        shutil.rmtree(tmp, ignore_errors=True)


# ════════════════════════════════════════════════════════════════════════════ #

if __name__ == "__main__":
    unittest.main(verbosity=2)
