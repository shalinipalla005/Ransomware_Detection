"""
RansomWall: Main Pipeline Controller
=====================================
Based on: "RansomWall: A Layered Defense System against Cryptographic
Ransomware Attacks using Machine Learning" (COMSNETS 2018)
IIT Delhi - Shaukat & Ribeiro

Architecture Overview
---------------------
This module is the top-level orchestrator that integrates all 5 RansomWall
layers exactly as described in the paper (Section III-B, IV-A):

    [EXE] --> Static Analysis Engine      (pre-execution, Layer 1)
                    |
                    v  (during execution)
     .--------------------------------.
     |  Honey Files & Trap Layer      |
     |  Dynamic Analysis Engine       | --> Feature Collector
     '--------------------------------'          |
                                       (score >= THRESHOLD)
                                                 |
                                      .---------------------.
                                      |  File Backup Layer  |
                                      '---------------------'
                                                 |
                                      .---------------------.
                                      |  ML Engine (GBT)    |
                                      '---------------------'
                                           |          |
                                      Ransomware    Benign
                                     Kill+Restore  Del Backup

Paper Section IV-A Workflow:
  Step 1 - Static layer runs first, before sample execution.
  Step 2 - TrapLayer + DynamicEngine run concurrently during execution.
  Step 3 - FeatureCollector aggregates feature values per process (per bucket).
  Step 4 - If combined score >= SUSPICION_THRESHOLD: tag as suspicious.
  Step 5 - BackupLayer starts backing up modified files for suspicious PIDs.
  Step 6 - MLEngine classifies per sliding-window bucket (every 1 second).
  Step 7 - Action: kill + restore (ransomware) OR delete backup (benign).
"""

import os, io
import sys
import time
import signal
import logging
import tempfile
import threading
import platform
from pathlib import Path
from datetime import datetime, timezone

from numpy import False_
UTC = timezone.utc
from typing import Dict, Optional, Set

# ---------------------------------------------------------------------------
# Layer imports
# ---------------------------------------------------------------------------
from stat_real                import run_static_layer
from ransomwall_trap_layer    import TrapLayer
from ransomwall_dynamic_layer import DynamicEngine
from backup_layer             import BackupLayer
from ml_layer                 import MLModel


# ===========================================================================
# CONFIGURATION
# ===========================================================================

# Paper Section IV-C: bucket = 1 second
MONITOR_INTERVAL_SEC = 1.0

# Paper Section IV-A: "6 or more feature indicators -> tagged as suspicious"
SUSPICION_THRESHOLD = 6.0

# Consecutive benign ticks before we finalize cleanup
BENIGN_CONFIRM_TICKS = 5


# ===========================================================================
# LOGGING
# ===========================================================================

def _setup_logging(log_path: str = "ransomwall_main.log") -> logging.Logger:
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  |  %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger("RansomWall.Main")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    if logger.handlers:
        return logger

    fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")  # <-- add encoding
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)

    # Force UTF-8 on stdout to handle Unicode arrow characters
    utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sh = logging.StreamHandler(utf8_stdout)  # <-- wrap stdout
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger

# ===========================================================================
# FEATURE AGGREGATOR
# Paper Section IV-A: "Feature Collector which accumulates feature values
# for each process."
# ===========================================================================

class FeatureAggregator:
    """
    Merges outputs from TrapLayer.get_status(pid) and
    DynamicEngine.get_status(pid) into the 18-dim feature vector
    expected by ml_layer.FEATURE_NAMES.
    """

    def __init__(self, static_result: Optional[dict] = None):
        self._static: dict = static_result or {}

    # -- Static features (pre-execution, paper Section III-D-1) -------------
    def _static_features(self) -> dict:
        s = self._static
        return {
            "invalid_signature":  0 if s.get("signature_valid") else 1,
            "packed_binary":      1 if s.get("packed_sections")  else 0,
            "suspicious_strings": min(len(s.get("suspicious_strings", [])), 5),
        }

    # -- Trap-layer features (paper Section III-D-2) -------------------------
    @staticmethod
    def _trap_features(trap_status: Optional[dict]) -> dict:
        tf = (trap_status or {}).get("triggered_features", {})
        return {
            "honey_file_write":     tf.get("honey_file_write",     0),
            "honey_file_rename":    tf.get("honey_file_rename",    0),
            "honey_file_delete":    tf.get("honey_file_delete",    0),
            "honey_dir_modified":   tf.get("honey_dir_modified",   0),
            "crypto_api_usage":     tf.get("crypto_api_usage",     0),
            "safe_mode_disabled":   tf.get("safe_mode_disabled",   0),
            "vss_deletion":         tf.get("vss_deletion",         0),
            "registry_persistence": tf.get("registry_persistence", 0),
            "entropy_spike":        tf.get("entropy_spike",        0),
        }

    # -- Dynamic features (paper Section III-D-3) ----------------------------
    @staticmethod
    def _dynamic_features(dyn_status: Optional[dict]) -> dict:
        fv = (dyn_status or {}).get("feature_vector", {})
        return {
            "file_read":            fv.get("read_count",           0),
            "file_write":           fv.get("write_count",          0),
            "file_rename":          fv.get("rename_count",         0),
            "file_delete":          fv.get("delete_count",         0),
            "dir_query":            fv.get("dir_query_count",      0),
            "fingerprint_mismatch": fv.get("fingerprint_mismatch", 0),
        }

    def build(self, trap_status: Optional[dict],
              dyn_status: Optional[dict]) -> dict:
        """Unified feature vector for the ML engine."""
        features = {}
        features.update(self._trap_features(trap_status))
        features.update(self._dynamic_features(dyn_status))
        features.update(self._static_features())
        return features

    @staticmethod
    def suspicion_score(trap_status: Optional[dict],
                        dyn_status:  Optional[dict]) -> float:
        """
        Combined score from both layers.
        Paper Section IV-A: >= SUSPICION_THRESHOLD -> tag as suspicious.
        """
        trap_score = (trap_status or {}).get("suspicion_score", 0.0)
        dyn_score  = (dyn_status  or {}).get("suspicion_score", 0.0)
        return trap_score + dyn_score


# ===========================================================================
# PROCESS MANAGER
# ===========================================================================

class ProcessManager:
    """
    Handles process termination (paper Section IV-A: "the process is killed").
    Falls back to simulation when process not found or no permission.
    """

    @staticmethod
    def kill(pid: int, logger: logging.Logger) -> bool:
        if pid in (0, -1, os.getpid()):
            logger.warning(f"[ProcessManager] Skipping kill for PID {pid}")
            return False
        try:
            import psutil
            proc = psutil.Process(pid)
            name = proc.name()
            proc.kill()
            logger.warning(f"[ACTION] KILLED process  PID={pid}  name={name}")
            return True
        except ImportError:
            try:
                if platform.system() == "Windows":
                    import subprocess
                    subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                                   capture_output=True)
                else:
                    os.kill(pid, signal.SIGKILL)
                logger.warning(f"[ACTION] KILLED process PID={pid}")
                return True
            except ProcessLookupError:
                logger.info(f"[ProcessManager] PID {pid} already terminated.")
                return False
            except PermissionError:
                logger.error(
                    f"[ProcessManager] No permission to kill PID {pid} "
                    f"(marked terminated in simulation)."
                )
                return False
        except Exception as e:
            logger.debug(f"[ProcessManager] kill PID={pid}: {e}")
            return False


# ===========================================================================
# RANSOMWALL SYSTEM
# ===========================================================================

class RansomWallSystem:
    """
    Top-level pipeline orchestrator following the RansomWall paper
    Section III-B and Section IV-A exactly.

    Public API:
      run_static(file_path)  - pre-execution static analysis (Layer 1)
      start()                - begin real-time monitoring
      stop()                 - graceful shutdown
      simulate_attack(pid)   - inject synthetic events for demo/testing
      print_status()         - pretty-print current system state
    """

    def __init__(self,
                 watch_dirs=None,
                 backup_dir: str = "rw_backup",
                 log_path:   str = "ransomwall_main.log"):

        self.log = _setup_logging(log_path)

        # Watch directories shared between Trap and Dynamic layers
        if watch_dirs is None:
            _tmp = Path(tempfile.gettempdir()) / "ransomwall_watch"
            _tmp.mkdir(parents=True, exist_ok=True)
            watch_dirs = [_tmp]
        self.watch_dirs = [Path(d) for d in watch_dirs]

        # ---- Layer 1: Static Analysis Engine (pre-execution) ---------------
        # Invoked via run_static(); no persistent object needed.
        self._static_result: Optional[dict] = None

        # ---- Layer 2: Honey Files & Trap Layer -----------------------------
        self.log.info("[INIT] Initializing Trap Layer ...")
        self.trap = TrapLayer(
            watch_dirs=self.watch_dirs,
            log_path="ransomwall_trap.log",
            cleanup_on_exit=True,
        )

        # ---- Layer 3: Dynamic Analysis Engine ------------------------------
        self.log.info("[INIT] Initializing Dynamic Analysis Engine ...")
        self.dynamic = DynamicEngine(
            watch_dirs=self.watch_dirs,
            log_path="ransomwall_dynamic.log",
        )

        # ---- Layer 4: File Backup Layer ------------------------------------
        self.log.info("[INIT] Initializing File Backup Layer ...")
        self.backup = BackupLayer(backup_dir=backup_dir)

        # ---- Layer 5: Machine Learning Engine ------------------------------
        self.log.info("[INIT] Initializing Machine Learning Engine ...")
        self.ml = MLModel()

        # ---- Feature Aggregator (paper: Feature Collector) -----------------
        self.aggregator = FeatureAggregator()

        # ---- Runtime state -------------------------------------------------
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # PIDs currently tagged suspicious (paper Section IV-A)
        self._suspicious_pids: Set[int] = set()

        # Final classification per PID: "ransomware" | "benign"
        self._classified_pids: Dict[int, str] = {}

        # Consecutive benign ticks before finalizing benign cleanup
        self._benign_ticks: Dict[int, int] = {}

        self.log.info("[INIT] All layers initialized. System ready.")

    # =======================================================================
    # LAYER 1: STATIC ANALYSIS  (pre-execution)
    # Paper Section III-B-1: "features can be obtained before executing
    # the sample ... This is the FIRST layer of RansomWall Architecture."
    # =======================================================================

    def run_static(self, file_path: str) -> dict:
        """
        Run static analysis: PE signature, packer entropy, FLOSS strings.
        Call this before starting the monitored process.
        """
        self.log.info(f"[STATIC] Running static analysis on: {file_path}")
        result = run_static_layer(file_path)
        self._static_result = result
        # Rebuild aggregator with static context so every feature vector
        # includes static indicators alongside dynamic/trap ones.
        self.aggregator = FeatureAggregator(static_result=result)
        return result

    # =======================================================================
    # START / STOP
    # =======================================================================

    def start(self):
        """
        Paper Section IV-A: Start Trap + Dynamic layers, then launch the
        1-second monitoring loop.
        """
        if self._running:
            self.log.warning("[SYSTEM] Already running.")
            return

        self.log.info("[SYSTEM] Starting monitoring layers ...")

        # Paper Section III-B-2: deploy honey files + start watchdog
        self.trap.start()

        # Paper Section III-B-3: start file-system event monitoring
        self.dynamic.start()

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="RansomWall-Monitor",
            daemon=True,
        )
        self._monitor_thread.start()

        self.log.info("[INFO] Monitoring started. Press Ctrl+C to stop.\n")

    def stop(self):
        """Graceful shutdown of all layers."""
        self.log.info("[SYSTEM] Shutting down ...")
        self._running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        self.trap.stop()
        self.dynamic.stop()
        self.log.info("[SYSTEM] RansomWall stopped.")

    # =======================================================================
    # MONITORING LOOP
    # Paper Section IV-C: "Bucket Size = 1 second"
    # =======================================================================

    def _monitor_loop(self):
        """
        Every 1-second bucket:
          1. Collect Trap + Dynamic status for all active PIDs.
          2. Compute combined suspicion score.
          3. Tag suspicious -> trigger Backup + ML.
          4. Sliding-window ML consensus.
          5. Act on final verdict.
        """
        while self._running:
            t_start = time.monotonic()

            # Gather all PIDs seen by either layer
            trap_all = self.trap.get_status()     # {pid: status_dict}
            dyn_all  = self.dynamic.get_status()  # {pid: status_dict}
            all_pids = set(trap_all.keys()) | set(dyn_all.keys())

            for pid in all_pids:
                if pid in (0, -1):
                    continue
                with self._lock:
                    if pid in self._classified_pids:
                        continue  # already fully classified

                self._process_pid(
                    pid,
                    trap_all.get(pid),
                    dyn_all.get(pid),
                )

            elapsed   = time.monotonic() - t_start
            time.sleep(max(0.0, MONITOR_INTERVAL_SEC - elapsed))

    # =======================================================================
    # PER-PID PIPELINE
    # =======================================================================

    def _process_pid(self,
                     pid:         int,
                     trap_status: Optional[dict],
                     dyn_status:  Optional[dict]):
        """
        Full pipeline for one PID in one time bucket.
        Directly maps to paper Section IV-A logical workflow.
        """

        # -- Step 1: Combined suspicion score --------------------------------
        score = self.aggregator.suspicion_score(trap_status, dyn_status)

        # -- Step 2: Suspicion tagging (paper Section IV-A: >= 6 indicators) -
        with self._lock:
            was_suspicious = pid in self._suspicious_pids

        if score >= SUSPICION_THRESHOLD and not was_suspicious:
            with self._lock:
                self._suspicious_pids.add(pid)
            self._on_suspicious(pid, score, trap_status, dyn_status)

        if pid not in self._suspicious_pids:
            return  # not yet suspicious; no backup or ML needed

        # -- Step 3: Build unified 18-dim feature vector ---------------------
        features = self.aggregator.build(trap_status, dyn_status)

        # -- Step 4: Backup modified files -----------------------------------
        # Paper Section III-B-4: "Filtered IRPs forwarded to File Backup
        # Layer. If it observes a file modification request by the suspicious
        # process, then the file is backed up in a backup folder."
        self._trigger_backup(pid, dyn_status)

        # -- Step 5: ML classification (sliding-window) ----------------------
        # Paper Section IV-C: same classification for 3 contiguous intervals
        verdict = self.ml.predict(pid, features)
        verdict = str(verdict).strip().lower()

        self.log.debug(
            f"[ML] PID={pid}  bucket_verdict={verdict}  score={score:.2f}"
        )

        # -- Step 6: Act on consensus verdict --------------------------------
        if verdict == "ransomware":
            self._on_ransomware(pid)
        else:
            with self._lock:
                self._benign_ticks[pid] = self._benign_ticks.get(pid, 0) + 1
                ticks = self._benign_ticks[pid]
            if ticks >= BENIGN_CONFIRM_TICKS:
                self._on_benign(pid)

    # =======================================================================
    # EVENT HANDLERS
    # =======================================================================

    def _on_suspicious(self,
                       pid:         int,
                       score:       float,
                       trap_status: Optional[dict],
                       dyn_status:  Optional[dict]):
        """
        Paper Section IV-A: "process is tagged as suspicious based on
        initial features of Static, Dynamic and Trap layers."
        """
        name = (trap_status or dyn_status or {}).get("process_name", "unknown")
        self.log.warning(
            f"\n{'-'*60}\n"
            f"[ALERT] Suspicious process detected!\n"
            f"        PID   : {pid}\n"
            f"        Name  : {name}\n"
            f"        Score : {score:.2f}  (threshold={SUSPICION_THRESHOLD})\n"
            f"{'-'*60}"
        )

    def _trigger_backup(self, pid: int, dyn_status: Optional[dict]):
        """
        Paper Section III-B-4: "Files modified by the suspicious process are
        backed up in a separate folder to preserve user data."
        """
        files_to_back: Set[str] = set()

        if dyn_status:
            # DynamicEngine tracks recently-modified file paths
            for fpath in dyn_status.get("modified_files", []):
                if fpath and os.path.isfile(fpath):
                    files_to_back.add(fpath)

        if files_to_back:
            n = self.backup.backup(pid, list(files_to_back))
            if n:
                self.log.info(
                    f"[BACKUP] Files backed up  PID={pid}  count={n}"
                )

    def _on_ransomware(self, pid: int):
        """
        Paper Section III-B-4: "If Machine Learning layer classifies as
        Ransomware, the process is killed and files modified by it are
        restored to their original locations."
        """
        with self._lock:
            if self._classified_pids.get(pid) == "ransomware":
                return
            self._classified_pids[pid] = "ransomware"

        self.log.warning(
            f"\n{'='*60}\n"
            f"[ML]     RANSOMWARE CONFIRMED  PID={pid}\n"
            f"{'='*60}"
        )

        # Kill the ransomware process
        ProcessManager.kill(pid, self.log)

        # Restore all files backed up for this PID
        restored = self.backup.restore(pid)
        self.log.warning(
            f"[ACTION] Restored {restored} file(s) for PID={pid}"
        )

        # Reset ML sliding window for this PID
        self.ml.reset_pid(pid)

    def _on_benign(self, pid: int):
        """
        Paper Section III-B-4: "If classified as Benign then files backed
        up due to the suspicious process are deleted."
        """
        with self._lock:
            if self._classified_pids.get(pid) == "benign":
                return
            self._classified_pids[pid] = "benign"

        self.log.info(
            f"\n{'-'*60}\n"
            f"[ML]     Process classified BENIGN  PID={pid}\n"
            f"         Deleting backup copies ...\n"
            f"{'-'*60}"
        )

        self.backup.cleanup(pid)
        self.ml.reset_pid(pid)

        with self._lock:
            self._suspicious_pids.discard(pid)

    # =======================================================================
    # DEMO / SIMULATION
    # =======================================================================

    def simulate_attack(self, pid: int = 1337, fast: bool = True):
        """
        Inject synthetic ransomware-like events into Trap + Dynamic layers
        for a given PID.  Mirrors the attack sequence from paper Section V-B
        sandbox evaluation.
        """
        delay = 0.05 if fast else 0.3
        self.log.info(
            f"[DEMO] Injecting simulated ransomware events for PID={pid}"
        )

        # Trap layer events (paper Section III-D-2 features)
        trap_events = [
            ("honey_file_write",     "decoy_report.docx"),
            ("honey_file_rename",    "decoy_report.docx"),
            ("crypto_api_usage",     "rsaenh.dll,bcrypt.dll,crypt32.dll"),
            ("safe_mode_disabled",   "bcdedit.exe"),
            ("vss_deletion",         "vssadmin.exe delete shadows /all"),
            ("entropy_spike",        "important_data.xlsx"),
            ("registry_persistence", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
            ("honey_file_delete",    "decoy_photo.jpg"),
            ("honey_dir_modified",   "C:\\Users\\victim\\Documents"),
        ]
        for feature, target in trap_events:
            self.trap.inject_test_event(feature, pid=pid, target=target)
            time.sleep(delay)

        # Dynamic layer events (paper Section III-D-3 features)
        # Simulate: directory scan -> mass read -> mass write -> rename -> delete
        dyn_ops = (
            [("dir_query", "",              "")] * 25 +
            [("read",   "data.docx",        "")] * 30 +
            [("write",  "data.docx",        "")] * 25 +
            [("rename", "data.docx", "data.encrypted")] * 20 +
            [("delete", "data.docx",        "")] * 12
        )
        for op, path, dst in dyn_ops:
            self.dynamic.inject_irp(op, pid, path=path, dst_path=dst)
            time.sleep(delay * 0.3)

        self.log.info(f"[DEMO] Simulation events injected for PID={pid}.")

    # =======================================================================
    # STATUS
    # =======================================================================

    def status_report(self) -> dict:
        with self._lock:
            return {
                "timestamp":       datetime.now(UTC).isoformat(),
                "suspicious_pids": list(self._suspicious_pids),
                "classified_pids": dict(self._classified_pids),
                "backup_status":   self.backup.status(),
            }

    def print_status(self):
        r = self.status_report()
        print(f"\n{'='*55}")
        print(f"  RansomWall Status  [{r['timestamp']}]")
        print(f"{'='*55}")
        print(f"  Suspicious PIDs  : {r['suspicious_pids']}")
        print(f"  Classified PIDs  : {r['classified_pids']}")
        bs = r["backup_status"]
        if bs:
            print("  Active Backups   :")
            for pid, info in bs.items():
                print(f"    PID {pid}: {info['files_backed_up']} file(s) backed up")
        else:
            print("  Active Backups   : None")
        print(f"{'='*55}\n")


# ===========================================================================
# DEMO RUNNER
# ===========================================================================

def run_demo():
    """
    Full pipeline demo - no real malware required.
      1. Initialize RansomWallSystem
      2. Start monitoring (Trap + Dynamic + ML loop)
      3. Inject synthetic ransomware attack events
      4. Wait for ML sliding-window consensus (3 x 1-sec buckets)
      5. Observe classification + action
    """
    
    print("=" * 60)
    print("  DEMO MODE - Full Pipeline Simulation")
    print("  No real malware required.")
    print("=" * 60 + "\n")

    demo_dir = Path(tempfile.mkdtemp(prefix="rw_demo_"))
    print(f"[Demo] Working directory: {demo_dir}\n")

    rw = RansomWallSystem(
        watch_dirs=[demo_dir],
        backup_dir=str(demo_dir / "backup"),
    )

    def _sigint(sig, frame):
        print("\n[Demo] Interrupted. Shutting down ...")
        rw.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)

    # Start all layers
    rw.start()
    time.sleep(1.0)  # let watchdog observers settle

    # Inject simulated attack
    print("\n[Demo] Injecting simulated ransomware events (PID=1337) ...\n")
    rw.simulate_attack(pid=1337, fast=True)

    # Wait for ML sliding-window to fill (paper: 3 contiguous buckets)
    print("\n[Demo] Waiting for ML sliding-window consensus (~6 seconds) ...")
    for i in range(6, 0, -1):
        time.sleep(1)
        sys.stdout.write(f"         {i}s ...\r")
        sys.stdout.flush()
    print()

    # Print final status
    rw.print_status()

    rw.stop()
    import shutil
    shutil.rmtree(demo_dir, ignore_errors=True)
    print("[Demo] RansomWall demo complete.\n")


# ===========================================================================
# PRODUCTION MONITOR
# ===========================================================================

def run_monitor(target_exe: Optional[str] = None):
    """
    Real monitoring mode. Optionally run static analysis on a PE first,
    then monitor continuously until Ctrl+C.
    """
    

    rw = RansomWallSystem()

    def _shutdown(sig, frame):
        print("\n[INFO] Shutdown signal received.")
        rw.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if target_exe:
        rw.run_static(target_exe)

    rw.start()

    try:
        while True:
            time.sleep(15)
            rw.print_status()
    except KeyboardInterrupt:
        rw.stop()


# ===========================================================================
# CLI
# ===========================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="RansomWall - Layered Ransomware Defense (COMSNETS 2018)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --demo           Full pipeline simulation (no real malware needed)
  --monitor        Real-time system monitoring (Ctrl+C to stop)
  --static FILE    Static analysis on a PE binary then monitor

Examples:
  python main.py --demo
  python main.py --monitor
  python main.py --static suspect.exe --monitor
        """,
    )
    parser.add_argument("--demo",    action="store_true",
                        help="Run full-pipeline simulation demo")
    parser.add_argument("--monitor", action="store_true",
                        help="Start real-time monitoring")
    parser.add_argument("--static",  metavar="FILE",
                        help="Path to executable for static pre-analysis")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.monitor or args.static:
        run_monitor(target_exe=args.static)
    else:
        run_demo()   # default
