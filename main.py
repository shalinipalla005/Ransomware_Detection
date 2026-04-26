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


from stat_real                import run_static_layer
from ransomwall_trap_layer    import TrapLayer
from ransomwall_dynamic_layer import DynamicEngine
from backup_layer             import BackupLayer
from ml_layer                 import MLModel



MONITOR_INTERVAL_SEC = 1.0

SUSPICION_THRESHOLD = 6.0

BENIGN_CONFIRM_TICKS = 5

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

    fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")  
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)

    utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sh = logging.StreamHandler(utf8_stdout)  
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger

class FeatureAggregator:
    def __init__(self, static_result: Optional[dict] = None):
        self._static: dict = static_result or {}

    def _static_features(self) -> dict:
        s = self._static
        return {
            "invalid_signature":  0 if s.get("signature_valid") else 1,
            "packed_binary":      1 if s.get("packed_sections")  else 0,
            "suspicious_strings": min(len(s.get("suspicious_strings", [])), 5),
        }
    
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
        features = {}
        features.update(self._trap_features(trap_status))
        features.update(self._dynamic_features(dyn_status))
        features.update(self._static_features())
        return features

    @staticmethod
    def suspicion_score(trap_status: Optional[dict],
                        dyn_status:  Optional[dict]) -> float:
    
        trap_score = (trap_status or {}).get("suspicion_score", 0.0)
        dyn_score  = (dyn_status  or {}).get("suspicion_score", 0.0)
        return trap_score + dyn_score

class ProcessManager:

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


class RansomWallSystem:

    def __init__(self,
                 watch_dirs=None,
                 backup_dir: str = "rw_backup",
                 log_path:   str = "ransomwall_main.log"):

        self.log = _setup_logging(log_path)

        if watch_dirs is None:
            _tmp = Path(tempfile.gettempdir()) / "ransomwall_watch"
            _tmp.mkdir(parents=True, exist_ok=True)
            watch_dirs = [_tmp]
        self.watch_dirs = [Path(d) for d in watch_dirs]

  
        self._static_result: Optional[dict] = None

        self.log.info("[INIT] Initializing Trap Layer ...")
        self.trap = TrapLayer(
            watch_dirs=self.watch_dirs,
            log_path="ransomwall_trap.log",
            cleanup_on_exit=True,
        )

        self.log.info("[INIT] Initializing Dynamic Analysis Engine ...")
        self.dynamic = DynamicEngine(
            watch_dirs=self.watch_dirs,
            log_path="ransomwall_dynamic.log",
        )

        self.log.info("[INIT] Initializing File Backup Layer ...")
        self.backup = BackupLayer(backup_dir=backup_dir)

        self.log.info("[INIT] Initializing Machine Learning Engine ...")
        self.ml = MLModel()

        self.aggregator = FeatureAggregator()

        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self._suspicious_pids: Set[int] = set()

        self._classified_pids: Dict[int, str] = {}

        self._benign_ticks: Dict[int, int] = {}

        self.log.info("[INIT] All layers initialized. System ready.")


    def run_static(self, file_path: str) -> dict:
 
        self.log.info(f"[STATIC] Running static analysis on: {file_path}")
        result = run_static_layer(file_path)
        self._static_result = result

        self.aggregator = FeatureAggregator(static_result=result)
        return result

    def start(self):
        if self._running:
            self.log.warning("[SYSTEM] Already running.")
            return

        self.log.info("[SYSTEM] Starting monitoring layers ...")

        self.trap.start()

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
        self.log.info("[SYSTEM] Shutting down ...")
        self._running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        self.trap.stop()
        self.dynamic.stop()
        self.log.info("[SYSTEM] RansomWall stopped.")

    def _monitor_loop(self):
        
        while self._running:
            t_start = time.monotonic()

            trap_all = self.trap.get_status()     
            dyn_all  = self.dynamic.get_status()  
            all_pids = set(trap_all.keys()) | set(dyn_all.keys())

            for pid in all_pids:
                if pid in (0, -1):
                    continue
                with self._lock:
                    if pid in self._classified_pids:
                        continue  

                self._process_pid(
                    pid,
                    trap_all.get(pid),
                    dyn_all.get(pid),
                )

            elapsed   = time.monotonic() - t_start
            time.sleep(max(0.0, MONITOR_INTERVAL_SEC - elapsed))


    def _process_pid(self,
                     pid:         int,
                     trap_status: Optional[dict],
                     dyn_status:  Optional[dict]):

        score = self.aggregator.suspicion_score(trap_status, dyn_status)

        with self._lock:
            was_suspicious = pid in self._suspicious_pids

        if score >= SUSPICION_THRESHOLD and not was_suspicious:
            with self._lock:
                self._suspicious_pids.add(pid)
            self._on_suspicious(pid, score, trap_status, dyn_status)

        if pid not in self._suspicious_pids:
            return  

        features = self.aggregator.build(trap_status, dyn_status)


        self._trigger_backup(pid, dyn_status)

        verdict = self.ml.predict(pid, features)
        verdict = str(verdict).strip().lower()

        self.log.debug(
            f"[ML] PID={pid}  bucket_verdict={verdict}  score={score:.2f}"
        )

        if verdict == "ransomware":
            self._on_ransomware(pid)
        else:
            with self._lock:
                self._benign_ticks[pid] = self._benign_ticks.get(pid, 0) + 1
                ticks = self._benign_ticks[pid]
            if ticks >= BENIGN_CONFIRM_TICKS:
                self._on_benign(pid)

    def _on_suspicious(self,
                       pid:         int,
                       score:       float,
                       trap_status: Optional[dict],
                       dyn_status:  Optional[dict]):

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

        files_to_back: Set[str] = set()

        if dyn_status:
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

        with self._lock:
            if self._classified_pids.get(pid) == "ransomware":
                return
            self._classified_pids[pid] = "ransomware"

        self.log.warning(
            f"\n{'='*60}\n"
            f"[ML]     RANSOMWARE CONFIRMED  PID={pid}\n"
            f"{'='*60}"
        )

        ProcessManager.kill(pid, self.log)

        restored = self.backup.restore(pid)
        self.log.warning(
            f"[ACTION] Restored {restored} file(s) for PID={pid}"
        )

        self.ml.reset_pid(pid)

    def _on_benign(self, pid: int):

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


    def simulate_attack(self, pid: int = 1337, fast: bool = True):
  
        delay = 0.05 if fast else 0.3
        self.log.info(
            f"[DEMO] Injecting simulated ransomware events for PID={pid}"
        )

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

def run_demo():
    
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

    rw.start()
    time.sleep(1.0)  

  
    print("\n[Demo] Injecting simulated ransomware events (PID=1337) ...\n")
    rw.simulate_attack(pid=1337, fast=True)

    print("\n[Demo] Waiting for ML sliding-window consensus (~6 seconds) ...")
    for i in range(6, 0, -1):
        time.sleep(1)
        sys.stdout.write(f"         {i}s ...\r")
        sys.stdout.flush()
    print()

    rw.print_status()

    rw.stop()
    import shutil
    shutil.rmtree(demo_dir, ignore_errors=True)
    print("[Demo] RansomWall demo complete.\n")



def run_monitor(target_exe: Optional[str] = None):
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



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="RansomWall - Layered Ransomware Defense",
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
        run_demo()   
