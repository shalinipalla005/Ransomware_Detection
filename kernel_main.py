import os
import sys
import io
import time
import signal
import logging
import tempfile
import threading
import argparse
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Optional, Set

UTC = timezone.utc

from stat_real                import run_static_layer
from ransomwall_trap_layer    import TrapLayer
from ransomwall_dynamic_layer import DynamicEngine
from backup_layer             import BackupLayer
from ml_layer                 import MLModel
from kernel_bridge            import (
    KernelBridge, IRPMessage, RansomWallSystemWithKernel,
    RW_OP_WRITE, RW_OP_RENAME, RW_OP_DELETE, RW_OP_ENTROPY_SPIKE,
    FLTLIB_AVAILABLE
)

from main import (
    FeatureAggregator,
    SUSPICION_THRESHOLD,
    MONITOR_INTERVAL_SEC,
    BENIGN_CONFIRM_TICKS,
    _setup_logging,
    ProcessManager,
)

log = logging.getLogger("RansomWall.KernelMain")


WATCHDOG_BANNER = """
+====================================================================+
|       RansomWall - SIMULATION MODE (watchdog fallback)             |
|       Kernel driver not loaded; using watchdog observation         |
|       To enable kernel mode: install_driver.bat  (run as Admin)   |
+====================================================================+
"""

class KernelProcessManager(ProcessManager):

    def __init__(self, kernel_bridge: Optional[KernelBridge] = None):
        self._bridge = kernel_bridge

    def kill(self, pid: int, logger: logging.Logger) -> bool:
        if pid in (0, -1, os.getpid()):
            logger.warning(f"[KernelProcessManager] Refusing self-kill PID={pid}")
            return False

        if self._bridge and self._bridge._port:
            logger.warning(
                f"[KERNEL-KILL] Requesting ZwTerminateProcess for PID={pid}"
            )
            killed = self._bridge.kill_pid(pid)
            if killed:
                logger.warning(
                    f"[KERNEL-KILL] SUCCESS  PID={pid}  "
                    f"(kernel ZwTerminateProcess – unblockable)"
                )
                return True
            logger.warning(
                f"[KERNEL-KILL] Kernel kill returned False for PID={pid}. "
                f"Falling back to user-mode..."
            )

        return super().kill(pid, logger)



class KernelRansomWallSystem:
    def __init__(self,
                 watch_dirs=None,
                 backup_dir: str  = "rw_backup",
                 log_path:   str  = "ransomwall_kernel.log"):

        self.log = _setup_logging(log_path)

        if watch_dirs is None:
            _tmp = Path(tempfile.gettempdir()) / "ransomwall_watch"
            _tmp.mkdir(parents=True, exist_ok=True)
            watch_dirs = [_tmp]
        self.watch_dirs = [Path(d) for d in watch_dirs]

        self._static_result: Optional[dict] = None

        self.log.info("[INIT] Initializing Trap Layer ...")
        self.trap = TrapLayer(
            watch_dirs     = self.watch_dirs,
            log_path       = "ransomwall_trap.log",
            cleanup_on_exit= True,
        )

        self.log.info("[INIT] Initializing Dynamic Analysis Engine ...")
        self.dynamic = DynamicEngine(
            watch_dirs = self.watch_dirs,
            log_path   = "ransomwall_dynamic.log",
        )

        self.log.info("[INIT] Initializing File Backup Layer ...")
        self.backup = BackupLayer(backup_dir=backup_dir)

        self.log.info("[INIT] Initializing Machine Learning Engine ...")
        self.ml = MLModel()

        self.aggregator = FeatureAggregator()

        self.log.info("[INIT] Creating Kernel Bridge ...")
        self.bridge = KernelBridge(
            dynamic_engine  = self.dynamic,
            trap_layer      = self.trap,
            on_irp_callback = self._on_kernel_irp,
        )

        self._proc_manager = KernelProcessManager(kernel_bridge=self.bridge)

        self._running              = False
        self._kernel_mode          = False    
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock                 = threading.Lock()
        self._suspicious_pids: Set[int]         = set()
        self._classified_pids: Dict[int, str]   = {}
        self._benign_ticks:    Dict[int, int]   = {}

        self.log.info("[INIT] All layers initialized. System ready.")


    def run_static(self, file_path: str) -> dict:
        self.log.info(f"[STATIC] Analyzing: {file_path}")
        result = run_static_layer(file_path)
        self._static_result = result
        self.aggregator = FeatureAggregator(static_result=result)
        return result


    def _on_kernel_irp(self, msg: IRPMessage):
        if msg.operation == RW_OP_ENTROPY_SPIKE:
            self.log.warning(
                f"[KERNEL-IRP] ENTROPY SPIKE  "
                f"PID={msg.process_id:<6}  proc={msg.process_name:<20}  "
                f"entropy={msg.entropy_x100/100:.2f}  "
                f"file=...{msg.file_path[-50:]}"
            )

        elif msg.is_ransom_extension and msg.operation == RW_OP_RENAME:
            self.log.warning(
                f"[KERNEL-IRP] RANSOM RENAME  "
                f"PID={msg.process_id:<6}  proc={msg.process_name:<20}  "
                f"{msg.file_extension} -> {msg.dest_extension}  "
                f"...{msg.file_path[-40:]}"
            )

        elif msg.fingerprint_mismatch:
            self.log.warning(
                f"[KERNEL-IRP] FINGERPRINT MISMATCH  "
                f"PID={msg.process_id:<6}  proc={msg.process_name:<20}  "
                f"ext={msg.file_extension}  "
                f"file=...{msg.file_path[-40:]}"
            )


    def start(self):
        if self._running:
            self.log.warning("[SYSTEM] Already running.")
            return

        if platform.system() == "Windows":
            kernel_connected = self.bridge.start()
            if kernel_connected:
                self._kernel_mode = True

                self.trap.honey_mgr.deploy(self.watch_dirs)
                self.trap.behavior.start(interval=2.0)
                self.trap.poller.start()
                self.log.info(
                    "[KERNEL] Trap Layer honey files deployed. "
                    "Watchdog DISABLED (kernel IRP path active)."
                )
            else:
                self.log.info(WATCHDOG_BANNER)
                self.trap.start()
                self.dynamic.start()
        else:
            self.log.info("[SYSTEM] Non-Windows OS: using watchdog simulation.")
            self.trap.start()
            self.dynamic.start()

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="KernelRansomWall-Monitor",
            daemon=True,
        )
        self._monitor_thread.start()

        mode = "KERNEL" if self._kernel_mode else "WATCHDOG"
        self.log.info(f"[SYSTEM] Monitoring started [{mode} mode]. Ctrl+C to stop.\n")

    def stop(self):
        self.log.info("[SYSTEM] Shutting down ...")
        self._running = False

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)

        self.bridge.stop()

        try:
            self.trap.stop()
        except Exception:
            pass
        try:
            self.dynamic.stop()
        except Exception:
            pass

        self.log.info("[SYSTEM] KernelRansomWall stopped.")



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
                self._process_pid(pid, trap_all.get(pid), dyn_all.get(pid))

            elapsed = time.monotonic() - t_start
            time.sleep(max(0.0, MONITOR_INTERVAL_SEC - elapsed))

    def _process_pid(self,
                     pid: int,
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
        self.log.debug(
            f"[ML] PID={pid}  verdict={verdict}  score={score:.2f}"
        )

        if verdict == "ransomware":
            self._on_ransomware(pid)
        elif verdict == "benign":
            with self._lock:
                self._benign_ticks[pid] = self._benign_ticks.get(pid, 0) + 1
                ticks = self._benign_ticks[pid]
            if ticks >= BENIGN_CONFIRM_TICKS:
                self._on_benign(pid)

    def _on_suspicious(self, pid, score, trap_status, dyn_status):
        name = (trap_status or dyn_status or {}).get("process_name", "unknown")
        self.log.warning(
            f"\n{'-'*60}\n"
            f"[ALERT] Suspicious process detected!\n"
            f"        PID   : {pid}\n"
            f"        Name  : {name}\n"
            f"        Score : {score:.2f}  (threshold={SUSPICION_THRESHOLD})\n"
            f"        Mode  : {'KERNEL IRP' if self._kernel_mode else 'watchdog'}\n"
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
                self.log.info(f"[BACKUP] Files backed up  PID={pid}  count={n}")

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

        self._proc_manager.kill(pid, self.log)

        if self._kernel_mode:
            self.bridge.whitelist_pid(pid)   

        restored = self.backup.restore(pid)
        self.log.warning(f"[ACTION] Restored {restored} file(s) for PID={pid}")

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

        if self._kernel_mode:
            self.bridge.whitelist_pid(pid)

        self.backup.cleanup(pid)
        self.ml.reset_pid(pid)

        with self._lock:
            self._suspicious_pids.discard(pid)


    def simulate_attack(self, pid: int = 1337, fast: bool = True):
        delay = 0.05 if fast else 0.3
        self.log.info(
            f"[DEMO] Injecting simulated ransomware events  PID={pid}  "
            f"mode={'KERNEL' if self._kernel_mode else 'watchdog'}"
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
            ("honey_dir_modified",   r"C:\Users\victim\Documents"),
        ]
        for feature, target in trap_events:
            self.trap.inject_test_event(feature, pid=pid, target=target)
            time.sleep(delay)

        dyn_ops = (
            [("dir_query", "",       "")] * 25 +
            [("read",   str(self.watch_dirs[0] / "data.docx"), "")] * 30 +
            [("write",  str(self.watch_dirs[0] / "data.docx"), "")] * 25 +
            [("rename", str(self.watch_dirs[0] / "data.docx"), "data.encrypted")] * 20 +
            [("delete", str(self.watch_dirs[0] / "data.docx"), "")] * 12
        )
        for op, path, dst in dyn_ops:
            self.dynamic.inject_irp(op, pid, path=path, dst_path=dst)
            time.sleep(delay * 0.3)

        self.log.info(f"[DEMO] Simulation complete for PID={pid}.")

    def status_report(self) -> dict:
        with self._lock:
            report = {
                "timestamp":       datetime.now(UTC).isoformat(),
                "kernel_mode":     self._kernel_mode,
                "suspicious_pids": list(self._suspicious_pids),
                "classified_pids": dict(self._classified_pids),
                "backup_status":   self.backup.status(),
            }
        if self._kernel_mode:
            report["driver_stats"] = self.bridge.get_driver_stats()
        return report

    def print_status(self):
        r = self.status_report()
        print(f"\n{'='*60}")
        print(f"  RansomWall Kernel Status  [{r['timestamp']}]")
        print(f"  Mode: {'KERNEL (RansomWallFilter.sys)' if r['kernel_mode'] else 'WATCHDOG (simulation)'}")
        print(f"{'='*60}")
        print(f"  Suspicious PIDs  : {r['suspicious_pids']}")
        print(f"  Classified PIDs  : {r['classified_pids']}")
        bs = r.get("backup_status", {})
        if bs:
            print("  Active Backups   :")
            for pid, info in bs.items():
                print(f"    PID {pid}: {info['files_backed_up']} file(s)")
        else:
            print("  Active Backups   : None")

        ds = r.get("driver_stats", {})
        if ds:
            print("  Kernel Stats     :")
            for k, v in ds.items():
                print(f"    {k:<30}: {v}")
        print(f"{'='*60}\n")

def run_kernel_demo():
    print("=" * 60)
    print("  KERNEL MODE DEMO")
    if FLTLIB_AVAILABLE and KernelBridge.is_driver_loaded():
        print("  RansomWallFilter.sys detected — KERNEL MODE active")
    else:
        print("  Driver not loaded — falling back to watchdog simulation")
        print("  To enable kernel mode: install_driver.bat (run as Admin)")
    print("=" * 60 + "\n")

    demo_dir = Path(tempfile.mkdtemp(prefix="rw_kernel_demo_"))
    print(f"[Demo] Working directory: {demo_dir}\n")

    rw = KernelRansomWallSystem(
        watch_dirs=[demo_dir],
        backup_dir=str(demo_dir / "backup"),
    )

    def _sigint(sig, frame):
        print("\n[Demo] Interrupted. Shutting down...")
        rw.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)

    rw.start()
    time.sleep(1.5)  

    for i in range(5):
        p = demo_dir / f"document_{i}.docx"
        with open(p, "w", encoding="utf-8") as f:
            f.write("important project data")

    with open(demo_dir / "data.docx", "w", encoding="utf-8") as f:
        f.write("sensitive office file")

    print("\n[Demo] Injecting simulated ransomware events (PID=1337)...\n")
    rw.simulate_attack(pid=1337, fast=True)

    print("\n[Demo] Waiting for ML sliding-window consensus (~6s)...")
    for i in range(6, 0, -1):
        time.sleep(1)
        sys.stdout.write(f"  {i}s...\r"); sys.stdout.flush()
    print()

    rw.print_status()
    rw.stop()

    import shutil
    shutil.rmtree(demo_dir, ignore_errors=True)
    print("[Demo] Complete.\n")

def run_kernel_monitor(target_exe: Optional[str] = None):
   
    rw = KernelRansomWallSystem()

    def _shutdown(sig, frame):
        print("\n[INFO] Shutdown signal.")
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

def show_driver_stats():
    print("[STATS] Querying RansomWallFilter.sys...")
    if not FLTLIB_AVAILABLE:
        print("[ERROR] fltlib.dll not available. Run on Windows with driver installed.")
        return

    bridge = KernelBridge()
    if not bridge.start():
        print("[ERROR] Cannot connect to kernel driver. Is it running?")
        print("  Check: install_driver.bat status")
        return

    stats = bridge.get_driver_stats()
    if stats:
        print("\nKernel Driver Statistics:")
        print(f"  {'Metric':<30}  Value")
        print(f"  {'-'*45}")
        for k, v in stats.items():
            print(f"  {k:<30}  {v}")
    else:
        print("[WARN] No stats returned from driver.")
    bridge.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="RansomWall Kernel-Mode Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --demo           Full pipeline demo (uses kernel driver if loaded)
  --monitor        Real-time monitoring (Ctrl+C to stop)
  --static FILE    Static analysis on PE binary, then monitor
  --stats          Print kernel driver statistics and exit

Setup (Windows, run as Admin):
  1. Build:         install_driver.bat build
  2. Test-sign:     install_driver.bat testsign   (then reboot)
  3. Install:       install_driver.bat install
  4. Monitor:       python kernel_main.py --monitor

Examples:
  python kernel_main.py --demo
  python kernel_main.py --monitor
  python kernel_main.py --static suspect.exe --monitor
  python kernel_main.py --stats
        """,
    )
    parser.add_argument("--demo",    action="store_true", help="Run pipeline demo")
    parser.add_argument("--monitor", action="store_true", help="Real-time monitoring")
    parser.add_argument("--static",  metavar="FILE",      help="Static pre-analysis on PE")
    parser.add_argument("--stats",   action="store_true", help="Print driver stats and exit")
    args = parser.parse_args()

    if args.stats:
        show_driver_stats()
    elif args.demo:
        run_kernel_demo()
    elif args.monitor or args.static:
        run_kernel_monitor(target_exe=args.static)
    else:
        run_kernel_demo()
