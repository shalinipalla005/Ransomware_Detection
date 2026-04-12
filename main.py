"""
RansomWall: Main Orchestrator
==============================
Based on: "RansomWall: A Layered Defense System against Cryptographic
Ransomware Attacks using Machine Learning" (COMSNETS 2018)
IIT Delhi - Shaukat & Ribeiro

Paper §IV-A (Logical Workflow):
  1. TrapLayer      → honey-file / behavioral monitoring (early detection)
  2. StaticLayer    → PE signature, packers, suspicious strings
  3. DynamicLayer   → file I/O counters, entropy, rename heuristics
  4. BackupLayer    → backs up modified files for suspicious PIDs
  5. MLLayer        → sliding-window classification → Ransomware | Benign
  6. kill_process() → terminate ransomware PID; restore or cleanup backup
"""

import os
import sys
import time
import signal
import logging
import threading
from pathlib import Path

# ── Fix Windows console Unicode (cp1252 -> utf-8) ────────────────────────────
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Layer imports ────────────────────────────────────────────────────────────
from ransomwall_trap_layer import TrapLayer, get_honey_directories
from dynamic_layer          import DynamicAnalyzer
from backup_layer           import BackupLayer
from ml_layer               import MLModel
from stat_real              import run_static_layer

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MAIN] %(levelname)s  %(message)s",
    handlers=[
        logging.FileHandler("ransomwall_main.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("RansomWall.Main")

# ── Layer instances ───────────────────────────────────────────────────────────
trap    = TrapLayer(cleanup_on_exit=True)
dynamic = DynamicAnalyzer()
backup  = BackupLayer(backup_dir="rw_backup")
ml      = MLModel()

# ── Already-processed PIDs (avoid reprocessing) ───────────────────────────────
_processed: set = set()
_lock = threading.Lock()


# ────────────────────────────────────────────────────────────────────────────
def kill_process(pid: int) -> bool:
    """
    Paper §IV-A: "If the Machine Learning Layer classifies as Ransomware,
    then the process is killed."
    """
    try:
        import psutil
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.kill()
        log.warning(f"[!] KILLED ransomware process  PID={pid}  name={proc_name}")
        return True
    except Exception as e:
        # Fallback to OS-level kill
        try:
            os.kill(pid, signal.SIGKILL)
            log.warning(f"[!] KILLED (SIGKILL) PID={pid}")
            return True
        except Exception as e2:
            log.error(f"[kill_process] Failed to kill PID {pid}: {e2}")
            return False


# ────────────────────────────────────────────────────────────────────────────
def analyze_static(pid: int) -> dict:
    """
    Paper §III-B-1 (Static Analysis Engine):
    Runs before or alongside dynamic monitoring.
    Tries to locate the executable for the PID and run static analysis.
    Returns empty dict if analysis is not possible.
    """
    try:
        import psutil
        proc = psutil.Process(pid)
        exe  = proc.exe()
        if exe and Path(exe).exists():
            log.info(f"[StaticLayer] Analyzing executable: {exe}")
            result = run_static_layer(exe)
            # Map static features into ML-compatible feature names
            features = {}
            if result.get("signature_valid") is False:
                features["invalid_signature"] = 1
            if result.get("packed_sections"):
                features["packed_binary"] = len(result["packed_sections"])
            if result.get("suspicious_strings"):
                features["suspicious_strings"] = len(result["suspicious_strings"])
            return features
    except Exception as e:
        log.debug(f"[StaticLayer] Could not analyze PID {pid}: {e}")
    return {}


# ────────────────────────────────────────────────────────────────────────────
def process_suspicious_pid(pid: int, info: dict):
    """
    Paper §IV-A Logical Workflow for a single suspicious PID:
      1. Run Dynamic Analysis Engine
      2. Run Static Analysis Engine  (best-effort)
      3. Merge all feature vectors
      4. Back up files modified so far
      5. Feed merged features to ML Engine
      6. Act on classification: kill+restore | cleanup
    """
    log.info(f"\n{'='*60}")
    log.info(f"[*] Processing suspicious PID: {pid}")
    log.info(f"    Name  : {info.get('process_name', 'unknown')}")
    log.info(f"    Score : {info.get('suspicion_score', 0)}")
    log.info(f"    Features (trap): {list(info.get('triggered_features', {}).keys())}")

    # ── Step 1: Dynamic features ─────────────────────────────────────────────
    dynamic_features = dynamic.analyze(pid)
    log.info(f"    Features (dynamic): {dynamic_features}")

    # ── Step 2: Static features (best-effort) ────────────────────────────────
    static_features = analyze_static(pid)
    log.info(f"    Features (static): {static_features}")

    # ── Step 3: Merge feature vectors ────────────────────────────────────────
    # Paper §IV-A: Feature Collector accumulates from all layers
    features = {
        **info.get("triggered_features", {}),
        **dynamic_features,
        **static_features,
    }

    # ── Step 4: Backup files modified by this PID ────────────────────────────
    # Paper §III-B-4: "Files modified by the suspicious process are backed up"
    # We use honey file paths recorded by the trap layer as a proxy for
    # recently modified files (a kernel IRP filter would give the real list)
    modified_files = list(info.get("triggered_features", {}).keys())
    # Also try psutil open_files for additional paths
    try:
        import psutil
        proc = psutil.Process(pid)
        open_paths = [f.path for f in proc.open_files()]
        modified_files = list(set(modified_files + open_paths))
    except Exception:
        pass

    backup.backup(pid, modified_files)

    # ── Step 5: ML classification ────────────────────────────────────────────
    result = ml.predict(pid, features)
    log.info(f"    [ML RESULT] PID={pid} -> {result.upper()}")

    # ── Step 6: Act on classification ────────────────────────────────────────
    if result == "ransomware":
        log.warning(f"[!!!] RANSOMWARE DETECTED  PID={pid}  -> Killing & Restoring")
        killed = kill_process(pid)
        if killed:
            backup.restore(pid)
            log.warning(f"[+] Files restored for PID {pid}")
        else:
            log.error(f"[!] Could not kill PID {pid}; backup preserved for manual recovery")
    else:
        log.info(f"[+] PID {pid} classified as BENIGN -> Cleaning up backup")
        backup.cleanup(pid)

    log.info(f"{'='*60}\n")


# ────────────────────────────────────────────────────────────────────────────
def main():
    log.info("[*] ============================================")
    log.info("[*]  RansomWall - Layered Defense System")
    log.info("[*]  COMSNETS 2018  |  Shaukat & Ribeiro")
    log.info("[*] ============================================")
    log.info("[*] Starting all layers...")

    # ── Start the Trap Layer ─────────────────────────────────────────────────
    trap.start()
    log.info("[*] TrapLayer     -> ACTIVE")
    log.info("[*] DynamicLayer  -> ACTIVE (on-demand per PID)")
    log.info("[*] BackupLayer   -> ACTIVE")
    log.info("[*] MLLayer       -> ACTIVE")
    log.info("[*] StaticLayer   -> ACTIVE (on-demand per PID)")
    log.info("[*] Monitoring... (Ctrl+C to stop)\n")

    try:
        while True:
            time.sleep(3)   # Paper: Feature Collector fetches values at regular intervals

            # Get all processes flagged as suspicious by the Trap Layer
            suspects = trap.get_status()

            for pid, info in suspects.items():

                if not info.get("flagged_suspicious"):
                    continue

                with _lock:
                    if pid in _processed:
                        continue
                    _processed.add(pid)

                # Offload to a thread so we can keep monitoring while processing
                t = threading.Thread(
                    target=process_suspicious_pid,
                    args=(pid, info),
                    daemon=True,
                    name=f"RW-Analyze-{pid}",
                )
                t.start()

    except KeyboardInterrupt:
        log.info("\n[*] Shutdown requested by user.")
    finally:
        trap.stop()
        log.info("[*] RansomWall stopped.")


# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()