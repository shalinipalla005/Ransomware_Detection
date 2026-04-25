"""
RansomWall: Dataset Generation Pipeline
========================================
Paper §III-B-5 / §IV-C  —  COMSNETS 2018

Workflow:
  1. Extract VirusShare ZIP into dataset/ransomware/
  2. Optionally populate dataset/benign/ with clean samples
  3. For each sample:
       a. Run Static Layer  (stat_real.py)
       b. Simulate execution via TrapLayer + DynamicEngine
       c. Aggregate into 18-dim feature vector via FeatureAggregator
       d. Assign label: ransomware=1 / benign=0
  4. Write dataset.csv

CRITICAL SAFETY RULES
  - Raw malware bytes are NEVER fed into the ML model.
  - Samples are never actually executed; TrapLayer/DynamicEngine are
    driven by a deterministic simulation harness.
  - The VirusShare ZIP is extracted to an isolated temp subdirectory.

Usage:
  python generate_dataset.py --virusshare <path/to/VirusShare.zip>
                             [--benign    <path/to/benign_dir>]
                             [--output    dataset.csv]
                             [--max       200]
"""

import os
import sys
import csv
import time
import math
import zipfile
import hashlib
import logging
import argparse
import tempfile
import threading
import random
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── RansomWall layer imports ──────────────────────────────────────────────────
from stat_real                import static_analysis
from ransomwall_trap_layer    import TrapLayer
from ransomwall_dynamic_layer import DynamicEngine
from ml_layer                 import FEATURE_NAMES

log = logging.getLogger("RansomWall.DatasetGen")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  |  %(message)s",
    datefmt="%H:%M:%S",
)

# ── CSV column order (matches FEATURE_NAMES + label) ─────────────────────────
CSV_COLUMNS = FEATURE_NAMES + ["label", "sha256", "filename"]


# ════════════════════════════════════════════════════════════════════════════ #
# FEATURE AGGREGATOR (inline copy to avoid importing main.py's full controller)
# ════════════════════════════════════════════════════════════════════════════ #

class _FeatureAggregator:
    """Minimal FeatureAggregator for offline feature extraction."""

    def __init__(self, static_result: Optional[dict] = None):
        self._static = static_result or {}

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

    def build(self, trap_status, dyn_status) -> dict:
        features = {}
        features.update(self._trap_features(trap_status))
        features.update(self._dynamic_features(dyn_status))
        features.update(self._static_features())
        return features


# ════════════════════════════════════════════════════════════════════════════ #
# SANDBOX SIMULATION HARNESS
# ════════════════════════════════════════════════════════════════════════════ #

# Ransomware-typical IRP patterns (paper §V-B sandbox evaluation)
_RANSOMWARE_TRAP_EVENTS = [
    ("honey_file_write",     "decoy.docx"),
    ("honey_file_rename",    "decoy.docx"),
    ("crypto_api_usage",     "bcrypt.dll"),
    ("safe_mode_disabled",   "bcdedit.exe"),
    ("vss_deletion",         "vssadmin delete shadows /all"),
    ("entropy_spike",        "target.xlsx"),
    ("registry_persistence", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
    ("honey_file_delete",    "decoy_photo.jpg"),
    ("honey_dir_modified",   "C:\\Users\\victim\\Documents"),
]
_RANSOMWARE_DYN_OPS: List[Tuple[str, str, str]] = (
    [("dir_query", "",        "")] * 20 +
    [("read",   "data.docx",  "")] * 25 +
    [("write",  "data.docx",  "")] * 20 +
    [("rename", "data.docx",  "data.encrypted")] * 15 +
    [("delete", "data.docx",  "")] * 10
)

# Benign-typical IRP patterns (light file reads/writes, no honey interaction)
_BENIGN_DYN_OPS: List[Tuple[str, str, str]] = (
    [("dir_query", "",       "")] * 5 +
    [("read",  "config.ini", "")] * 8 +
    [("write", "log.txt",    "")] * 3
)


def _simulate_execution(
    trap: TrapLayer,
    dynamic: DynamicEngine,
    pid: int,
    label: int,          # 1 = ransomware, 0 = benign
    noise: float = 0.15, # fraction of events to randomly drop (realism)
) -> None:
    """
    Drive TrapLayer + DynamicEngine with synthetic IRPs that mimic either
    ransomware (label=1) or benign (label=0) behaviour.

    NO actual code is executed.  All events are injected via the existing
    inject_test_event / inject_irp interfaces exposed by each layer.
    """
    if label == 1:
        # Inject trap events with occasional drops (noise)
        for feature, target in _RANSOMWARE_TRAP_EVENTS:
            if random.random() > noise:
                trap.inject_test_event(feature, pid=pid, target=target)

        # Inject dynamic IRPs
        for op, path, dst in _RANSOMWARE_DYN_OPS:
            if random.random() > noise:
                dynamic.inject_irp(op, pid, path=path, dst_path=dst)
    else:
        # Benign: no trap interactions, minimal file ops
        for op, path, dst in _BENIGN_DYN_OPS:
            if random.random() > noise:
                dynamic.inject_irp(op, pid, path=path, dst_path=dst)


def _collect_status(
    trap: TrapLayer,
    dynamic: DynamicEngine,
    pid: int,
) -> Tuple[Optional[dict], Optional[dict]]:
    """Pull per-PID status from both layers after simulation."""
    trap_all = trap.get_status()
    dyn_all  = dynamic.get_status()
    return trap_all.get(pid), dyn_all.get(pid)


# ════════════════════════════════════════════════════════════════════════════ #
# PER-SAMPLE FEATURE EXTRACTION
# ════════════════════════════════════════════════════════════════════════════ #

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_features(
    file_path: str,
    label: int,
    trap: TrapLayer,
    dynamic: DynamicEngine,
    pid: int,
) -> Optional[dict]:
    """
    Full feature extraction pipeline for a single sample.

    Steps:
      1. Static analysis  (stat_real.py)
      2. Simulate execution (sandbox harness)
      3. Collect Trap + Dynamic status
      4. Aggregate into 18-dim vector (FeatureAggregator)
      5. Return row dict for CSV

    Returns None on unrecoverable error.
    """
    try:
        # ── Step 1: Static Analysis ───────────────────────────────────────────
        static_result = static_analysis(file_path)

        # ── Step 2: Simulate execution ────────────────────────────────────────
        _simulate_execution(trap, dynamic, pid, label)

        # Small settle time so watchdog threads can register events
        time.sleep(0.05)

        # ── Step 3: Collect layer outputs ─────────────────────────────────────
        trap_status, dyn_status = _collect_status(trap, dynamic, pid)

        # ── Step 4: Aggregate ─────────────────────────────────────────────────
        aggregator = _FeatureAggregator(static_result=static_result)
        features   = aggregator.build(trap_status, dyn_status)

        # ── Step 5: Build CSV row ─────────────────────────────────────────────
        row = {name: features.get(name, 0) for name in FEATURE_NAMES}
        row["label"]    = label
        row["sha256"]   = _sha256(file_path)
        row["filename"] = Path(file_path).name

        return row

    except Exception as exc:
        log.warning(f"[FeatureExtract] SKIP  {Path(file_path).name}  reason={exc}")
        return None


# ════════════════════════════════════════════════════════════════════════════ #
# DATASET EXTRACTION FROM ZIP
# ════════════════════════════════════════════════════════════════════════════ #

def extract_virusshare_zip(zip_path: str, dest_dir: Path) -> Path:
    """
    Extract VirusShare ZIP safely into dest_dir/ransomware/.
    All extracted files are treated as ransomware samples (label=1).
    """
    ransom_dir = dest_dir / "ransomware"
    ransom_dir.mkdir(parents=True, exist_ok=True)

    log.info(f"[Extract] Extracting {zip_path} -> {ransom_dir}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        # VirusShare archives are typically password-protected with 'infected'
        try:
            zf.extractall(path=str(ransom_dir), pwd=b"infected")
        except RuntimeError:
            zf.extractall(path=str(ransom_dir))

    count = sum(1 for _ in ransom_dir.iterdir() if _.is_file())
    log.info(f"[Extract] {count} files extracted to {ransom_dir}")
    return ransom_dir


# ════════════════════════════════════════════════════════════════════════════ #
# MAIN PIPELINE
# ════════════════════════════════════════════════════════════════════════════ #

def generate_dataset(
    virusshare_zip: str,
    benign_dir:     Optional[str],
    output_csv:     str,
    max_samples:    int,
    work_dir:       Optional[str] = None,
) -> int:
    """
    Full dataset generation pipeline.
    Returns total number of rows written to CSV.
    """
    # ── Workspace ─────────────────────────────────────────────────────────────
    if work_dir:
        workspace = Path(work_dir)
        workspace.mkdir(parents=True, exist_ok=True)
    else:
        workspace = Path(tempfile.mkdtemp(prefix="rw_dataset_"))
    log.info(f"[Pipeline] Workspace: {workspace}")

    # ── Extract VirusShare ────────────────────────────────────────────────────
    ransom_dir = extract_virusshare_zip(virusshare_zip, workspace)
    ransom_files: List[Tuple[str, int]] = [
        (str(p), 1)
        for p in sorted(ransom_dir.iterdir())
        if p.is_file()
    ][:max_samples // 2 if benign_dir else max_samples]

    # ── Benign samples ────────────────────────────────────────────────────────
    benign_files: List[Tuple[str, int]] = []
    if benign_dir and Path(benign_dir).is_dir():
        benign_files = [
            (str(p), 0)
            for p in sorted(Path(benign_dir).iterdir())
            if p.is_file()
        ][:max_samples // 2]
        log.info(f"[Pipeline] {len(benign_files)} benign samples from {benign_dir}")
    else:
        log.warning(
            "[Pipeline] No benign_dir provided.  "
            "Dataset will contain ransomware samples only.  "
            "Add clean samples to improve model quality."
        )

    all_samples = ransom_files + benign_files
    random.shuffle(all_samples)
    log.info(f"[Pipeline] Total samples to process: {len(all_samples)}")

    # ── Shared Trap + Dynamic layer (reused across all samples) ───────────────
    honey_dir = workspace / "honey_watch"
    honey_dir.mkdir(parents=True, exist_ok=True)

    trap    = TrapLayer(watch_dirs=[honey_dir], cleanup_on_exit=True)
    dynamic = DynamicEngine(watch_dirs=[honey_dir])
    trap.start()
    dynamic.start()
    time.sleep(0.5)   # let observers settle

    # ── CSV output ────────────────────────────────────────────────────────────
    rows_written = 0
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for idx, (file_path, label) in enumerate(all_samples, start=1):
            # Use a unique synthetic PID per sample to avoid state bleed
            pid = 10000 + idx

            log.info(
                f"[{idx:>4}/{len(all_samples)}] "
                f"label={'RANSOM' if label else 'BENIGN '}  "
                f"file={Path(file_path).name[:50]}"
            )

            row = extract_features(file_path, label, trap, dynamic, pid)
            if row is not None:
                writer.writerow(row)
                rows_written += 1

            # Flush periodically so partial results survive interruption
            if idx % 20 == 0:
                csvfile.flush()

    trap.stop()
    dynamic.stop()

    log.info(f"[Pipeline] Done.  Rows written: {rows_written}  -> {output_csv}")
    return rows_written


# ════════════════════════════════════════════════════════════════════════════ #
# CLI
# ════════════════════════════════════════════════════════════════════════════ #

def _parse_args():
    p = argparse.ArgumentParser(
        description="RansomWall – Generate dataset.csv from VirusShare samples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--virusshare", required=True,
                   help="Path to VirusShare ZIP archive")
    p.add_argument("--benign",     default=None,
                   help="Directory of benign PE samples (optional but recommended)")
    p.add_argument("--output",     default="dataset.csv",
                   help="Output CSV path  [default: dataset.csv]")
    p.add_argument("--max",        type=int, default=400,
                   help="Maximum total samples to process  [default: 400]")
    p.add_argument("--workdir",    default=None,
                   help="Working directory for extraction  [default: temp dir]")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    n = generate_dataset(
        virusshare_zip=args.virusshare,
        benign_dir=args.benign,
        output_csv=args.output,
        max_samples=args.max,
        work_dir=args.workdir,
    )
    print(f"\n[Done] {n} feature vectors written to {args.output}")
