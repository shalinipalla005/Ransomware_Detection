# RansomWall 

## Files in the project

| File | Purpose |
|---|---|
| `main.py` | Top-level orchestrator — starts all layers, runs monitoring loop |
| `stat_real.py` | Layer 1: Static analysis (PE signature, packer entropy, FLOSS strings) |
| `ransomwall_trap_layer.py` | Layer 2: Honey files, watchdog, behavior detector |
| `ransomwall_dynamic_layer.py` | Layer 3: IRP tracking (read/write/rename/delete/dir_query, fingerprint mismatch) |
| `backup_layer.py` | Layer 4: Per-PID file backup / restore / cleanup |
| `ml_layer.py` | Layer 5: GBT classifier with 3-bucket sliding-window consensus |
| `generate_dataset.py` | Full feature extraction pipeline from real samples |
| `augment_dataset.py` | Synthetic dataset generation (no real malware needed) |
| `train_model.py` | GradientBoostingClassifier training + evaluation |
| `test_backup_layer.py` | 27-test unit suite for BackupLayer (all 5 bug fixes verified) |
| `ransom.py` | Ransomware simulator (XOR-encrypts honey_files/ for integration testing) |
| `feature_collector.py` | Standalone feature score helper |

---

## Quick Start (3 steps)

### Step 1 — Install dependencies
```bash
pip install watchdog psutil scikit-learn numpy
# Optional (Windows PE analysis only):
pip install pefile
```

### Step 2 — Generate dataset and train model
```bash
# Generate 300 synthetic samples per class (600 total)
python augment_dataset.py --n 300

# Train GradientBoostingClassifier
python train_model.py
```

### Step 3 — Run the full pipeline demo
```bash
python main.py --demo
```

---

## All run modes

```bash
# Full pipeline simulation (no real malware needed)
python main.py --demo

# Real-time continuous monitoring (Ctrl+C to stop)
python main.py --monitor

# Static analysis on a PE binary, then monitor
python main.py --static suspect.exe --monitor

# Run all 27 backup layer unit tests
python test_backup_layer.py -v

# Individual layer demos
python ransomwall_dynamic_layer.py
python ransomwall_trap_layer.py
python stat_real.py <path_to_exe>

# Dataset from real VirusShare samples (if you have a ZIP)
python generate_dataset.py --virusshare VirusShare.zip --benign ./clean_samples/
```

---

## Architecture

```
[EXE]
  │
  ▼  (pre-execution)
Layer 1: Static Analysis       stat_real.py
  │  PE signature, packer entropy, FLOSS suspicious strings
  │
  ▼  (during execution — concurrent)
Layer 2: Trap Layer            ransomwall_trap_layer.py
  │  Honey files watchdog + behavior detector (crypto APIs, bcdedit, vssadmin)
  │
Layer 3: Dynamic Layer         ransomwall_dynamic_layer.py
  │  IRP counts per bucket: read/write/rename/delete/dir_query
  │  Fingerprint mismatch + entropy spike detection
  │
  ▼  (combined score ≥ 6 → suspicious)
Layer 4: Backup Layer          backup_layer.py
  │  Back up files modified by suspicious PID
  │
  ▼  (sliding window: 3 × 1-second buckets must agree)
Layer 5: ML Engine             ml_layer.py
  │  GradientBoostingClassifier → Ransomware | Benign
  │
  ├── Ransomware → Kill process + Restore backed-up files
  └── Benign     → Delete backup copies
```

---

## Paper targets vs achieved results

| Metric | Paper target | Achieved |
|---|---|---|
| Recall / TPR | 98.25% | 100% (synthetic data) |
| Sliding window | 3 consecutive buckets | ✓ implemented |
| Feature count | 18 | ✓ 18 features |
| Classifier | Gradient Tree Boosting | ✓ GradientBoostingClassifier |
| Backup restore | On ransomware verdict | ✓ |
| Honey file types | Write/Rename/Delete | ✓ all 3 |

