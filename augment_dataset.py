import csv
import random
import argparse
from pathlib import Path
from ml_layer import FEATURE_NAMES

CSV_COLUMNS = FEATURE_NAMES + ["label", "sha256", "filename"]

random.seed(42)


def _ri(lo, hi):
    """Random int in [lo, hi]."""
    return random.randint(lo, hi)


def _rb(p):
    """Bernoulli: 1 with probability p."""
    return 1 if random.random() < p else 0


def _rn(mu, sigma, lo=0.0, hi=None):
    """Clipped normal."""
    v = random.gauss(mu, sigma)
    v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return round(v, 1)

def _ransomware_row(idx: int) -> dict:
    row = {
        "honey_file_write":       _rb(0.85),
        "honey_file_rename":      _rb(0.80),
        "honey_file_delete":      _rb(0.75),
        "honey_dir_modified":     _rb(0.70),
        "crypto_api_usage":       _rb(0.90),
        "safe_mode_disabled":     _rb(0.60),
        "vss_deletion":           _rb(0.65),
        "registry_persistence":   _rb(0.55),
        "entropy_spike":          _rb(0.85),
        "file_read":              _rn(22, 6,  lo=5),
        "file_write":             _rn(18, 5,  lo=5),
        "file_rename":            _rn(14, 4,  lo=3),
        "file_delete":            _rn(9,  3,  lo=2),
        "dir_query":              _rn(16, 5,  lo=3),
        "fingerprint_mismatch":   _rb(0.70),
        "invalid_signature":      _rb(0.80),
        "packed_binary":          _rb(0.65),
        "suspicious_strings":     _ri(1, 5),
        "label":    1,
        "sha256":   f"synth_ransom_{idx:04d}",
        "filename": f"ransom_synth_{idx:04d}.exe",
    }
    return row


def _benign_row(idx: int) -> dict:
    row = {
        "honey_file_write":       _rb(0.02),
        "honey_file_rename":      _rb(0.01),
        "honey_file_delete":      _rb(0.01),
        "honey_dir_modified":     _rb(0.05),
        "crypto_api_usage":       _rb(0.15),   
        "safe_mode_disabled":     0,
        "vss_deletion":           0,
        "registry_persistence":   _rb(0.08),   
        "entropy_spike":          _rb(0.05),
         "file_read":              _rn(6,  3,  lo=0, hi=20),
        "file_write":             _rn(2,  1,  lo=0, hi=8),
        "file_rename":            _rn(0.3, 0.5, lo=0, hi=3),
        "file_delete":            _rn(0.2, 0.4, lo=0, hi=2),
        "dir_query":              _rn(4,  2,  lo=0, hi=12),
        "fingerprint_mismatch":   _rb(0.05),
        "invalid_signature":      _rb(0.10),
        "packed_binary":          _rb(0.08),
        "suspicious_strings":     _ri(0, 1),
        "label":    0,
        "sha256":   f"synth_benign_{idx:04d}",
        "filename": f"benign_synth_{idx:04d}.exe",
    }
    return row


def augment(input_csv: str, output_csv: str, n: int):
    existing = []
    if Path(input_csv).exists():
        with open(input_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing.append(row)
        print(f"[Augment] Loaded {len(existing)} existing rows from {input_csv}")
    else:
        print(f"[Augment] {input_csv} not found; creating fresh dataset.")

    synth_ransom = [_ransomware_row(i) for i in range(n)]
    synth_benign = [_benign_row(i)    for i in range(n)]
    new_rows = synth_ransom + synth_benign
    random.shuffle(new_rows)

    all_rows = existing + new_rows

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in all_rows:
            writer.writerow({col: row.get(col, 0) for col in CSV_COLUMNS})

    n_ransom = sum(1 for r in all_rows if str(r.get("label")) == "1")
    n_benign = sum(1 for r in all_rows if str(r.get("label")) == "0")
    print(f"[Augment] Written {len(all_rows)} rows -> {output_csv}")
    print(f"          Ransomware={n_ransom}  Benign={n_benign}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Augment RansomWall dataset with synthetic samples")
    p.add_argument("--input",  default="dataset.csv",
                   help="Existing dataset CSV to augment  [default: dataset.csv]")
    p.add_argument("--output", default="dataset.csv",
                   help="Output CSV path  [default: dataset.csv (overwrites)]")
    p.add_argument("--n",      type=int, default=200,
                   help="Synthetic samples PER CLASS to generate  [default: 200]")
    args = p.parse_args()
    augment(args.input, args.output, args.n)
