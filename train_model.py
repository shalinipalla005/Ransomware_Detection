"""
RansomWall: Model Training Pipeline
=====================================
Paper §III-B-5 / §IV-C / §V-E  —  COMSNETS 2018

Usage:
  python train_model.py [--dataset dataset.csv]
                        [--model   rw_model.pkl]
                        [--scaler  rw_scaler.pkl]
                        [--test-ratio 0.2]
                        [--seed 42]

Paper §V-E result target:
  Gradient Tree Boosting  →  98.25% TPR
"""

import sys
import csv
import json
import pickle
import logging
import argparse
import warnings
from pathlib import Path
from typing import List, Tuple

import numpy as np

try:
    from sklearn.ensemble         import GradientBoostingClassifier
    from sklearn.preprocessing    import StandardScaler
    from sklearn.model_selection  import train_test_split, StratifiedKFold, cross_val_score
    from sklearn.metrics          import (
        accuracy_score, precision_score, recall_score,
        f1_score, confusion_matrix, classification_report,
    )
except ImportError:
    sys.exit(
        "[ERROR] scikit-learn is required: pip install scikit-learn"
    )

from ml_layer import FEATURE_NAMES

log = logging.getLogger("RansomWall.Train")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  |  %(message)s",
    datefmt="%H:%M:%S",
)

warnings.filterwarnings("ignore")

# ── GBT hyperparameters (paper §V-E: best configuration) ─────────────────────
GBT_PARAMS = dict(
    n_estimators  = 200,
    learning_rate = 0.1,
    max_depth     = 4,
    subsample     = 0.8,
    random_state  = 42,
)


# ════════════════════════════════════════════════════════════════════════════ #
def load_dataset(csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load dataset.csv and return (X, y).
    Columns must include all FEATURE_NAMES plus 'label'.
    Extras (sha256, filename) are silently ignored.
    """
    log.info(f"[Load] Reading {csv_path}")
    X_rows: List[List[float]] = []
    y_list: List[int]         = []
    skipped = 0

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            sys.exit("[ERROR] CSV has no header row.")

        missing = [n for n in FEATURE_NAMES if n not in reader.fieldnames]
        if missing:
            sys.exit(f"[ERROR] CSV missing columns: {missing}")
        if "label" not in reader.fieldnames:
            sys.exit("[ERROR] CSV missing 'label' column.")

        for row in reader:
            try:
                vec   = [float(row[name]) for name in FEATURE_NAMES]
                label = int(row["label"])
                if label not in (0, 1):
                    skipped += 1
                    continue
                X_rows.append(vec)
                y_list.append(label)
            except (ValueError, KeyError):
                skipped += 1

    if skipped:
        log.warning(f"[Load] Skipped {skipped} malformed rows.")

    X = np.array(X_rows, dtype=float)
    y = np.array(y_list, dtype=int)

    n_ransom = int(y.sum())
    n_benign = len(y) - n_ransom
    log.info(
        f"[Load] {len(y)} samples loaded  "
        f"(ransomware={n_ransom}, benign={n_benign})"
    )
    if len(y) == 0:
        sys.exit("[ERROR] Dataset is empty.")
    return X, y


# ════════════════════════════════════════════════════════════════════════════ #
def train_and_evaluate(
    X: np.ndarray,
    y: np.ndarray,
    test_ratio: float,
    model_path: str,
    scaler_path: str,
    seed: int,
) -> dict:
    """
    Full training pipeline:
      1. Stratified train/test split
      2. StandardScaler fit on train, transform both
      3. Fit GradientBoostingClassifier  (paper §V-E)
      4. Evaluate on held-out test set
      5. 5-fold cross-validation on full dataset
      6. Persist model + scaler
    """
    # ── 1. Split ──────────────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size     = test_ratio,
        stratify      = y,
        random_state  = seed,
    )
    log.info(
        f"[Split] Train={len(y_train)}  Test={len(y_test)}  "
        f"(test_ratio={test_ratio})"
    )

    # ── 2. Scaling ────────────────────────────────────────────────────────────
    scaler   = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── 3. Train ──────────────────────────────────────────────────────────────
    log.info("[Train] Fitting GradientBoostingClassifier ...")
    model = GradientBoostingClassifier(**GBT_PARAMS)
    model.fit(X_train_s, y_train)
    log.info("[Train] Fitting complete.")

    # ── 4. Held-out evaluation ────────────────────────────────────────────────
    y_pred = model.predict(X_test_s)

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)   # = TPR
    f1        = f1_score(y_test, y_pred, zero_division=0)
    cm        = confusion_matrix(y_test, y_pred)

    # ── 5. Cross-validation (5-fold stratified) ───────────────────────────────
    X_full_s = scaler.transform(X)   # scaler already fitted on train
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    cv_scores = cross_val_score(model, X_full_s, y, cv=cv, scoring="recall")

    # ── 6. Persist ────────────────────────────────────────────────────────────
    with open(model_path,  "wb") as f: pickle.dump(model,  f)
    with open(scaler_path, "wb") as f: pickle.dump(scaler, f)
    log.info(f"[Save] Model  -> {model_path}")
    log.info(f"[Save] Scaler -> {scaler_path}")

    # ── Feature importance ────────────────────────────────────────────────────
    importances = dict(zip(FEATURE_NAMES, model.feature_importances_))
    top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)

    results = {
        "samples_total":      len(y),
        "samples_ransomware": int(y.sum()),
        "samples_benign":     int(len(y) - y.sum()),
        "train_samples":      len(y_train),
        "test_samples":       len(y_test),
        "accuracy":           round(accuracy,  4),
        "precision":          round(precision, 4),
        "recall_tpr":         round(recall,    4),
        "f1_score":           round(f1,        4),
        "cv_recall_mean":     round(float(cv_scores.mean()), 4),
        "cv_recall_std":      round(float(cv_scores.std()),  4),
        "confusion_matrix":   cm.tolist(),
        "top_features":       top_features[:5],
    }
    return results


# ════════════════════════════════════════════════════════════════════════════ #
def print_results(r: dict):
    print("\n" + "=" * 60)
    print("  RansomWall — Training Results  (paper §V-E target: TPR 98.25%)")
    print("=" * 60)
    print(f"  Dataset       : {r['samples_total']} samples  "
          f"(ransomware={r['samples_ransomware']}, benign={r['samples_benign']})")
    print(f"  Train / Test  : {r['train_samples']} / {r['test_samples']}")
    print()
    print(f"  Accuracy      : {r['accuracy']  * 100:.2f}%")
    print(f"  Precision     : {r['precision'] * 100:.2f}%")
    print(f"  Recall (TPR)  : {r['recall_tpr']* 100:.2f}%   ← paper target: 98.25%")
    print(f"  F1 Score      : {r['f1_score']  * 100:.2f}%")
    print()
    print(f"  5-fold CV TPR : {r['cv_recall_mean']*100:.2f}% "
          f"(±{r['cv_recall_std']*100:.2f}%)")
    print()
    cm = r["confusion_matrix"]
    print("  Confusion Matrix:")
    print(f"            Predicted")
    print(f"              Benign  Ransom")
    print(f"  Actual Benign  {cm[0][0]:>5}   {cm[0][1]:>5}")
    print(f"         Ransom  {cm[1][0]:>5}   {cm[1][1]:>5}")
    print()
    print("  Top 5 Features by Importance:")
    for feat, imp in r["top_features"]:
        bar = "█" * int(imp * 40)
        print(f"    {feat:<25}  {imp:.4f}  {bar}")
    print("=" * 60 + "\n")


# ════════════════════════════════════════════════════════════════════════════ #
def _parse_args():
    p = argparse.ArgumentParser(
        description="RansomWall — Train GradientBoostingClassifier (paper §V-E)",
    )
    p.add_argument("--dataset",    default="dataset.csv",
                   help="Path to dataset CSV  [default: dataset.csv]")
    p.add_argument("--model",      default="rw_model.pkl",
                   help="Output model path    [default: rw_model.pkl]")
    p.add_argument("--scaler",     default="rw_scaler.pkl",
                   help="Output scaler path   [default: rw_scaler.pkl]")
    p.add_argument("--test-ratio", type=float, default=0.20,
                   help="Held-out test ratio  [default: 0.20]")
    p.add_argument("--seed",       type=int,   default=42,
                   help="Random seed          [default: 42]")
    return p.parse_args()


# ════════════════════════════════════════════════════════════════════════════ #
if __name__ == "__main__":
    args = _parse_args()

    if not Path(args.dataset).exists():
        sys.exit(
            f"[ERROR] Dataset not found: {args.dataset}\n"
            f"        Run  python generate_dataset.py --virusshare <zip>  first."
        )

    X, y = load_dataset(args.dataset)
    results = train_and_evaluate(
        X, y,
        test_ratio  = args.test_ratio,
        model_path  = args.model,
        scaler_path = args.scaler,
        seed        = args.seed,
    )
    print_results(results)

    # Write JSON summary alongside model
    summary_path = Path(args.model).with_suffix(".training_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log.info(f"[Save] Training summary -> {summary_path}")
