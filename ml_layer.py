"""
RansomWall: Machine Learning Engine
=====================================
Based on: "RansomWall: A Layered Defense System against Cryptographic
Ransomware Attacks using Machine Learning" (COMSNETS 2018)
IIT Delhi - Shaukat & Ribeiro

Paper §III-B-5 (Machine Learning Engine):
  • Binary classification: Ransomware | Benign
  • Supervised learning (Gradient Tree Boosting gives best results: 98.25% TPR)
  • Feature input: merged Static + Dynamic + Trap layer features
  • Moving-average sliding window (Bucket = 1 second, window = 3 intervals)
  • Final verdict: same classification for 3 CONTIGUOUS intervals -> confirmed

Paper §IV-C (ML Implementation):
  "The Machine Learning Layer outputs a suspicious process as Ransomware
  or Benign if the classification result is same for 3 contiguous
  time-intervals, to reduce false detections."
"""

import math
import pickle
import logging
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("RansomWall.MLLayer")

# ── Optional scikit-learn ─────────────────────────────────────────────────────
try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    log.debug("[MLLayer] scikit-learn not found; using rule-based classifier.")

# ── Model persistence paths ───────────────────────────────────────────────────
MODEL_PATH  = "rw_model.pkl"
SCALER_PATH = "rw_scaler.pkl"

# ── Canonical feature order (paper compact feature set) ──────────────────────
# Must match training order exactly.
FEATURE_NAMES = [
    # Trap Layer features (paper §III-D-2)
    "honey_file_write",
    "honey_file_rename",
    "honey_file_delete",
    "honey_dir_modified",
    "crypto_api_usage",
    "safe_mode_disabled",
    "vss_deletion",
    "registry_persistence",
    "entropy_spike",
    # Dynamic Layer features (paper §III-D-3)
    "file_read",
    "file_write",
    "file_rename",
    "file_delete",
    "dir_query",
    "fingerprint_mismatch",
    # Static Layer features (paper §III-D-1)
    "invalid_signature",
    "packed_binary",
    "suspicious_strings",
]

# ── Sliding window size (paper §IV-C: 3 contiguous intervals) ────────────────
WINDOW_SIZE = 3

# ── Minimum agreement in window for confirmed verdict ────────────────────────
# 3/3 = strict consensus (all three buckets must agree)
CONSENSUS_THRESHOLD = 3


# ════════════════════════════════════════════════════════════════════════════ #
class RuleBasedClassifier:
    """
    Fallback rule-based classifier used when no trained model is available.
    Weights derived from paper §IV-A feature importance rankings.
    """

    WEIGHTS = {
        "honey_file_write":       3.0,
        "honey_file_rename":      3.0,
        "honey_file_delete":      2.5,
        "honey_dir_modified":     1.5,
        "crypto_api_usage":       1.5,
        "safe_mode_disabled":     4.0,   # near-certain ransomware indicator
        "vss_deletion":           4.0,   # near-certain ransomware indicator
        "registry_persistence":   1.0,
        "entropy_spike":          2.0,
        "file_rename":            2.0,
        "file_write":             1.5,
        "file_delete":            1.5,
        "file_read":              0.5,
        "dir_query":              0.5,
        "fingerprint_mismatch":   2.5,
        "invalid_signature":      1.5,
        "packed_binary":          1.0,
        "suspicious_strings":     1.5,
    }

    # Score threshold derived from paper §IV-A: "6 or more feature indicators"
    RANSOMWARE_THRESHOLD = 5.0

    def predict_score(self, features: dict) -> float:
        score = 0.0
        for feat, weight in self.WEIGHTS.items():
            val = features.get(feat, 0)
            if val > 0:
                contribution = min(weight * (1 + math.log1p(val)), weight * 3)
                score += contribution
        return score

    def predict(self, features: dict) -> int:
        """Returns 1 = Ransomware, 0 = Benign."""
        return 1 if self.predict_score(features) >= self.RANSOMWARE_THRESHOLD else 0


# ════════════════════════════════════════════════════════════════════════════ #
class MLModel:
    """
    RansomWall Machine Learning Engine (paper §III-B-5).

    Wraps either:
      (a) A trained GradientBoostingClassifier loaded from rw_model.pkl, or
      (b) The RuleBasedClassifier fallback when no trained model is present.

    Sliding-window consensus (paper §IV-C):
      - Collects binary predictions across 1-second buckets per PID.
      - Requires WINDOW_SIZE (3) consecutive identical predictions to confirm.
      - Returns "Ransomware", "Benign", or "Suspicious" (window not yet full
        or no consensus).

    Public API:
      predict(pid, features) -> "Ransomware" | "Benign" | "Suspicious"
      train(X, y)            -> fit GBT model from labeled feature dicts
      save() / load()        -> persist / restore trained model
      reset_pid(pid)         -> clear sliding-window state for a PID
    """

    def __init__(self, model_path: str = MODEL_PATH, scaler_path: str = SCALER_PATH):
        self.model_path  = model_path
        self.scaler_path = scaler_path

        # Paper §IV-C: deque of last WINDOW_SIZE bucket decisions per PID.
        # Each entry is a binary int: 1 = Ransomware, 0 = Benign.
        self._history: Dict[int, deque] = {}
        self._scores:  Dict[int, deque] = {}

        self._model      = None
        self._scaler     = None
        self._rule_based = RuleBasedClassifier()

        self._load_model_if_available()

        mode = "GradientBoostingClassifier" if self._model else "RuleBasedClassifier"
        log.info(f"[MLModel] Initialized with {mode}")
        print(f"[ML] Model loaded ({mode})")

    # ── Prediction ────────────────────────────────────────────────────────────

    def predict(self, pid: int, features: dict) -> str:
        """
        Paper §IV-C workflow:
          1. Vectorize features using canonical FEATURE_NAMES order.
          2. Compute binary prediction for this 1-second bucket via GBT or
             RuleBasedClassifier fallback.
          3. Append decision to per-PID sliding window (deque maxlen=3).
          4. If window is full AND all WINDOW_SIZE entries agree ->
             return confirmed verdict ("Ransomware" or "Benign").
          5. Otherwise -> "Suspicious" (window filling or mixed signals).

        Args:
          pid      : Process ID being monitored.
          features : 18-dim feature dict keyed by FEATURE_NAMES elements.
                     Missing keys default to 0.  Extra keys are ignored.

        Returns:
          "Ransomware" — confirmed across WINDOW_SIZE consecutive buckets
          "Benign"     — confirmed benign  across WINDOW_SIZE buckets
          "Suspicious" — window not yet full or no consensus (accumulating)
        """
        # Initialise per-PID sliding window on first encounter
        if pid not in self._history:
            self._history[pid] = deque(maxlen=WINDOW_SIZE)
            self._scores[pid]  = deque(maxlen=WINDOW_SIZE)

        # ── Single-bucket prediction ──────────────────────────────────────────
        if self._model and SKLEARN_AVAILABLE:
            decision, score = self._sklearn_predict(features)
        else:
            score    = self._rule_based.predict_score(features)
            decision = self._rule_based.predict(features)

        self._history[pid].append(decision)
        self._scores[pid].append(round(score, 2))

        log.debug(
            f"[MLModel] PID={pid}  bucket={'RANSOM' if decision else 'BENIGN'}  "
            f"score={score:.2f}  window={list(self._history[pid])}"
        )

        # ── Sliding-window consensus (paper §IV-C) ────────────────────────────
        window = self._history[pid]
        if len(window) == WINDOW_SIZE:
            total = sum(window)
            if total == WINDOW_SIZE:           # all 3 buckets = Ransomware
                log.warning(
                    f"[MLModel] RANSOMWARE CONFIRMED  PID={pid}  "
                    f"window={list(window)}  scores={list(self._scores[pid])}"
                )
                return "Ransomware"
            if total == 0:                     # all 3 buckets = Benign
                log.info(
                    f"[MLModel] BENIGN CONFIRMED  PID={pid}  "
                    f"window={list(window)}"
                )
                return "Benign"

        # Window not yet full or mixed signals -> accumulating evidence
        return "Suspicious"

    # ── Sklearn inference ─────────────────────────────────────────────────────

    def _sklearn_predict(self, features: dict) -> Tuple[int, float]:
        """
        Vectorize features via FEATURE_NAMES order, scale, then run GBT model.

        Returns:
          (decision, score)
            decision : int  — 1 = Ransomware, 0 = Benign
            score    : float — ransomware probability scaled to [0, 10]
        """
        vec = self._vectorize(features)

        if self._scaler is not None:
            vec_scaled = self._scaler.transform([vec])
        else:
            vec_scaled = np.array([vec])

        decision  = int(self._model.predict(vec_scaled)[0])
        proba     = self._model.predict_proba(vec_scaled)[0]
        # proba[1] = P(Ransomware).  Scale to [0,10] for human-readable logs.
        score     = float(proba[1]) * 10.0

        return decision, score

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, X: List[dict], y: List[int]):
        """
        Offline training (paper §IV-C / §V-E).

        Args:
          X : list of feature dicts (each keyed by FEATURE_NAMES elements)
          y : list of int labels — 1 = Ransomware, 0 = Benign

        Fits a GradientBoostingClassifier with StandardScaler preprocessing,
        then saves model + scaler to disk.
        """
        if not SKLEARN_AVAILABLE:
            log.error("[MLModel] scikit-learn not available; cannot train.")
            return

        X_mat = np.array([self._vectorize(f) for f in X], dtype=float)
        y_arr = np.array(y, dtype=int)

        # Fit scaler on training data (paper uses raw feature values)
        scaler   = StandardScaler()
        X_scaled = scaler.fit_transform(X_mat)

        # Paper §V-E: Gradient Tree Boosting gives best result (98.25% TPR)
        model = GradientBoostingClassifier(
            n_estimators  = 200,
            learning_rate = 0.1,
            max_depth     = 4,
            subsample     = 0.8,
            random_state  = 42,
        )
        model.fit(X_scaled, y_arr)

        self._model  = model
        self._scaler = scaler

        n_ransom = int(y_arr.sum())
        log.info(
            f"[MLModel] Training complete. "
            f"Samples={len(y_arr)}  Ransomware={n_ransom}  "
            f"Benign={len(y_arr) - n_ransom}"
        )
        self.save()

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self):
        """Persist trained GBT model and StandardScaler to disk."""
        if self._model is None:
            log.warning("[MLModel] No trained model to save.")
            return
        with open(self.model_path,  "wb") as f:
            pickle.dump(self._model,  f)
        with open(self.scaler_path, "wb") as f:
            pickle.dump(self._scaler, f)
        log.info(f"[MLModel] Saved -> {self.model_path}, {self.scaler_path}")

    def load(self):
        """
        Explicitly reload model + scaler from disk.
        Useful after external retraining (e.g., by train_model.py).
        """
        self._load_model_if_available()

    def _load_model_if_available(self):
        """
        Load persisted GBT model + StandardScaler if both PKL files exist and
        scikit-learn is available.  Silently falls back to RuleBasedClassifier.
        """
        if not (SKLEARN_AVAILABLE
                and Path(self.model_path).exists()
                and Path(self.scaler_path).exists()):
            return

        try:
            with open(self.model_path,  "rb") as f:
                self._model  = pickle.load(f)
            with open(self.scaler_path, "rb") as f:
                self._scaler = pickle.load(f)
            log.info(
                f"[MLModel] Loaded trained GBT model from {self.model_path}"
            )
        except Exception as exc:
            log.warning(
                f"[MLModel] Could not load model ({exc}); "
                f"using RuleBasedClassifier."
            )
            self._model  = None
            self._scaler = None

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _vectorize(features: dict) -> List[float]:
        """
        Convert a feature dict to an ordered numeric list aligned with
        FEATURE_NAMES.  Missing keys default to 0.  Extra keys are ignored.
        This guarantees the same column order used during training.
        """
        return [float(features.get(name, 0)) for name in FEATURE_NAMES]

    def reset_pid(self, pid: int):
        """
        Clear sliding-window state for `pid` after a final classification.
        Called by main.py's _on_ransomware() and _on_benign() handlers.
        """
        self._history.pop(pid, None)
        self._scores.pop(pid,  None)
        log.debug(f"[MLModel] Sliding-window reset for PID={pid}")

    # ── Introspection helpers (useful for debugging / reporting) ──────────────

    def window_state(self, pid: int) -> dict:
        """
        Return the current sliding-window state for a PID.
        Useful for unit tests and monitoring dashboards.
        """
        return {
            "pid":     pid,
            "window":  list(self._history.get(pid, [])),
            "scores":  list(self._scores.get(pid,  [])),
            "size":    WINDOW_SIZE,
            "full":    len(self._history.get(pid, [])) == WINDOW_SIZE,
            "backend": "GBT" if self._model else "RuleBased",
        }

    def is_trained(self) -> bool:
        """True if a GBT model is loaded; False if using rule-based fallback."""
        return self._model is not None
