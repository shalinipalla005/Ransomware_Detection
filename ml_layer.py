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

"""
RansomWall: Machine Learning Engine (Paper-strict implementation)
"""

import math
import pickle
import logging
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("RansomWall.MLLayer")

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    log.debug("[MLLayer] scikit-learn not found; using rule-based classifier.")

MODEL_PATH  = "rw_model.pkl"
SCALER_PATH = "rw_scaler.pkl"

FEATURE_NAMES = [
    "honey_file_write",
    "honey_file_rename",
    "honey_file_delete",
    "honey_dir_modified",
    "crypto_api_usage",
    "safe_mode_disabled",
    "vss_deletion",
    "registry_persistence",
    "entropy_spike",
    "file_read",
    "file_write",
    "file_rename",
    "file_delete",
    "dir_query",
    "fingerprint_mismatch",
    "invalid_signature",
    "packed_binary",
    "suspicious_strings",
]

WINDOW_SIZE = 3
CONSENSUS_THRESHOLD = 3


class RuleBasedClassifier:
    WEIGHTS = {
        "honey_file_write":       3.0,
        "honey_file_rename":      3.0,
        "honey_file_delete":      2.5,
        "honey_dir_modified":     1.5,
        "crypto_api_usage":       1.5,
        "safe_mode_disabled":     4.0,
        "vss_deletion":           4.0,
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
        return 1 if self.predict_score(features) >= self.RANSOMWARE_THRESHOLD else 0


class MLModel:
    def __init__(self, model_path: str = MODEL_PATH, scaler_path: str = SCALER_PATH):
        self.model_path  = model_path
        self.scaler_path = scaler_path

        self._history: Dict[int, deque] = {}
        self._scores:  Dict[int, deque] = {}
        self._feature_history: Dict[int, deque] = {}

        self._model      = None
        self._scaler     = None
        self._rule_based = RuleBasedClassifier()

        self._load_model_if_available()

        mode = "GradientBoostingClassifier" if self._model else "RuleBasedClassifier"
        log.info(f"[MLModel] Initialized with {mode}")
        print(f"[ML] Model loaded ({mode})")

    def predict(self, pid: int, features: dict) -> str:
        if pid not in self._history:
            self._history[pid]         = deque(maxlen=WINDOW_SIZE)
            self._scores[pid]          = deque(maxlen=WINDOW_SIZE)
            self._feature_history[pid] = deque(maxlen=WINDOW_SIZE)

        self._feature_history[pid].append(features)

        if len(self._feature_history[pid]) < WINDOW_SIZE:
            log.debug(
                f"[MLModel] PID={pid} feature-history filling "
                f"({len(self._feature_history[pid])}/{WINDOW_SIZE}) — "
                f"deferring classification."
            )
            return "Suspicious"

        smoothed_features: dict = {
            name: sum(bucket.get(name, 0) for bucket in self._feature_history[pid])
                  / WINDOW_SIZE
            for name in FEATURE_NAMES
        }

        if self._model and SKLEARN_AVAILABLE:
            decision, score = self._sklearn_predict(smoothed_features)
        else:
            score    = self._rule_based.predict_score(smoothed_features)
            decision = 1 if score >= self._rule_based.RANSOMWARE_THRESHOLD else 0

        self._history[pid].append(decision)
        self._scores[pid].append(round(score, 2))

        log.debug(
            f"[MLModel] PID={pid} bucket={'RANSOM' if decision else 'BENIGN'} "
            f"score={score:.2f} window={list(self._history[pid])}"
        )

        window = self._history[pid]
        if len(window) == WINDOW_SIZE:
            total = sum(window)
            if total == WINDOW_SIZE:
                log.warning(
                    f"[MLModel] RANSOMWARE CONFIRMED PID={pid} "
                    f"window={list(window)} scores={list(self._scores[pid])}"
                )
                return "Ransomware"
            if total == 0:
                log.info(
                    f"[MLModel] BENIGN CONFIRMED PID={pid} "
                    f"window={list(window)}"
                )
                return "Benign"

        return "Suspicious"

    def _sklearn_predict(self, features: dict) -> Tuple[int, float]:
        vec = self._vectorize(features)

        if self._scaler is not None:
            vec_scaled = self._scaler.transform([vec])
        else:
            vec_scaled = np.array([vec])

        decision = int(self._model.predict(vec_scaled)[0])
        proba    = self._model.predict_proba(vec_scaled)[0]
        score    = float(proba[1]) * 10.0

        return decision, score

    def train(self, X: List[dict], y: List[int]):
        if not SKLEARN_AVAILABLE:
            log.error("[MLModel] scikit-learn not available; cannot train.")
            return

        X_mat = np.array([self._vectorize(f) for f in X], dtype=float)
        y_arr = np.array(y, dtype=int)

        scaler   = StandardScaler()
        X_scaled = scaler.fit_transform(X_mat)

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
            f"Samples={len(y_arr)} Ransomware={n_ransom} "
            f"Benign={len(y_arr) - n_ransom}"
        )
        self.save()

    def save(self):
        if self._model is None:
            log.warning("[MLModel] No trained model to save.")
            return
        with open(self.model_path,  "wb") as f:
            pickle.dump(self._model,  f)
        with open(self.scaler_path, "wb") as f:
            pickle.dump(self._scaler, f)
        log.info(f"[MLModel] Saved -> {self.model_path}, {self.scaler_path}")

    def load(self):
        self._load_model_if_available()

    def _load_model_if_available(self):
        if not (SKLEARN_AVAILABLE
                and Path(self.model_path).exists()
                and Path(self.scaler_path).exists()):
            return

        try:
            with open(self.model_path,  "rb") as f:
                self._model  = pickle.load(f)
            with open(self.scaler_path, "rb") as f:
                self._scaler = pickle.load(f)
            log.info(f"[MLModel] Loaded trained GBT model from {self.model_path}")
        except Exception as exc:
            log.warning(
                f"[MLModel] Could not load model ({exc}); "
                f"using RuleBasedClassifier."
            )
            self._model  = None
            self._scaler = None

    @staticmethod
    def _vectorize(features: dict) -> List[float]:
        return [float(features.get(name, 0)) for name in FEATURE_NAMES]

    def reset_pid(self, pid: int):
        self._history.pop(pid, None)
        self._scores.pop(pid,  None)
        self._feature_history.pop(pid, None)
        log.debug(f"[MLModel] Sliding-window reset for PID={pid}")

    def window_state(self, pid: int) -> dict:
        return {
            "pid":             pid,
            "window":          list(self._history.get(pid, [])),
            "scores":          list(self._scores.get(pid,  [])),
            "size":            WINDOW_SIZE,
            "full":            len(self._history.get(pid, [])) == WINDOW_SIZE,
            "backend":         "GBT" if self._model else "RuleBased",
            "feature_buf_len": len(self._feature_history.get(pid, [])),
        }

    def is_trained(self) -> bool:
        return self._model is not None