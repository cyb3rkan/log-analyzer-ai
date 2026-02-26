"""Anomaly detection using Isolation Forest."""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import List

import numpy as np

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Isolation Forest anomaly detector for log traffic."""

    def __init__(self, contamination: float = 0.1, n_estimators: int = 100) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self._model = None
        self._scaler = None
        self._is_trained = False

    @staticmethod
    def extract_features(entries: list) -> np.ndarray:
        METHOD_MAP = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "HEAD": 4}
        features = []
        for e in entries:
            path = e.path or ""
            hour = e.timestamp.hour if e.timestamp else 12
            features.append([
                e.status_code, e.bytes_sent, len(path),
                1 if "?" in path else 0,
                METHOD_MAP.get(e.method, 5), hour,
                sum(1 for c in path if c in "'\";|<>{}()[]"),
            ])
        return np.array(features, dtype=np.float64)

    def train(self, entries: list) -> dict:
        if len(entries) < 10:
            return {"status": "error", "message": "Need at least 10 entries"}

        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self._scaler = StandardScaler()
        self._model = IsolationForest(
            contamination=self.contamination, n_estimators=self.n_estimators,
            random_state=42, n_jobs=-1,
        )
        features = self.extract_features(entries)
        scaled = self._scaler.fit_transform(features)
        self._model.fit(scaled)
        self._is_trained = True

        preds = self._model.predict(scaled)
        n_anom = int(np.sum(preds == -1))
        logger.info(f"Trained on {len(entries)} entries, {n_anom} anomalies in training data")
        return {"status": "success", "training_samples": len(entries), "anomalies_in_training": n_anom}

    def predict(self, entries: list) -> List[dict]:
        if not self._is_trained:
            return []
        features = self.extract_features(entries)
        scaled = self._scaler.transform(features)
        scores = self._model.decision_function(scaled)
        preds = self._model.predict(scaled)
        return [
            {"entry": e, "anomaly_score": float(scores[i]), "is_anomaly": bool(preds[i] == -1),
             "ip": e.ip, "path": e.path}
            for i, e in enumerate(entries)
        ]

    def save_model(self, filepath: str) -> None:
        if not self._is_trained:
            raise ValueError("Model not trained")
        with open(filepath, "wb") as f:
            pickle.dump({"model": self._model, "scaler": self._scaler}, f)

    def load_model(self, filepath: str) -> None:
        if not Path(filepath).exists():
            raise FileNotFoundError(f"Model not found: {filepath}")
        with open(filepath, "rb") as f:
            data = pickle.load(f)
        self._model, self._scaler = data["model"], data["scaler"]
        self._is_trained = True
