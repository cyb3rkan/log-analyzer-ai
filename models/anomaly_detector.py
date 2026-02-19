"""
Anomaly Detector - ML Tabanlı Anomali Tespiti
Isolation Forest algoritması kullanarak anormal trafik kalıplarını tespit eder.
"""
import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# scikit-learn opsiyonel bağımlılık
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn bulunamadı. ML tabanlı anomali tespiti devre dışı.")


def _check_sklearn() -> None:
    if not _SKLEARN_AVAILABLE:
        raise ImportError(
            "scikit-learn gerekli: pip install scikit-learn"
        )


class RequestFeatureExtractor:
    """
    Log entry'lerinden ML için sayısal özellikler çıkarır.
    """

    # HTTP metot sıralaması
    METHOD_MAP = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "HEAD": 4, "OPTIONS": 5, "PATCH": 6}

    def extract(self, entry) -> list[float]:
        """
        Bir log entry'sinden feature vektörü çıkarır.

        Args:
            entry: LogEntry nesnesi

        Returns:
            Float listesi (feature vektörü)
        """
        features = [
            self._method_code(entry.method),
            float(entry.status_code),
            float(entry.bytes_sent),
            float(len(entry.path)),
            float(len(entry.user_agent)),
            float(self._count_query_params(entry.path)),
            float(self._has_special_chars(entry.path)),
            float(entry.status_code >= 400),
            float(entry.status_code >= 500),
            float(entry.timestamp.hour),
        ]
        return features

    def _method_code(self, method: str) -> float:
        return float(self.METHOD_MAP.get(method.upper(), 9))

    def _count_query_params(self, path: str) -> int:
        if "?" not in path:
            return 0
        query = path.split("?", 1)[1]
        return query.count("&") + 1

    def _has_special_chars(self, path: str) -> int:
        suspicious = {"<", ">", "'", '"', ";", "(", ")", "\\", "../"}
        return 1 if any(c in path for c in suspicious) else 0


class AnomalyDetector:
    """
    Isolation Forest tabanlı anomali tespit modeli.
    Model eğitimi ve tahmin işlemleri sağlar.
    """

    MODEL_FILENAME = "anomaly_model.pkl"
    SCALER_FILENAME = "anomaly_scaler.pkl"

    def __init__(self, contamination: float = 0.05, model_dir: str = "./models"):
        """
        Args:
            contamination: Beklenen anomali oranı (0.0 - 0.5)
            model_dir: Model dosyalarının saklanacağı dizin
        """
        self.contamination = contamination
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._extractor = RequestFeatureExtractor()
        self._model: Optional[object] = None
        self._scaler: Optional[object] = None
        self._is_fitted = False

    def fit(self, entries: list) -> "AnomalyDetector":
        """
        Modeli verilen log entry'leri ile eğitir.

        Args:
            entries: LogEntry nesneleri listesi

        Returns:
            self (method chaining)
        """
        _check_sklearn()
        if not entries:
            raise ValueError("Eğitim için en az bir entry gereklidir.")

        X = np.array([self._extractor.extract(e) for e in entries])

        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._is_fitted = True
        logger.info(f"Anomali modeli eğitildi: {len(entries)} örnek")
        return self

    def predict(self, entry) -> bool:
        """
        Tek bir entry'nin anomali olup olmadığını tahmin eder.

        Args:
            entry: LogEntry nesnesi

        Returns:
            True ise anomali
        """
        if not self._is_fitted:
            return False

        _check_sklearn()
        features = np.array([self._extractor.extract(entry)])
        features_scaled = self._scaler.transform(features)
        prediction = self._model.predict(features_scaled)
        # Isolation Forest: -1 = anomali, 1 = normal
        return int(prediction[0]) == -1

    def score(self, entry) -> float:
        """
        Anomali skorunu döner (negatif değer = daha anormal).

        Args:
            entry: LogEntry nesnesi

        Returns:
            Anomali skoru
        """
        if not self._is_fitted:
            return 0.0

        _check_sklearn()
        features = np.array([self._extractor.extract(entry)])
        features_scaled = self._scaler.transform(features)
        return float(self._model.score_samples(features_scaled)[0])

    def save(self) -> None:
        """Modeli ve scaler'ı diske kaydeder."""
        if not self._is_fitted:
            raise RuntimeError("Model henüz eğitilmedi.")

        model_path = self.model_dir / self.MODEL_FILENAME
        scaler_path = self.model_dir / self.SCALER_FILENAME

        with open(model_path, "wb") as f:
            pickle.dump(self._model, f)
        with open(scaler_path, "wb") as f:
            pickle.dump(self._scaler, f)

        logger.info(f"Model kaydedildi: {model_path}")

    def load(self) -> bool:
        """
        Önceden kaydedilmiş modeli yükler.

        Returns:
            Başarılı ise True
        """
        model_path = self.model_dir / self.MODEL_FILENAME
        scaler_path = self.model_dir / self.SCALER_FILENAME

        if not model_path.exists() or not scaler_path.exists():
            logger.warning("Kayıtlı model bulunamadı.")
            return False

        try:
            with open(model_path, "rb") as f:
                self._model = pickle.load(f)
            with open(scaler_path, "rb") as f:
                self._scaler = pickle.load(f)
            self._is_fitted = True
            logger.info("Model yüklendi.")
            return True
        except (pickle.UnpicklingError, EOFError, ValueError) as e:
            logger.error(f"Model yükleme hatası: {e}")
            return False
