"""
Threat Classifier - AI Destekli Tehdit Sınıflandırıcısı
OpenAI GPT ile şüpheli log entry'lerini analiz eder.
"""
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# openai opsiyonel bağımlılık
try:
    from openai import OpenAI
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False
    logger.warning("openai paketi bulunamadı. AI sınıflandırma devre dışı.")


SYSTEM_PROMPT = """Sen bir siber güvenlik uzmanısın. Sana verilen HTTP log entry'sini analiz et ve şu JSON formatında yanıt ver:
{
  "is_threat": true/false,
  "threat_type": "BRUTE_FORCE|SQL_INJECTION|XSS|PATH_TRAVERSAL|DDOS|SCANNING|BENIGN",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0-1.0,
  "reason": "kısa açıklama"
}
Sadece JSON döndür, başka açıklama ekleme."""


class ThreatClassifier:
    """
    OpenAI GPT kullanarak log entry'lerini sınıflandıran AI modeli.
    Rule-based tespiti desteklemek için kullanılır.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: config.yaml'dan gelen ai konfigürasyonu
        """
        ai_cfg = config.get("ai", {}) if config else {}
        self.model = ai_cfg.get("model", "gpt-4")
        self.threshold = ai_cfg.get("analyze_threshold", "medium").lower()
        api_key = os.environ.get("OPENAI_API_KEY", ai_cfg.get("api_key", ""))

        self._client: Optional[object] = None
        if _OPENAI_AVAILABLE and api_key:
            try:
                self._client = OpenAI(api_key=api_key)
                logger.info(f"OpenAI istemcisi başlatıldı (model: {self.model})")
            except Exception as e:
                logger.error(f"OpenAI istemcisi oluşturulamadı: {e}")

    def is_available(self) -> bool:
        """AI sınıflandırmanın kullanılabilir olup olmadığını döner."""
        return self._client is not None

    def classify(self, entry) -> Optional[dict]:
        """
        Bir log entry'sini AI ile analiz eder.

        Args:
            entry: LogEntry nesnesi

        Returns:
            Sınıflandırma sonucu dict veya None (AI kullanılamıyorsa)
        """
        if not self.is_available():
            return None

        prompt = self._build_prompt(entry)

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=200,
            )
            content = response.choices[0].message.content.strip()
            return self._parse_response(content)
        except Exception as e:
            logger.error(f"AI sınıflandırma hatası: {e}")
            return None

    def classify_batch(self, entries: list) -> list[Optional[dict]]:
        """
        Birden fazla entry'yi sırayla sınıflandırır.

        Args:
            entries: LogEntry listesi

        Returns:
            Sınıflandırma sonuçları listesi
        """
        results = []
        for entry in entries:
            result = self.classify(entry)
            results.append(result)
        return results

    def _build_prompt(self, entry) -> str:
        """Entry'den analiz promptu oluşturur."""
        return (
            f"IP: {entry.ip}\n"
            f"Method: {entry.method}\n"
            f"Path: {entry.path}\n"
            f"Status: {entry.status_code}\n"
            f"User-Agent: {entry.user_agent[:200]}\n"
            f"Bytes: {entry.bytes_sent}\n"
        )

    def _parse_response(self, content: str) -> Optional[dict]:
        """AI yanıtını parse eder."""
        import json
        # JSON fence'leri temizle
        content = content.replace("```json", "").replace("```", "").strip()
        try:
            data = json.loads(content)
            # Zorunlu alanları kontrol et
            required = {"is_threat", "threat_type", "severity", "confidence", "reason"}
            if not required.issubset(data.keys()):
                logger.warning(f"AI yanıtı eksik alan içeriyor: {data}")
                return None
            return data
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"AI yanıtı parse edilemedi: {e} | Content: {content[:200]}")
            return None
