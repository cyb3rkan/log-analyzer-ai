"""
Threat Detector - Tehdit Tespit Modülü
Brute force, DDoS, SQL injection, path traversal, XSS ve port tarama tespiti.
"""
import re
import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .parsers.nginx import LogEntry

logger = logging.getLogger(__name__)


# ─── Tehdit seviyeleri ────────────────────────────────────────────────────────

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


@dataclass
class ThreatEvent:
    """Tespit edilen bir tehdit olayını temsil eder."""
    threat_type: str
    severity: str
    source_ip: str
    timestamp: datetime
    description: str
    target: str = ""
    payload: str = ""
    details: dict = field(default_factory=dict)
    raw_entry: Optional[LogEntry] = None

    def to_dict(self) -> dict:
        return {
            "threat_type": self.threat_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "target": self.target,
            "payload": self.payload,
            "details": self.details,
        }


# ─── SQL Injection pattern'leri ───────────────────────────────────────────────

SQL_INJECTION_PATTERNS = [
    re.compile(r"('|%27)\s*(OR|AND)\s*('|\d|%27)", re.IGNORECASE),
    re.compile(r"(\bUNION\b.*\bSELECT\b)", re.IGNORECASE),
    re.compile(r"(--|#|/\*)", re.IGNORECASE),
    re.compile(r"\b(DROP|DELETE|TRUNCATE|ALTER|CREATE)\b.*\b(TABLE|DATABASE)\b", re.IGNORECASE),
    re.compile(r"\bEXEC\b.*\(", re.IGNORECASE),
    re.compile(r"(xp_cmdshell|sp_executesql)", re.IGNORECASE),
    re.compile(r"SLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
    re.compile(r"1\s*=\s*1|'1'\s*=\s*'1'", re.IGNORECASE),
    re.compile(r"(char|nchar|varchar|nvarchar)\s*\(", re.IGNORECASE),
]

# ─── Path Traversal pattern'leri ─────────────────────────────────────────────

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e%2f", re.IGNORECASE),
    re.compile(r"%2e%2e/", re.IGNORECASE),
    re.compile(r"\.\.%2f", re.IGNORECASE),
    re.compile(r"%252e%252e%252f", re.IGNORECASE),
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
    re.compile(r"c:\\windows\\system32", re.IGNORECASE),
    re.compile(r"boot\.ini", re.IGNORECASE),
]

# ─── XSS pattern'leri ────────────────────────────────────────────────────────

XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(load|click|mouseover|error|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+src\s*=\s*['\"]?javascript", re.IGNORECASE),
    re.compile(r"document\.(cookie|write|location)", re.IGNORECASE),
    re.compile(r"(alert|prompt|confirm)\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"%3cscript", re.IGNORECASE),
    re.compile(r"&#\d+;", re.IGNORECASE),
    re.compile(r"data:text/html", re.IGNORECASE),
]

# ─── Şüpheli User Agent'lar ──────────────────────────────────────────────────

SUSPICIOUS_UA_PATTERNS = [
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"nmap", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
    re.compile(r"zgrab", re.IGNORECASE),
    re.compile(r"python-requests", re.IGNORECASE),
    re.compile(r"curl/", re.IGNORECASE),
    re.compile(r"wget/", re.IGNORECASE),
    re.compile(r"dirbuster", re.IGNORECASE),
    re.compile(r"gobuster", re.IGNORECASE),
    re.compile(r"hydra", re.IGNORECASE),
    re.compile(r"metasploit", re.IGNORECASE),
]

# ─── Brute-force hedef yolları ───────────────────────────────────────────────

BRUTE_FORCE_PATHS = {
    "/wp-login.php", "/wp-admin/", "/admin/", "/administrator/",
    "/login", "/login.php", "/signin", "/auth", "/api/auth",
    "/.env", "/.git/config", "/phpmyadmin/", "/xmlrpc.php",
}


class SlidingWindowCounter:
    """
    Kayar pencere algoritması ile istek sayısını takip eder.
    Thread-safe değildir; tek thread kullanımı için tasarlanmıştır.
    """

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._data: dict[str, deque] = defaultdict(deque)

    def add(self, key: str, ts: Optional[float] = None) -> int:
        """
        Yeni bir olay ekler ve mevcut penceredeki toplam sayısını döner.

        Args:
            key: Gruplama anahtarı (örn. IP adresi)
            ts: Unix timestamp (None ise şimdiki zaman)

        Returns:
            Penceredeki mevcut olay sayısı
        """
        now = ts or time.time()
        cutoff = now - self.window
        dq = self._data[key]
        dq.append(now)
        # Eski olayları temizle
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def count(self, key: str) -> int:
        """Bir anahtara ait mevcut penceredeki olay sayısını döner."""
        now = time.time()
        cutoff = now - self.window
        dq = self._data[key]
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def reset(self, key: str) -> None:
        """Bir anahtarın sayacını sıfırlar."""
        self._data.pop(key, None)


class ThreatDetector:
    """
    Ana tehdit tespit motoru.
    Log entry'leri analiz ederek tehdit olayları üretir.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: config.yaml'dan gelen detection konfigürasyonu
        """
        self.config = config or {}
        detection = self.config.get("detection", {})

        # Brute force konfigürasyonu
        bf = detection.get("brute_force", {})
        self._bf_threshold = bf.get("threshold", 100)
        self._bf_window = bf.get("window", 60)
        self._bf_enabled = bf.get("enabled", True)
        self._bf_counter = SlidingWindowCounter(self._bf_window)
        self._bf_blocked: set[str] = set()

        # DDoS konfigürasyonu
        ddos = detection.get("ddos", {})
        self._ddos_threshold = ddos.get("threshold", 1000)
        self._ddos_window = ddos.get("window", 60)
        self._ddos_enabled = ddos.get("enabled", True)
        self._ddos_counter = SlidingWindowCounter(self._ddos_window)

        # Diğer tespitler
        sqli = detection.get("sql_injection", {})
        self._sqli_enabled = sqli.get("enabled", True)

        pt = detection.get("path_traversal", {})
        self._pt_enabled = pt.get("enabled", True)

        xss = detection.get("xss", {})
        self._xss_enabled = xss.get("enabled", True)

        # Whitelist
        whitelist = self.config.get("whitelist", {})
        self._whitelist_ips: set[str] = set(whitelist.get("ips", []))
        self._whitelist_uas: list[str] = [ua.lower() for ua in whitelist.get("user_agents", [])]

    def _is_whitelisted(self, entry: LogEntry) -> bool:
        """IP veya user agent beyaz listede mi kontrol eder."""
        if entry.ip in self._whitelist_ips:
            return True
        ua_lower = entry.user_agent.lower()
        for wa in self._whitelist_uas:
            if wa in ua_lower:
                return True
        return False

    def analyze(self, entry: LogEntry) -> list[ThreatEvent]:
        """
        Tek bir log entry'sini analiz eder ve tespit edilen tehditleri döner.

        Args:
            entry: Parse edilmiş log entry

        Returns:
            Tespit edilen ThreatEvent listesi (boş olabilir)
        """
        if self._is_whitelisted(entry):
            return []

        threats: list[ThreatEvent] = []

        # Brute Force
        if self._bf_enabled:
            threat = self._check_brute_force(entry)
            if threat:
                threats.append(threat)

        # DDoS
        if self._ddos_enabled:
            threat = self._check_ddos(entry)
            if threat:
                threats.append(threat)

        # SQL Injection
        if self._sqli_enabled:
            threat = self._check_sql_injection(entry)
            if threat:
                threats.append(threat)

        # Path Traversal
        if self._pt_enabled:
            threat = self._check_path_traversal(entry)
            if threat:
                threats.append(threat)

        # XSS
        if self._xss_enabled:
            threat = self._check_xss(entry)
            if threat:
                threats.append(threat)

        # Şüpheli User Agent
        threat = self._check_suspicious_ua(entry)
        if threat:
            threats.append(threat)

        return threats

    def _check_brute_force(self, entry: LogEntry) -> Optional[ThreatEvent]:
        """Brute force saldırısı tespit eder."""
        path_lower = entry.path.lower().split("?")[0]
        if path_lower not in BRUTE_FORCE_PATHS:
            return None
        if entry.status_code not in (401, 403, 200):
            return None

        ts = entry.timestamp.timestamp()
        count = self._bf_counter.add(entry.ip, ts)

        if count >= self._bf_threshold:
            return ThreatEvent(
                threat_type="BRUTE_FORCE",
                severity=SEVERITY_HIGH,
                source_ip=entry.ip,
                timestamp=entry.timestamp,
                description=f"Brute Force saldırısı tespit edildi: {count} istek / {self._bf_window}s",
                target=entry.path,
                details={"count": count, "threshold": self._bf_threshold, "window": self._bf_window},
                raw_entry=entry,
            )
        return None

    def _check_ddos(self, entry: LogEntry) -> Optional[ThreatEvent]:
        """DDoS saldırısı tespit eder."""
        ts = entry.timestamp.timestamp()
        count = self._ddos_counter.add(entry.ip, ts)

        if count >= self._ddos_threshold:
            return ThreatEvent(
                threat_type="DDOS",
                severity=SEVERITY_CRITICAL,
                source_ip=entry.ip,
                timestamp=entry.timestamp,
                description=f"Olası DDoS saldırısı: {count} istek / {self._ddos_window}s",
                target=entry.path,
                details={"count": count, "threshold": self._ddos_threshold},
                raw_entry=entry,
            )
        return None

    def _check_sql_injection(self, entry: LogEntry) -> Optional[ThreatEvent]:
        """SQL Injection girişimini tespit eder."""
        # URL decode edilmiş path'i kontrol et
        from urllib.parse import unquote
        decoded_path = unquote(entry.path)

        for pattern in SQL_INJECTION_PATTERNS:
            match = pattern.search(decoded_path)
            if match:
                payload = match.group(0)[:200]
                return ThreatEvent(
                    threat_type="SQL_INJECTION",
                    severity=SEVERITY_HIGH,
                    source_ip=entry.ip,
                    timestamp=entry.timestamp,
                    description=f"SQL Injection girişimi tespit edildi",
                    target=entry.path,
                    payload=payload,
                    details={"pattern": pattern.pattern, "decoded_path": decoded_path[:500]},
                    raw_entry=entry,
                )
        return None

    def _check_path_traversal(self, entry: LogEntry) -> Optional[ThreatEvent]:
        """Path traversal saldırısını tespit eder."""
        from urllib.parse import unquote
        decoded_path = unquote(entry.path)

        for pattern in PATH_TRAVERSAL_PATTERNS:
            match = pattern.search(decoded_path)
            if match:
                payload = match.group(0)[:200]
                return ThreatEvent(
                    threat_type="PATH_TRAVERSAL",
                    severity=SEVERITY_HIGH,
                    source_ip=entry.ip,
                    timestamp=entry.timestamp,
                    description="Path traversal saldırısı tespit edildi",
                    target=entry.path,
                    payload=payload,
                    details={"decoded_path": decoded_path[:500]},
                    raw_entry=entry,
                )
        return None

    def _check_xss(self, entry: LogEntry) -> Optional[ThreatEvent]:
        """XSS saldırısını tespit eder."""
        from urllib.parse import unquote
        decoded_path = unquote(entry.path)

        for pattern in XSS_PATTERNS:
            match = pattern.search(decoded_path)
            if match:
                payload = match.group(0)[:200]
                return ThreatEvent(
                    threat_type="XSS",
                    severity=SEVERITY_MEDIUM,
                    source_ip=entry.ip,
                    timestamp=entry.timestamp,
                    description="XSS girişimi tespit edildi",
                    target=entry.path,
                    payload=payload,
                    details={"decoded_path": decoded_path[:500]},
                    raw_entry=entry,
                )
        return None

    def _check_suspicious_ua(self, entry: LogEntry) -> Optional[ThreatEvent]:
        """Şüpheli user agent tespiti."""
        ua_lower = entry.user_agent.lower()
        for pattern in SUSPICIOUS_UA_PATTERNS:
            if pattern.search(ua_lower):
                return ThreatEvent(
                    threat_type="SUSPICIOUS_UA",
                    severity=SEVERITY_LOW,
                    source_ip=entry.ip,
                    timestamp=entry.timestamp,
                    description=f"Şüpheli User-Agent tespit edildi: {entry.user_agent[:100]}",
                    target=entry.path,
                    payload=entry.user_agent[:200],
                    details={"user_agent": entry.user_agent},
                    raw_entry=entry,
                )
        return None
