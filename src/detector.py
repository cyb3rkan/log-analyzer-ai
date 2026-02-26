<<<<<<< HEAD
"""Threat detection engine with rule-based and AI-assisted detection.

Key fix: All request paths are URL-decoded before pattern matching,
so encoded payloads like %27+union+select are properly detected.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from urllib.parse import unquote, unquote_plus

from src.parsers.nginx import LogEntry

logger = logging.getLogger(__name__)

# ── SQL Injection Patterns ──────────────────────────────────────────────────
SQL_PATTERNS: list[re.Pattern] = [
    re.compile(r"('|%27)\s*(OR|AND)\s*('|\d|%27)", re.IGNORECASE),
    re.compile(r"\bUNION\b.*\bSELECT\b", re.IGNORECASE),
    re.compile(r"(--|#|/\*)", re.IGNORECASE),
    re.compile(r"\bDROP\b.*\bTABLE\b", re.IGNORECASE),
    re.compile(r"\bEXEC(\s|\()+\w+", re.IGNORECASE),
    re.compile(r"xp_cmdshell", re.IGNORECASE),
    re.compile(r";\s*DROP", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
    re.compile(r"load_file\s*\(", re.IGNORECASE),
    re.compile(r"into\s+outfile", re.IGNORECASE),
    re.compile(r"\bOR\b\s+\d+\s*=\s*\d+", re.IGNORECASE),          # OR 1=1
    re.compile(r"'\s*OR\s+'[^']*'\s*=\s*'", re.IGNORECASE),         # ' OR 'x'='x
    re.compile(r"\bdatabase\s*\(\s*\)", re.IGNORECASE),              # database()
    re.compile(r"\bconcat\s*\(", re.IGNORECASE),                     # concat(
    re.compile(r"\bgroup_concat\s*\(", re.IGNORECASE),               # group_concat(
]

# ── Path Traversal Patterns ─────────────────────────────────────────────────
PATH_TRAVERSAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e[/%5c]", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|hosts)", re.IGNORECASE),
    re.compile(r"\\windows\\system32", re.IGNORECASE),
    re.compile(r"/proc/self", re.IGNORECASE),
    re.compile(r"boot\.ini", re.IGNORECASE),
]

# ── XSS Patterns ────────────────────────────────────────────────────────────
XSS_PATTERNS: list[re.Pattern] = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(load|error|click|mouseover)\s*=", re.IGNORECASE),
    re.compile(r"<iframe", re.IGNORECASE),
    re.compile(r"<img[^>]+onerror", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
    re.compile(r"<svg[^>]+onload", re.IGNORECASE),
]

# ── Suspicious User Agent Patterns ──────────────────────────────────────────
SUSPICIOUS_UA_PATTERNS: list[re.Pattern] = [
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"nmap", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
    re.compile(r"dirbuster", re.IGNORECASE),
    re.compile(r"gobuster", re.IGNORECASE),
    re.compile(r"wpscan", re.IGNORECASE),
    re.compile(r"havij", re.IGNORECASE),
    re.compile(r"acunetix", re.IGNORECASE),
    re.compile(r"nessus", re.IGNORECASE),
    re.compile(r"openvas", re.IGNORECASE),
    re.compile(r"burpsuite", re.IGNORECASE),
    re.compile(r"metasploit", re.IGNORECASE),
    re.compile(r"hydra", re.IGNORECASE),
    re.compile(r"w3af", re.IGNORECASE),
]


def _url_decode(text: str) -> str:
    """Decode URL-encoded text (handles both %XX and + encoding).

    Applies double-decoding to catch evasion attempts like %2527.
    """
    decoded = unquote_plus(text)
    # Second pass for double-encoding evasion
    if "%" in decoded:
        decoded = unquote_plus(decoded)
    return decoded


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ThreatEvent:
    """Represents a detected threat event."""
    threat_type: str
    severity: str                     # CRITICAL, HIGH, MEDIUM, LOW
    source_ip: str
    timestamp: Optional[datetime]
    description: str
    payload: str = ""
    confidence: float = 1.0
    raw_log: str = ""
    detection_method: str = "rule-based"
=======
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
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0

    def to_dict(self) -> dict:
        return {
            "threat_type": self.threat_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
<<<<<<< HEAD
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "description": self.description,
            "payload": self.payload,
            "confidence": self.confidence,
            "raw_log": self.raw_log,
            "detection_method": self.detection_method,
        }


class SlidingWindowCounter:
    """Time-based sliding window counter for brute force detection."""

    def __init__(self, window_seconds: int = 60) -> None:
        self._window = window_seconds
        self._data: dict[str, deque] = defaultdict(deque)

    def add(self, key: str, timestamp: datetime) -> int:
        dq = self._data[key]
        ts = timestamp.timestamp()
        cutoff = ts - self._window
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(ts)
        return len(dq)

    def get(self, key: str) -> int:
        return len(self._data.get(key, deque()))

    def reset(self, key: str) -> None:
        self._data.pop(key, None)

    def reset_all(self) -> None:
        self._data.clear()


# ── Main Detector ────────────────────────────────────────────────────────────

class ThreatDetector:
    """Main threat detection engine combining rule-based and AI-assisted detection."""

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = config or {}
        det = self.config.get("detection", {})

        # Brute force settings
        bf = det.get("brute_force", {})
        self._bf_enabled = bf.get("enabled", True)
        self._bf_threshold = bf.get("threshold", 5)
        self._bf_window = bf.get("window", 60)
        self._bf_counter = SlidingWindowCounter(self._bf_window)

        # Feature flags
        self._sqli_enabled = det.get("sql_injection", {}).get("enabled", True)
        self._pt_enabled = det.get("path_traversal", {}).get("enabled", True)
        self._xss_enabled = det.get("xss", {}).get("enabled", True)
        self._ua_enabled = det.get("suspicious_ua", {}).get("enabled", True)

        # Whitelist
        wl = self.config.get("whitelist", {})
        self._whitelist_ips = self._parse_whitelist_ips(wl.get("ips", []))
        self._whitelist_uas = [ua.lower() for ua in wl.get("user_agents", [])]

        # AI
        self._ai_classifier = None
        self._use_ai = det.get("sql_injection", {}).get("use_ai", False)

        # Stats
        self.stats: dict = {"total_analyzed": 0, "threats_detected": 0, "by_type": Counter()}

    @staticmethod
    def _parse_whitelist_ips(ip_list: list) -> list:
        parsed = []
        for ip_str in ip_list:
            try:
                s = str(ip_str)
                if "/" in s:
                    net = ipaddress.ip_network(s, strict=False)
                    if net.prefixlen <= 16:
                        logger.warning(f"Broad whitelist: {s} ({net.num_addresses} addrs) — may miss threats!")
                    parsed.append(net)
                else:
                    parsed.append(ipaddress.ip_address(s))
            except ValueError:
                logger.warning(f"Invalid whitelist entry: {ip_str}")
        return parsed

    def _is_whitelisted(self, entry: LogEntry) -> bool:
        try:
            addr = ipaddress.ip_address(entry.ip)
            for item in self._whitelist_ips:
                if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if addr in item:
                        return True
                elif addr == item:
                    return True
        except ValueError:
            pass

        if entry.user_agent:
            ua_lower = entry.user_agent.lower()
            for wl_ua in self._whitelist_uas:
                if wl_ua in ua_lower:
                    return True
        return False

    def analyze(self, entry: LogEntry) -> List[ThreatEvent]:
        """Analyze a log entry for threats. Returns list of detected threats."""
        self.stats["total_analyzed"] += 1

=======
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
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0
        if self._is_whitelisted(entry):
            return []

        threats: list[ThreatEvent] = []

<<<<<<< HEAD
        # URL-decode path + protocol for analysis (handles %27, %20, +, etc.)
        decoded_path = _url_decode(f"{entry.path} {getattr(entry, 'protocol', '')}")
        decoded_referrer = _url_decode(entry.referrer) if entry.referrer else ""

        if self._sqli_enabled:
            t = self._detect_sql_injection(entry, decoded_path, decoded_referrer)
            if t:
                threats.append(t)

        if self._pt_enabled:
            t = self._detect_path_traversal(entry, decoded_path)
            if t:
                threats.append(t)

        if self._xss_enabled:
            t = self._detect_xss(entry, decoded_path, decoded_referrer)
            if t:
                threats.append(t)

        if self._ua_enabled:
            t = self._detect_suspicious_ua(entry)
            if t:
                threats.append(t)

        if self._bf_enabled:
            t = self._detect_brute_force(entry)
            if t:
                threats.append(t)

        for threat in threats:
            self.stats["threats_detected"] += 1
            self.stats["by_type"][threat.threat_type] += 1

        return threats

    def _detect_sql_injection(self, entry: LogEntry, decoded_path: str, decoded_referrer: str) -> Optional[ThreatEvent]:
        test_str = f"{decoded_path} {decoded_referrer}"
        for pattern in SQL_PATTERNS:
            if pattern.search(test_str):
                return ThreatEvent(
                    threat_type="SQL_INJECTION", severity="CRITICAL", source_ip=entry.ip,
                    timestamp=entry.timestamp,
                    description=f"SQL Injection from {entry.ip}",
                    payload=decoded_path[:200], confidence=0.95, raw_log=entry.raw,
                )
        return None

    def _detect_path_traversal(self, entry: LogEntry, decoded_path: str) -> Optional[ThreatEvent]:
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern.search(decoded_path):
                return ThreatEvent(
                    threat_type="PATH_TRAVERSAL", severity="HIGH", source_ip=entry.ip,
                    timestamp=entry.timestamp,
                    description=f"Path Traversal from {entry.ip}",
                    payload=decoded_path[:200], confidence=0.90, raw_log=entry.raw,
                )
        return None

    def _detect_xss(self, entry: LogEntry, decoded_path: str, decoded_referrer: str) -> Optional[ThreatEvent]:
        test_str = f"{decoded_path} {decoded_referrer}"
        for pattern in XSS_PATTERNS:
            if pattern.search(test_str):
                return ThreatEvent(
                    threat_type="XSS", severity="HIGH", source_ip=entry.ip,
                    timestamp=entry.timestamp,
                    description=f"XSS attempt from {entry.ip}",
                    payload=decoded_path[:200], confidence=0.90, raw_log=entry.raw,
                )
        return None

    def _detect_suspicious_ua(self, entry: LogEntry) -> Optional[ThreatEvent]:
        if not entry.user_agent:
            return None
        for pattern in SUSPICIOUS_UA_PATTERNS:
            if pattern.search(entry.user_agent):
                return ThreatEvent(
                    threat_type="SUSPICIOUS_UA", severity="MEDIUM", source_ip=entry.ip,
                    timestamp=entry.timestamp,
                    description=f"Suspicious UA from {entry.ip}: {entry.user_agent}",
                    payload=entry.user_agent, confidence=0.85, raw_log=entry.raw,
                )
        return None

    def _detect_brute_force(self, entry: LogEntry) -> Optional[ThreatEvent]:
        is_failed = entry.status_code in (401, 403)
        is_login = any(p in entry.path.lower() for p in
                       ["/login", "/wp-login", "/admin", "/auth", "/signin"])
        if not (is_failed or (is_login and entry.status_code >= 400)):
            return None
        if entry.timestamp is None:
            return None

        count = self._bf_counter.add(entry.ip, entry.timestamp)
        if count >= self._bf_threshold:
            return ThreatEvent(
                threat_type="BRUTE_FORCE",
                severity="CRITICAL" if count >= self._bf_threshold * 2 else "HIGH",
                source_ip=entry.ip, timestamp=entry.timestamp,
                description=f"Brute force: {count} failed attempts in {self._bf_window}s from {entry.ip}",
                payload=entry.path, confidence=min(1.0, count / self._bf_threshold),
                raw_log=entry.raw,
            )
        return None

    def get_ai_classifier(self):
        if self._ai_classifier is None and self._use_ai:
            try:
                from models.classifier import AIClassifier
                self._ai_classifier = AIClassifier(self.config.get("ai", {}))
            except Exception as e:
                logger.warning(f"AI classifier load failed: {e}")
        return self._ai_classifier

    def reset(self) -> None:
        self._bf_counter.reset_all()
        self.stats = {"total_analyzed": 0, "threats_detected": 0, "by_type": Counter()}
=======
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
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0
