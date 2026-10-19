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

    def to_dict(self) -> dict:
        return {
            "threat_type": self.threat_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
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

        if self._is_whitelisted(entry):
            return []

        threats: list[ThreatEvent] = []

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
