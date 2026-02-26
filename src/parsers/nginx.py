<<<<<<< HEAD
"""Nginx combined format log parser."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

NGINX_COMBINED_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s*(?P<protocol>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

NGINX_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
=======
"""
Nginx Access Log Parser
Combined ve custom format destekler.
"""
import re
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0


@dataclass
class LogEntry:
<<<<<<< HEAD
    """Represents a single parsed log entry."""
    ip: str = ""
    timestamp: Optional[datetime] = None
    method: str = ""
    path: str = ""
    status_code: int = 0
    bytes_sent: int = 0
    referrer: str = "-"
    user_agent: str = ""
    raw: str = ""
    source: str = "unknown"
    protocol: str = "HTTP/1.1"
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "bytes_sent": self.bytes_sent,
            "referrer": self.referrer,
            "user_agent": self.user_agent,
            "source": self.source,
        }


class NginxParser:
    """Parser for Nginx combined log format."""

    def __init__(self) -> None:
        self.name = "nginx"
        self._parse_errors = 0
        self._lines_parsed = 0

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip().replace("\r", "")
        if not line or line.startswith("#"):
            return None

        match = NGINX_COMBINED_PATTERN.match(line)
        if not match:
            self._parse_errors += 1
            return None

        self._lines_parsed += 1
        try:
            timestamp = datetime.strptime(match.group("timestamp"), NGINX_TIMESTAMP_FORMAT)
        except ValueError:
            timestamp = None

        bytes_sent = match.group("bytes")
        return LogEntry(
            ip=match.group("ip"),
            timestamp=timestamp,
            method=match.group("method"),
            path=match.group("path"),
            status_code=int(match.group("status")),
            bytes_sent=int(bytes_sent) if bytes_sent != "-" else 0,
            referrer=match.group("referrer") or "-",
            user_agent=match.group("user_agent") or "",
            raw=line,
            source="nginx",
            protocol=(match.group("protocol") or "HTTP/1.1").strip(),
        )

    def parse_file(self, filepath: str) -> Generator[LogEntry, None, None]:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                entry = self.parse_line(line)
                if entry is not None:
                    yield entry

    @property
    def stats(self) -> dict:
        total = self._lines_parsed + self._parse_errors
        return {
            "lines_parsed": self._lines_parsed,
            "parse_errors": self._parse_errors,
            "success_rate": (self._lines_parsed / total * 100) if total > 0 else 0.0,
        }
=======
    """Parse edilmiş tek bir log satırını temsil eder."""
    ip: str
    timestamp: datetime
    method: str
    path: str
    status_code: int
    bytes_sent: int
    referrer: str
    user_agent: str
    raw: str
    source: str = "nginx"
    extra: dict = field(default_factory=dict)


# Nginx combined format regex
# path grubu: HTTP versiyon etiketine kadar her şeyi yakalar
# (boşluk içeren SQL injection yüklerini de destekler)
COMBINED_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'                    # IP adresi
    r'\S+\s+'                             # ident
    r'\S+\s+'                             # kullanıcı adı
    r'\[(?P<time>[^\]]+)\]\s+'           # zaman damgası
    r'"(?P<method>\S+)\s+'               # HTTP metodu
    r'(?P<path>.*?)\s+HTTP/\S+"\s+'      # yol (HTTP/ öncesine kadar)
    r'(?P<status>\d{3})\s+'              # durum kodu
    r'(?P<bytes>\d+|-)\s+'               # gönderilen byte
    r'"(?P<referrer>[^"]*)"\s+'          # referrer
    r'"(?P<user_agent>[^"]*)"'           # user agent
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class NginxParser:
    """Nginx access log dosyalarını parse eden sınıf."""

    def __init__(self):
        self._pattern = COMBINED_PATTERN

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Tek bir log satırını parse eder.

        Args:
            line: Ham log satırı

        Returns:
            LogEntry nesnesi veya parse edilemezse None
        """
        line = line.strip()
        if not line:
            return None

        match = self._pattern.match(line)
        if not match:
            return None

        try:
            d = match.groupdict()
            bytes_sent = int(d["bytes"]) if d["bytes"] != "-" else 0
            timestamp = datetime.strptime(d["time"], TIME_FORMAT)

            return LogEntry(
                ip=d["ip"],
                timestamp=timestamp,
                method=d["method"],
                path=d["path"],
                status_code=int(d["status"]),
                bytes_sent=bytes_sent,
                referrer=d["referrer"],
                user_agent=d["user_agent"],
                raw=line,
                source="nginx",
            )
        except (ValueError, KeyError):
            return None

    def parse_file(self, filepath: str):
        """
        Log dosyasını satır satır parse eder (generator).

        Args:
            filepath: Log dosyası yolu

        Yields:
            LogEntry nesneleri
        """
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = self.parse_line(line)
                if entry:
                    yield entry
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0
