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


@dataclass
class LogEntry:
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
