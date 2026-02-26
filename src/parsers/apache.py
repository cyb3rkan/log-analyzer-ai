<<<<<<< HEAD
"""Apache combined/common log format parser."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from src.parsers.nginx import LogEntry

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s*(?P<protocol>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S %z"


class ApacheParser:
    """Parser for Apache combined and common log formats."""

    def __init__(self) -> None:
        self.name = "apache"
        self._parse_errors = 0
        self._lines_parsed = 0

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip().replace("\r", "")
        if not line or line.startswith("#"):
            return None

        match = APACHE_PATTERN.match(line)
        if not match:
            self._parse_errors += 1
            return None

        self._lines_parsed += 1
        try:
            timestamp = datetime.strptime(match.group("timestamp"), TIMESTAMP_FMT)
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
            source="apache",
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
"""
Apache Access Log Parser
Combined ve Common Log Format (CLF) destekler.
"""
import re
from datetime import datetime
from typing import Optional

from .nginx import LogEntry  # Aynı dataclass yapısını paylaşır


COMBINED_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<path>.*?)\s+HTTP/\S+"\s+'     # yol (HTTP/ öncesine kadar, boşluk destekli)
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class ApacheParser:
    """Apache access log dosyalarını parse eden sınıf."""

    def __init__(self):
        self._pattern = COMBINED_PATTERN

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Tek bir log satırını parse eder.

        Args:
            line: Ham log satırı

        Returns:
            LogEntry nesnesi veya None
        """
        line = line.strip()
        if not line:
            return None

        match = self._pattern.match(line)
        if not match:
            return None

        try:
            d = match.groupdict()
            bytes_sent = int(d["bytes"]) if d["bytes"] not in (None, "-") else 0
            timestamp = datetime.strptime(d["time"], TIME_FORMAT)

            return LogEntry(
                ip=d["ip"],
                timestamp=timestamp,
                method=d["method"] if d.get("method") else "UNKNOWN",
                path=d["path"] if d.get("path") else "/",
                status_code=int(d["status"]),
                bytes_sent=bytes_sent,
                referrer=d.get("referrer") or "-",
                user_agent=d.get("user_agent") or "-",
                raw=line,
                source="apache",
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
