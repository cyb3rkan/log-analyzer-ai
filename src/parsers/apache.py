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
