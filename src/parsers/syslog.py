"""Syslog format parser (RFC 3164 / BSD style)."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from src.parsers.nginx import LogEntry

SYSLOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)'
)

IP_EXTRACT = re.compile(r'(?:from|src|source|addr|ip)[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})', re.IGNORECASE)
IP_FALLBACK = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')


class SyslogParser:
    """Parser for syslog (RFC 3164 BSD-style) format."""

    def __init__(self) -> None:
        self.name = "syslog"
        self._parse_errors = 0
        self._lines_parsed = 0

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip().replace("\r", "")
        if not line or line.startswith("#"):
            return None

        match = SYSLOG_PATTERN.match(line)
        if not match:
            self._parse_errors += 1
            return None

        self._lines_parsed += 1
        try:
            year = datetime.now().year
            timestamp = datetime.strptime(f"{year} {match.group('timestamp')}", "%Y %b %d %H:%M:%S")
        except ValueError:
            timestamp = None

        message = match.group("message")
        ip_match = IP_EXTRACT.search(message)
        ip = ip_match.group(1) if ip_match else (IP_FALLBACK.search(message) or type("", (), {"group": lambda s, x: "0.0.0.0"})()).group(1)

        program = match.group("program").strip()
        return LogEntry(
            ip=ip, timestamp=timestamp, method="SYSLOG", path=f"/{program}",
            status_code=0, bytes_sent=0, referrer="-",
            user_agent=f"{match.group('hostname')}/{program}",
            raw=line, source="syslog",
            extra={"hostname": match.group("hostname"), "program": program,
                   "pid": match.group("pid") or "", "message": message},
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
        return {"lines_parsed": self._lines_parsed, "parse_errors": self._parse_errors,
                "success_rate": (self._lines_parsed / total * 100) if total > 0 else 0.0}
