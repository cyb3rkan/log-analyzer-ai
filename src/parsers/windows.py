"""Windows Event Log parser (text/CSV export format)."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from src.parsers.nginx import LogEntry

WINDOWS_CSV_PATTERN = re.compile(
    r'(?P<date>\d{4}-\d{2}-\d{2})[,\t]'
    r'(?P<time>\d{2}:\d{2}:\d{2})[,\t]'
    r'(?P<source>[^,\t]+)[,\t]'
    r'(?P<event_id>\d+)[,\t]'
    r'(?P<level>[^,\t]+)[,\t]'
    r'(?P<message>.*)'
)

IP_PATTERN = re.compile(r'(?:IP|Address|Source)[:\s]+(\d{1,3}(?:\.\d{1,3}){3})', re.IGNORECASE)

SECURITY_EVENTS = {
    4625: "Failed logon", 4624: "Successful logon", 4648: "Explicit credentials",
    4672: "Special privileges", 4720: "Account created", 4726: "Account deleted",
    4740: "Account locked out", 1102: "Audit log cleared",
}


class WindowsEventParser:
    """Parser for Windows Event Log text exports."""

    def __init__(self) -> None:
        self.name = "windows"
        self._parse_errors = 0
        self._lines_parsed = 0

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip().replace("\r", "")
        if not line or line.startswith("#") or line.startswith("Date"):
            return None

        match = WINDOWS_CSV_PATTERN.match(line)
        if not match:
            self._parse_errors += 1
            return None

        self._lines_parsed += 1
        try:
            timestamp = datetime.strptime(f"{match.group('date')} {match.group('time')}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            timestamp = None

        message = match.group("message")
        event_id = int(match.group("event_id"))
        ip_match = IP_PATTERN.search(message)
        ip = ip_match.group(1) if ip_match else "0.0.0.0"

        return LogEntry(
            ip=ip, timestamp=timestamp, method="EVENT", path=f"/event/{event_id}",
            status_code=event_id, bytes_sent=0, referrer="-",
            user_agent=f"Windows/{match.group('source').strip()}", raw=line, source="windows",
            extra={"event_id": event_id, "level": match.group("level").strip(),
                   "source": match.group("source").strip(), "message": message,
                   "event_description": SECURITY_EVENTS.get(event_id, "")},
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
