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
