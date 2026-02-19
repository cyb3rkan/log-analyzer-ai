"""
Syslog Parser
RFC 3164 ve RFC 5424 formatlarını destekler.
"""
import re
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class SyslogEntry:
    """Parse edilmiş syslog satırı."""
    timestamp: datetime
    hostname: str
    process: str
    pid: Optional[int]
    message: str
    severity: str
    facility: str
    raw: str
    source: str = "syslog"
    extra: dict = field(default_factory=dict)


# RFC 3164 format: Jan 15 14:32:00 hostname process[pid]: message
RFC3164_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+'
    r'(?P<day>\s?\d+)\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)'
)

# RFC 5424 format: <priority>version timestamp hostname app-name procid msgid msg
RFC5424_PATTERN = re.compile(
    r'<(?P<priority>\d+)>(?P<version>\d+)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<appname>\S+)\s+'
    r'(?P<procid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<message>.+)'
)

SEVERITY_MAP = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"
}

FACILITY_MAP = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7"
}

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


class SyslogParser:
    """Syslog dosyalarını parse eden sınıf."""

    def parse_line(self, line: str) -> Optional[SyslogEntry]:
        """
        Tek bir syslog satırını parse eder.

        Args:
            line: Ham syslog satırı

        Returns:
            SyslogEntry nesnesi veya None
        """
        line = line.strip()
        if not line:
            return None

        # RFC 5424 dene
        match = RFC5424_PATTERN.match(line)
        if match:
            return self._parse_rfc5424(match, line)

        # RFC 3164 dene
        match = RFC3164_PATTERN.match(line)
        if match:
            return self._parse_rfc3164(match, line)

        return None

    def _parse_rfc3164(self, match: re.Match, raw: str) -> Optional[SyslogEntry]:
        try:
            d = match.groupdict()
            month = MONTH_MAP.get(d["month"], 1)
            day = int(d["day"].strip())
            time_parts = d["time"].split(":")
            current_year = datetime.now().year
            timestamp = datetime(
                current_year, month, day,
                int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
            )
            pid = int(d["pid"]) if d.get("pid") else None
            return SyslogEntry(
                timestamp=timestamp,
                hostname=d["hostname"],
                process=d["process"],
                pid=pid,
                message=d["message"],
                severity="INFO",
                facility="syslog",
                raw=raw,
            )
        except (ValueError, KeyError):
            return None

    def _parse_rfc5424(self, match: re.Match, raw: str) -> Optional[SyslogEntry]:
        try:
            d = match.groupdict()
            priority = int(d["priority"])
            facility_code = priority >> 3
            severity_code = priority & 0x07
            severity = SEVERITY_MAP.get(severity_code, "UNKNOWN")
            facility = FACILITY_MAP.get(facility_code, "unknown")

            try:
                timestamp = datetime.fromisoformat(d["timestamp"].replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now()

            pid = None
            if d["procid"] != "-":
                try:
                    pid = int(d["procid"])
                except ValueError:
                    pass

            return SyslogEntry(
                timestamp=timestamp,
                hostname=d["hostname"],
                process=d["appname"],
                pid=pid,
                message=d["message"],
                severity=severity,
                facility=facility,
                raw=raw,
            )
        except (ValueError, KeyError):
            return None

    def parse_file(self, filepath: str):
        """
        Syslog dosyasını satır satır parse eder (generator).

        Args:
            filepath: Syslog dosyası yolu

        Yields:
            SyslogEntry nesneleri
        """
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = self.parse_line(line)
                if entry:
                    yield entry
