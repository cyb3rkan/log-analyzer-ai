"""
Nginx Access Log Parser
Combined ve custom format destekler.
"""
import re
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class LogEntry:
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
