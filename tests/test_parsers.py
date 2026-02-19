"""
Parser Testleri
"""
import pytest
from datetime import datetime, timezone

from src.parsers.nginx import NginxParser, LogEntry
from src.parsers.apache import ApacheParser
from src.parsers.syslog import SyslogParser


# ─── Örnek log satırları ──────────────────────────────────────────────────────

NGINX_COMBINED = (
    '192.168.1.1 - frank [10/Jan/2024:13:55:36 +0000] '
    '"GET /index.html HTTP/1.1" 200 2326 '
    '"https://www.example.com/" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)

NGINX_EMPTY_REFERRER = (
    '10.0.0.1 - - [15/Jan/2024:14:32:00 +0000] '
    '"POST /api/login HTTP/1.1" 401 512 '
    '"-" "python-requests/2.28.0"'
)

NGINX_BYTES_DASH = (
    '127.0.0.1 - - [15/Jan/2024:00:00:01 +0000] '
    '"HEAD /health HTTP/1.1" 200 - "-" "curl/7.88.1"'
)

APACHE_COMBINED = (
    '203.0.113.5 - - [15/Jan/2024:12:00:00 +0000] '
    '"GET /wp-login.php HTTP/1.1" 401 1234 '
    '"-" "sqlmap/1.7"'
)

SYSLOG_RFC3164 = 'Jan 15 14:32:00 myhost sshd[1234]: Failed password for root from 192.168.1.100'

SYSLOG_RFC5424 = (
    '<165>1 2024-01-15T14:32:00+00:00 mymachine.example.com '
    'evntslog 256 ID47 [exampleSDID@32473 iut="3"] '
    'An application event log entry'
)


class TestNginxParser:

    def setup_method(self):
        self.parser = NginxParser()

    def test_parse_combined_format(self):
        entry = self.parser.parse_line(NGINX_COMBINED)
        assert entry is not None
        assert entry.ip == "192.168.1.1"
        assert entry.method == "GET"
        assert entry.path == "/index.html"
        assert entry.status_code == 200
        assert entry.bytes_sent == 2326
        assert entry.source == "nginx"

    def test_parse_empty_referrer(self):
        entry = self.parser.parse_line(NGINX_EMPTY_REFERRER)
        assert entry is not None
        assert entry.ip == "10.0.0.1"
        assert entry.method == "POST"
        assert entry.path == "/api/login"
        assert entry.status_code == 401
        assert entry.user_agent == "python-requests/2.28.0"

    def test_parse_bytes_dash(self):
        entry = self.parser.parse_line(NGINX_BYTES_DASH)
        assert entry is not None
        assert entry.bytes_sent == 0

    def test_parse_empty_line(self):
        assert self.parser.parse_line("") is None
        assert self.parser.parse_line("   ") is None

    def test_parse_invalid_line(self):
        assert self.parser.parse_line("not a log line at all") is None

    def test_parse_file(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(
            NGINX_COMBINED + "\n" +
            NGINX_EMPTY_REFERRER + "\n" +
            "invalid line\n"
        )
        entries = list(self.parser.parse_file(str(log_file)))
        assert len(entries) == 2

    def test_timestamp_parsed(self):
        entry = self.parser.parse_line(NGINX_COMBINED)
        assert isinstance(entry.timestamp, datetime)
        assert entry.timestamp.year == 2024
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 10

    def test_raw_stored(self):
        entry = self.parser.parse_line(NGINX_COMBINED)
        assert entry.raw == NGINX_COMBINED


class TestApacheParser:

    def setup_method(self):
        self.parser = ApacheParser()

    def test_parse_combined_format(self):
        entry = self.parser.parse_line(APACHE_COMBINED)
        assert entry is not None
        assert entry.ip == "203.0.113.5"
        assert entry.method == "GET"
        assert entry.path == "/wp-login.php"
        assert entry.status_code == 401
        assert entry.source == "apache"

    def test_parse_empty_line(self):
        assert self.parser.parse_line("") is None

    def test_parse_file(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(APACHE_COMBINED + "\n")
        entries = list(self.parser.parse_file(str(log_file)))
        assert len(entries) == 1


class TestSyslogParser:

    def setup_method(self):
        self.parser = SyslogParser()

    def test_parse_rfc3164(self):
        entry = self.parser.parse_line(SYSLOG_RFC3164)
        assert entry is not None
        assert entry.hostname == "myhost"
        assert entry.process == "sshd"
        assert entry.pid == 1234
        assert "Failed password" in entry.message

    def test_parse_rfc5424(self):
        entry = self.parser.parse_line(SYSLOG_RFC5424)
        assert entry is not None
        assert entry.hostname == "mymachine.example.com"

    def test_parse_empty_line(self):
        assert self.parser.parse_line("") is None

    def test_parse_invalid(self):
        assert self.parser.parse_line("not syslog") is None
