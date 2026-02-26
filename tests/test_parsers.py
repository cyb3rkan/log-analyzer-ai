<<<<<<< HEAD
"""Unit tests for log parsers."""
import os, tempfile
import pytest
from src.parsers.nginx import NginxParser, LogEntry
from src.parsers.apache import ApacheParser
from src.parsers.syslog import SyslogParser
from src.parsers.windows import WindowsEventParser
from src.parsers import get_parser, PARSER_REGISTRY


class TestNginxParser:
    def setup_method(self):
        self.p = NginxParser()

    def test_normal(self):
        e = self.p.parse_line('127.0.0.1 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"')
        assert e and e.ip == "127.0.0.1" and e.method == "GET" and e.status_code == 200

    def test_sqli_payload(self):
        e = self.p.parse_line('10.0.0.55 - - [15/Jan/2024:14:30:06 +0000] "GET /search?q=\' OR \'1\'=\'1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"')
        assert e and e.ip == "10.0.0.55"

    def test_empty(self):
        assert self.p.parse_line("") is None
        assert self.p.parse_line("   ") is None

    def test_invalid(self):
        assert self.p.parse_line("not a log line") is None

    def test_post(self):
        e = self.p.parse_line('192.168.1.100 - - [15/Jan/2024:14:30:00 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"')
        assert e and e.method == "POST" and e.status_code == 401

    def test_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write('127.0.0.1 - - [15/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Test"\n')
            f.write('10.0.0.1 - - [15/Jan/2024:10:00:01 +0000] "POST /api HTTP/1.1" 201 50 "-" "curl"\n')
            fp = f.name
        try:
            assert len(list(self.p.parse_file(fp))) == 2
        finally:
            os.unlink(fp)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            list(self.p.parse_file("/nonexistent.log"))

    def test_to_dict(self):
        e = self.p.parse_line('1.2.3.4 - - [15/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "T"')
        assert e.to_dict()["ip"] == "1.2.3.4"

    def test_carriage_return(self):
        e = self.p.parse_line('1.2.3.4 - - [15/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "T"\r')
        assert e and e.ip == "1.2.3.4"


class TestApacheParser:
    def test_combined(self):
        p = ApacheParser()
        e = p.parse_line('192.168.1.1 - admin [15/Jan/2024:14:30:00 +0000] "GET /dash HTTP/1.1" 200 5678 "http://x.com" "Mozilla/5.0"')
        assert e and e.source == "apache"


class TestSyslogParser:
    def test_ssh(self):
        p = SyslogParser()
        e = p.parse_line("Jan 15 14:30:00 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2")
        assert e and e.ip == "192.168.1.100"


class TestWindowsParser:
    def test_failed_logon(self):
        p = WindowsEventParser()
        e = p.parse_line("2024-01-15,14:30:00,Security,4625,Error,An account failed to log on. IP: 192.168.1.50")
        assert e and e.ip == "192.168.1.50" and e.status_code == 4625

    def test_header(self):
        p = WindowsEventParser()
        assert p.parse_line("Date,Time,Source,EventID,Level,Message") is None


class TestRegistry:
    def test_all_parsers(self):
        for name in ["nginx", "apache", "syslog", "windows"]:
            assert get_parser(name) is not None

    def test_unknown(self):
        with pytest.raises(ValueError):
            get_parser("unknown")
=======
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
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0
