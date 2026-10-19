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
