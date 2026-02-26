<<<<<<< HEAD
"""Unit tests for LogAnalyzer."""
import os, tempfile, shutil
import pytest
from src.analyzer import LogAnalyzer

LOG = """127.0.0.1 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.55 - - [15/Jan/2024:14:30:06 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
192.168.50.10 - - [15/Jan/2024:16:00:00 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.88"
172.16.0.50 - - [15/Jan/2024:17:00:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
10.0.0.100 - - [15/Jan/2024:18:00:00 +0000] "GET /api/users HTTP/1.1" 200 512 "-" "sqlmap/1.7.11#stable"
"""

CFG = {"detection": {"brute_force": {"enabled": True, "threshold": 5, "window": 60},
       "sql_injection": {"enabled": True}, "path_traversal": {"enabled": True},
       "xss": {"enabled": True}, "suspicious_ua": {"enabled": True}},
       "whitelist": {"ips": [], "user_agents": []}}

@pytest.fixture
def log_file():
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    f.write(LOG); f.flush(); f.close()
    yield f.name
    os.unlink(f.name)

@pytest.fixture
def log_dir():
    d = tempfile.mkdtemp()
    for i in range(2):
        with open(os.path.join(d, f"t{i}.log"), "w") as f:
            f.write(LOG)
    yield d
    shutil.rmtree(d)

class TestAnalyzer:
    def test_file(self, log_file):
        r = LogAnalyzer(CFG).analyze_file(log_file)
        assert r.total_lines_processed == 5 and len(r.threats) >= 3

    def test_callback(self, log_file):
        found = []
        r = LogAnalyzer(CFG).analyze_file(log_file, on_threat=found.append)
        assert len(found) == len(r.threats)

    def test_not_found(self):
        with pytest.raises(FileNotFoundError):
            LogAnalyzer(CFG).analyze_file("/nope.log")

    def test_directory(self, log_dir):
        r = LogAnalyzer(CFG).analyze_directory(log_dir, "*.log")
        assert r.total_lines_processed == 10

    def test_report(self, log_file):
        a = LogAnalyzer(CFG)
        r = a.analyze_file(log_file)
        d = tempfile.mkdtemp()
        files = a.generate_report(r, d, "both")
        assert len(files) == 2
        shutil.rmtree(d)

    def test_threat_types(self, log_file):
        types = {t.threat_type for t in LogAnalyzer(CFG).analyze_file(log_file).threats}
        assert "PATH_TRAVERSAL" in types and "XSS" in types and "SUSPICIOUS_UA" in types
=======
"""
Analyzer Entegrasyon Testleri
"""
import pytest
from pathlib import Path

from src.analyzer import LogAnalyzer
from src.reporter import ReportData


SAMPLE_NGINX_LOG = """\
192.168.1.100 - - [15/Jan/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [15/Jan/2024:14:30:01 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:02 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:03 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:04 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:05 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
10.0.0.55 - - [15/Jan/2024:14:30:06 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
10.0.0.56 - - [15/Jan/2024:14:30:07 +0000] "GET /files/../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.88"
10.0.0.57 - - [15/Jan/2024:14:30:08 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
"""

MINIMAL_CONFIG = {
    "detection": {
        "brute_force": {"enabled": True, "threshold": 5, "window": 60},
        "ddos": {"enabled": True, "threshold": 10000, "window": 60},
        "sql_injection": {"enabled": True, "use_ai": False},
        "path_traversal": {"enabled": True},
        "xss": {"enabled": True},
    },
    "response": {
        "auto_block": {"enabled": False},
        "alerts": {"slack": {"enabled": False}, "telegram": {"enabled": False}},
    },
    "whitelist": {"ips": [], "user_agents": []},
    "reporting": {"output_dir": "/tmp/test_reports", "daily": False, "weekly": False},
}


class TestLogAnalyzerFile:

    def setup_method(self):
        self.analyzer = LogAnalyzer(MINIMAL_CONFIG)

    def test_analyze_file_returns_report_data(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(SAMPLE_NGINX_LOG)
        data = self.analyzer.analyze_file(str(log_file))
        assert isinstance(data, ReportData)

    def test_analyze_file_counts_lines(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(SAMPLE_NGINX_LOG)
        data = self.analyzer.analyze_file(str(log_file))
        # 9 valid log satırı var
        assert data.total_lines_processed == 9

    def test_analyze_file_detects_threats(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(SAMPLE_NGINX_LOG)
        data = self.analyzer.analyze_file(str(log_file))
        assert len(data.threats) > 0

    def test_analyze_file_detects_sqli(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(SAMPLE_NGINX_LOG)
        collected = []
        self.analyzer.analyze_file(str(log_file), on_threat=collected.append)
        sqli = [t for t in collected if t.threat_type == "SQL_INJECTION"]
        assert len(sqli) >= 1

    def test_analyze_file_detects_path_traversal(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(SAMPLE_NGINX_LOG)
        collected = []
        self.analyzer.analyze_file(str(log_file), on_threat=collected.append)
        pt = [t for t in collected if t.threat_type == "PATH_TRAVERSAL"]
        assert len(pt) >= 1

    def test_analyze_file_detects_xss(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(SAMPLE_NGINX_LOG)
        collected = []
        self.analyzer.analyze_file(str(log_file), on_threat=collected.append)
        xss = [t for t in collected if t.threat_type == "XSS"]
        assert len(xss) >= 1

    def test_on_threat_callback(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text(SAMPLE_NGINX_LOG)
        callback_calls = []
        self.analyzer.analyze_file(str(log_file), on_threat=callback_calls.append)
        assert len(callback_calls) > 0

    def test_analyze_nonexistent_file(self):
        data = self.analyzer.analyze_file("/nonexistent/path/access.log")
        assert data.total_lines_processed == 0

    def test_analyze_apache_format(self, tmp_path):
        apache_log = (
            '192.168.1.1 - - [15/Jan/2024:12:00:00 +0000] '
            '"GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
        )
        log_file = tmp_path / "apache.log"
        log_file.write_text(apache_log)
        data = self.analyzer.analyze_file(str(log_file), log_format="apache")
        assert data.total_lines_processed == 1


class TestLogAnalyzerDirectory:

    def setup_method(self):
        self.analyzer = LogAnalyzer(MINIMAL_CONFIG)

    def test_analyze_directory(self, tmp_path):
        for i in range(3):
            (tmp_path / f"access{i}.log").write_text(SAMPLE_NGINX_LOG)

        data = self.analyzer.analyze_directory(str(tmp_path))
        assert data.total_lines_processed == 9 * 3

    def test_analyze_empty_directory(self, tmp_path):
        data = self.analyzer.analyze_directory(str(tmp_path))
        assert data.total_lines_processed == 0

    def test_analyze_directory_pattern(self, tmp_path):
        (tmp_path / "access.log").write_text(SAMPLE_NGINX_LOG)
        (tmp_path / "error.txt").write_text("not a log")

        data = self.analyzer.analyze_directory(str(tmp_path), pattern="*.log")
        assert data.total_lines_processed == 9


class TestGetParser:

    def test_nginx_format(self):
        from src.parsers.nginx import NginxParser
        parser = LogAnalyzer._get_parser("nginx")
        assert isinstance(parser, NginxParser)

    def test_apache_format(self):
        from src.parsers.apache import ApacheParser
        parser = LogAnalyzer._get_parser("apache")
        assert isinstance(parser, ApacheParser)

    def test_syslog_format(self):
        from src.parsers.syslog import SyslogParser
        parser = LogAnalyzer._get_parser("syslog")
        assert isinstance(parser, SyslogParser)

    def test_combined_alias(self):
        from src.parsers.nginx import NginxParser
        parser = LogAnalyzer._get_parser("combined")
        assert isinstance(parser, NginxParser)

    def test_unknown_fallback(self):
        from src.parsers.nginx import NginxParser
        parser = LogAnalyzer._get_parser("unknown_format")
        assert isinstance(parser, NginxParser)
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0
