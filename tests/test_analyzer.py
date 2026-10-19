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
