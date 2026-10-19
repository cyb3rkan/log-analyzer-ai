"""Unit tests for threat detection engine."""
from datetime import datetime, timezone
import pytest
from src.detector import ThreatDetector, ThreatEvent, SlidingWindowCounter
from src.parsers.nginx import LogEntry

CFG = {
    "detection": {
        "brute_force": {"enabled": True, "threshold": 5, "window": 60},
        "sql_injection": {"enabled": True},
        "path_traversal": {"enabled": True},
        "xss": {"enabled": True},
        "suspicious_ua": {"enabled": True},
    },
    "whitelist": {"ips": ["10.10.10.10"], "user_agents": ["GoogleBot"]},
}


def mk(ip="1.2.3.4", path="/", method="GET", status=200, ua="Mozilla/5.0", ts=None):
    if ts is None:
        ts = datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc)
    return LogEntry(ip=ip, timestamp=ts, method=method, path=path, status_code=status,
                    bytes_sent=1024, referrer="-", user_agent=ua, raw="", source="nginx")


class TestSlidingWindow:
    def test_count(self):
        c = SlidingWindowCounter(60)
        ts = datetime(2024, 1, 15, 14, 30, 0)
        assert c.add("k", ts) == 1
        assert c.add("k", ts) == 2

    def test_expiry(self):
        c = SlidingWindowCounter(60)
        c.add("k", datetime(2024, 1, 15, 14, 30, 0))
        assert c.add("k", datetime(2024, 1, 15, 14, 31, 30)) == 1


class TestDetector:
    def test_normal(self):
        assert len(ThreatDetector(CFG).analyze(mk())) == 0

    def test_sqli_or(self):
        assert any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk(path="/q?x=' OR '1'='1")))

    def test_sqli_union(self):
        assert any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk(path="/q?id=1 UNION SELECT * FROM u")))

    def test_sqli_encoded_union(self):
        """URL-encoded UNION SELECT must be detected."""
        assert any(t.threat_type == "SQL_INJECTION" for t in
                    ThreatDetector(CFG).analyze(mk(path="/q?id=%22%20union%20select%201,%202--")))

    def test_sqli_plus_encoded(self):
        """Plus-encoded OR 1=1 must be detected."""
        assert any(t.threat_type == "SQL_INJECTION" for t in
                    ThreatDetector(CFG).analyze(mk(path="/q?id=5%27+OR+1%3D1%23")))

    def test_sqli_information_schema_encoded(self):
        assert any(t.threat_type == "SQL_INJECTION" for t in
                    ThreatDetector(CFG).analyze(mk(path="/q?id=1%27+union+select+1%2C+column_name+from+information_schema.columns")))

    def test_sqli_drop(self):
        assert any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk(path="/q?x=; DROP TABLE u")))

    def test_path_traversal(self):
        assert any(t.threat_type == "PATH_TRAVERSAL" for t in ThreatDetector(CFG).analyze(mk(path="/f?x=../../etc/passwd")))

    def test_xss(self):
        assert any(t.threat_type == "XSS" for t in ThreatDetector(CFG).analyze(mk(path="/q?x=<script>alert(1)</script>")))

    def test_suspicious_ua_sqlmap(self):
        assert any(t.threat_type == "SUSPICIOUS_UA" for t in ThreatDetector(CFG).analyze(mk(ua="sqlmap/1.7")))

    def test_suspicious_ua_nikto(self):
        assert any(t.threat_type == "SUSPICIOUS_UA" for t in ThreatDetector(CFG).analyze(mk(ua="Nikto/2.1.6")))

    def test_brute_force(self):
        d = ThreatDetector(CFG)
        found = []
        for i in range(6):
            ts = datetime(2024, 1, 15, 14, 30, i, tzinfo=timezone.utc)
            found.extend(d.analyze(mk(ip="192.168.1.100", path="/wp-login.php", method="POST", status=401, ts=ts)))
        assert any(t.threat_type == "BRUTE_FORCE" for t in found)

    def test_whitelist_ip(self):
        assert len(ThreatDetector(CFG).analyze(mk(ip="10.10.10.10", path="/q?x=' OR 1=1"))) == 0

    def test_whitelist_ua(self):
        assert len(ThreatDetector(CFG).analyze(mk(ua="GoogleBot/2.1", path="/q?x=' OR 1=1"))) == 0

    def test_to_dict(self):
        t = ThreatEvent("SQL_INJECTION", "CRITICAL", "1.2.3.4", datetime.now(), "test", confidence=0.95)
        assert t.to_dict()["threat_type"] == "SQL_INJECTION"

    def test_reset(self):
        d = ThreatDetector(CFG)
        d.analyze(mk(path="/q?x=<script>alert(1)</script>"))
        d.reset()
        assert d.stats["total_analyzed"] == 0
