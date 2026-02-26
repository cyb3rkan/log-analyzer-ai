<<<<<<< HEAD
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
=======
"""
Detector Testleri
"""
import pytest
from datetime import datetime, timezone

from src.parsers.nginx import LogEntry
from src.detector import (
    ThreatDetector,
    ThreatEvent,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_CRITICAL,
    SEVERITY_LOW,
    SlidingWindowCounter,
)


def _make_entry(
    ip="1.2.3.4",
    method="GET",
    path="/",
    status=200,
    bytes_sent=1024,
    user_agent="Mozilla/5.0",
    referrer="-",
    ts=None,
) -> LogEntry:
    return LogEntry(
        ip=ip,
        timestamp=ts or datetime.now(tz=timezone.utc),
        method=method,
        path=path,
        status_code=status,
        bytes_sent=bytes_sent,
        referrer=referrer,
        user_agent=user_agent,
        raw="",
        source="nginx",
    )


DEFAULT_CONFIG = {
    "detection": {
        "brute_force": {"enabled": True, "threshold": 5, "window": 60},
        "ddos":        {"enabled": True, "threshold": 50, "window": 60},
        "sql_injection": {"enabled": True, "use_ai": False},
        "path_traversal": {"enabled": True},
        "xss": {"enabled": True},
    },
    "whitelist": {"ips": [], "user_agents": []},
}


class TestSlidingWindowCounter:

    def test_initial_count_is_zero(self):
        counter = SlidingWindowCounter(60)
        assert counter.count("testkey") == 0

    def test_add_increments(self):
        counter = SlidingWindowCounter(60)
        assert counter.add("ip1") == 1
        assert counter.add("ip1") == 2
        assert counter.add("ip1") == 3

    def test_different_keys_independent(self):
        counter = SlidingWindowCounter(60)
        counter.add("ip1")
        counter.add("ip1")
        counter.add("ip2")
        assert counter.count("ip1") == 2
        assert counter.count("ip2") == 1

    def test_reset(self):
        counter = SlidingWindowCounter(60)
        counter.add("ip1")
        counter.add("ip1")
        counter.reset("ip1")
        assert counter.count("ip1") == 0

    def test_window_expiry(self):
        import time
        counter = SlidingWindowCounter(window_seconds=1)
        counter.add("ip1", ts=time.time() - 2)  # Eski olay
        counter.add("ip1", ts=time.time() - 2)  # Eski olay
        # Yeni bir olay ekle — eski olaylar silinmeli
        count = counter.add("ip1")
        assert count == 1


class TestBruteForceDetection:

    def setup_method(self):
        self.detector = ThreatDetector(DEFAULT_CONFIG)

    def test_no_threat_below_threshold(self):
        for _ in range(4):
            threats = self.detector.analyze(_make_entry(path="/wp-login.php", status=401))
        # Son çağrıda brute force sayısı 4, threshold 5 → tehdit yok
        bf_threats = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        assert len(bf_threats) == 0

    def test_threat_at_threshold(self):
        all_threats = []
        for _ in range(5):
            threats = self.detector.analyze(_make_entry(path="/wp-login.php", status=401))
            all_threats.extend(threats)
        bf_threats = [t for t in all_threats if t.threat_type == "BRUTE_FORCE"]
        assert len(bf_threats) >= 1
        assert bf_threats[0].severity == SEVERITY_HIGH

    def test_non_login_path_not_detected(self):
        for _ in range(10):
            threats = self.detector.analyze(_make_entry(path="/static/style.css", status=200))
        bf_threats = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        assert len(bf_threats) == 0

    def test_whitelisted_ip_ignored(self):
        config = dict(DEFAULT_CONFIG)
        config["whitelist"] = {"ips": ["1.2.3.4"], "user_agents": []}
        detector = ThreatDetector(config)
        for _ in range(10):
            threats = detector.analyze(_make_entry(ip="1.2.3.4", path="/wp-login.php", status=401))
        assert len(threats) == 0


class TestSQLInjectionDetection:

    def setup_method(self):
        self.detector = ThreatDetector(DEFAULT_CONFIG)

    def test_detect_or_1_equals_1(self):
        entry = _make_entry(path="/search?q=' OR '1'='1")
        threats = self.detector.analyze(entry)
        sqli = [t for t in threats if t.threat_type == "SQL_INJECTION"]
        assert len(sqli) == 1
        assert sqli[0].severity == SEVERITY_HIGH

    def test_detect_union_select(self):
        entry = _make_entry(path="/api/items?id=1 UNION SELECT * FROM users")
        threats = self.detector.analyze(entry)
        sqli = [t for t in threats if t.threat_type == "SQL_INJECTION"]
        assert len(sqli) == 1

    def test_detect_url_encoded(self):
        entry = _make_entry(path="/search?q=%27%20OR%20%271%27%3D%271")
        threats = self.detector.analyze(entry)
        sqli = [t for t in threats if t.threat_type == "SQL_INJECTION"]
        assert len(sqli) == 1

    def test_no_false_positive_normal_path(self):
        entry = _make_entry(path="/articles/python-tutorial")
        threats = self.detector.analyze(entry)
        sqli = [t for t in threats if t.threat_type == "SQL_INJECTION"]
        assert len(sqli) == 0

    def test_detect_drop_table(self):
        entry = _make_entry(path="/api/exec?cmd=DROP TABLE users")
        threats = self.detector.analyze(entry)
        sqli = [t for t in threats if t.threat_type == "SQL_INJECTION"]
        assert len(sqli) == 1


class TestPathTraversalDetection:

    def setup_method(self):
        self.detector = ThreatDetector(DEFAULT_CONFIG)

    def test_detect_dotdot(self):
        entry = _make_entry(path="/files/../../etc/passwd")
        threats = self.detector.analyze(entry)
        pt = [t for t in threats if t.threat_type == "PATH_TRAVERSAL"]
        assert len(pt) == 1

    def test_detect_etc_passwd(self):
        entry = _make_entry(path="/download?file=/etc/passwd")
        threats = self.detector.analyze(entry)
        pt = [t for t in threats if t.threat_type == "PATH_TRAVERSAL"]
        assert len(pt) == 1

    def test_no_false_positive(self):
        entry = _make_entry(path="/downloads/report.pdf")
        threats = self.detector.analyze(entry)
        pt = [t for t in threats if t.threat_type == "PATH_TRAVERSAL"]
        assert len(pt) == 0


class TestXSSDetection:

    def setup_method(self):
        self.detector = ThreatDetector(DEFAULT_CONFIG)

    def test_detect_script_tag(self):
        entry = _make_entry(path="/search?q=<script>alert(1)</script>")
        threats = self.detector.analyze(entry)
        xss = [t for t in threats if t.threat_type == "XSS"]
        assert len(xss) == 1
        assert xss[0].severity == SEVERITY_MEDIUM

    def test_detect_javascript_protocol(self):
        entry = _make_entry(path="/redirect?url=javascript:alert(document.cookie)")
        threats = self.detector.analyze(entry)
        xss = [t for t in threats if t.threat_type == "XSS"]
        assert len(xss) == 1

    def test_no_false_positive(self):
        entry = _make_entry(path="/articles/what-is-javascript")
        threats = self.detector.analyze(entry)
        xss = [t for t in threats if t.threat_type == "XSS"]
        assert len(xss) == 0


class TestSuspiciousUserAgent:

    def setup_method(self):
        self.detector = ThreatDetector(DEFAULT_CONFIG)

    def test_detect_sqlmap(self):
        entry = _make_entry(user_agent="sqlmap/1.7.11#stable")
        threats = self.detector.analyze(entry)
        ua = [t for t in threats if t.threat_type == "SUSPICIOUS_UA"]
        assert len(ua) == 1
        assert ua[0].severity == SEVERITY_LOW

    def test_detect_nikto(self):
        entry = _make_entry(user_agent="Nikto v2.1.6")
        threats = self.detector.analyze(entry)
        ua = [t for t in threats if t.threat_type == "SUSPICIOUS_UA"]
        assert len(ua) == 1

    def test_normal_ua_not_flagged(self):
        entry = _make_entry(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        threats = self.detector.analyze(entry)
        ua = [t for t in threats if t.threat_type == "SUSPICIOUS_UA"]
        assert len(ua) == 0


class TestThreatEventToDict:

    def test_to_dict_complete(self):
        event = ThreatEvent(
            threat_type="SQL_INJECTION",
            severity=SEVERITY_HIGH,
            source_ip="1.2.3.4",
            timestamp=datetime(2024, 1, 15, 14, 32, 0, tzinfo=timezone.utc),
            description="SQL injection detected",
            target="/api/search",
            payload="' OR '1'='1",
        )
        d = event.to_dict()
        assert d["threat_type"] == "SQL_INJECTION"
        assert d["severity"] == "HIGH"
        assert d["source_ip"] == "1.2.3.4"
        assert d["target"] == "/api/search"
        assert "timestamp" in d
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0
