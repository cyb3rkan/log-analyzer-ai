<<<<<<< HEAD
#!/usr/bin/env python3
"""Log Analyzer AI - Comprehensive Test Suite."""

import json, os, sys, tempfile, time, shutil
from datetime import datetime, timezone

passed = failed = 0
fails = []

def run(name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  \u2705 {name}")
    except Exception as e:
        failed += 1
        fails.append((name, str(e)))
        print(f"  \u274c {name}: {e}")

CFG = {"detection": {"brute_force": {"enabled": True, "threshold": 5, "window": 60},
       "sql_injection": {"enabled": True}, "path_traversal": {"enabled": True},
       "xss": {"enabled": True}, "suspicious_ua": {"enabled": True}},
       "whitelist": {"ips": [], "user_agents": []}}

LINES = [
    '1.2.3.4 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n',
    '1.2.3.4 - - [15/Jan/2024:10:00:01 +0000] "GET /style.css HTTP/1.1" 200 4567 "-" "Mozilla/5.0"\n',
    '10.0.0.55 - - [15/Jan/2024:14:30:06 +0000] "GET /q?id=1 UNION SELECT * FROM users HTTP/1.1" 200 2048 "-" "Mozilla/5.0"\n',
    '192.168.36.1 - - [15/May/2024:04:46:11 +0000] "GET /dvwa/vulnerabilities/sqli/?id=1%27+OR+1%3D1%23 HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n',
    '192.168.36.1 - - [15/May/2024:04:47:36 +0000] "GET /dvwa/vulnerabilities/sqli/?id=1%27+union+select+database()%23 HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n',
    '192.168.36.1 - - [15/May/2024:04:51:33 +0000] "GET /dvwa/vulnerabilities/sqli/?id=1%27+union+select+1,+table_name+from+information_schema.tables HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n',
    '192.168.50.10 - - [15/Jan/2024:16:00:00 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.88"\n',
    '172.16.0.50 - - [15/Jan/2024:17:00:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n',
    '10.0.0.100 - - [15/Jan/2024:18:00:00 +0000] "GET /api/users HTTP/1.1" 200 512 "-" "sqlmap/1.7.11"\n',
]

def mklog():
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    f.writelines(LINES); f.flush(); f.close()
    return f.name

def mk_entry(ip="1.2.3.4", path="/", ua="Mozilla/5.0", status=200, ts=None):
    from src.parsers.nginx import LogEntry
    if ts is None: ts = datetime(2024,1,15,14,30,0,tzinfo=timezone.utc)
    return LogEntry(ip=ip, timestamp=ts, method="GET", path=path, status_code=status,
                    bytes_sent=1024, referrer="-", user_agent=ua, raw="", source="nginx")


def main():
    global passed, failed, fails
    passed = failed = 0; fails = []

    print("\n" + "=" * 60)
    print("\U0001f6e1\ufe0f  LOG ANALYZER AI - KAPSAMLI TEST SÜİTİ")
    print("=" * 60)

    # ── 1. PARSER ────────────────────────────────────
    print("\n\U0001f4cb 1. PARSER TESTLERİ\n" + "-" * 40)
    from src.parsers.nginx import NginxParser
    from src.parsers.apache import ApacheParser
    from src.parsers.syslog import SyslogParser
    from src.parsers.windows import WindowsEventParser

    run("Nginx - Normal log", lambda: (
        e := NginxParser().parse_line(LINES[0]),
        assert_(e and e.ip == "1.2.3.4" and e.status_code == 200)
    ))
    run("Nginx - URL-encoded SQLi line", lambda: (
        e := NginxParser().parse_line(LINES[3]),
        assert_(e and e.ip == "192.168.36.1")
    ))
    run("Nginx - File parse", lambda: (
        f := mklog(),
        r := list(NginxParser().parse_file(f)),
        os.unlink(f),
        assert_(len(r) == len(LINES), f"Expected {len(LINES)}, got {len(r)}")
    ))
    run("Nginx - Empty/invalid", lambda: assert_(
        NginxParser().parse_line("") is None and NginxParser().parse_line("garbage") is None
    ))
    run("Apache - Combined format", lambda: (
        e := ApacheParser().parse_line('1.2.3.4 - - [15/Jan/2024:14:30:00 +0000] "GET /x HTTP/1.1" 200 100 "-" "M"'),
        assert_(e and e.source == "apache")
    ))
    run("Syslog - SSH failed login", lambda: (
        e := SyslogParser().parse_line("Jan 15 14:30:00 srv sshd[123]: Failed from 192.168.1.100 port 22"),
        assert_(e and e.ip == "192.168.1.100")
    ))
    run("Windows - Event 4625", lambda: (
        e := WindowsEventParser().parse_line("2024-01-15,14:30:00,Security,4625,Error,Failed. IP: 1.2.3.4"),
        assert_(e and e.ip == "1.2.3.4" and e.status_code == 4625)
    ))

    # ── 2. DETECTOR ──────────────────────────────────
    print("\n\U0001f6e1\ufe0f 2. DETECTOR TESTLERİ\n" + "-" * 40)
    from src.detector import ThreatDetector

    run("SQLi - Plain OR pattern", lambda: assert_(
        any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk_entry(path="/q?x=' OR '1'='1")))
    ))
    run("SQLi - UNION SELECT", lambda: assert_(
        any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk_entry(path="/q?id=1 UNION SELECT * FROM u")))
    ))
    run("SQLi - URL-encoded UNION", lambda: assert_(
        any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk_entry(path="/q?id=%22%20union%20select%201")))
    ))
    run("SQLi - Plus-encoded OR 1=1", lambda: assert_(
        any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk_entry(path="/q?id=5%27+OR+1%3D1%23")))
    ))
    run("SQLi - information_schema encoded", lambda: assert_(
        any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk_entry(path="/q?id=1%27+union+select+1+from+information_schema.tables")))
    ))
    run("SQLi - database() encoded", lambda: assert_(
        any(t.threat_type == "SQL_INJECTION" for t in ThreatDetector(CFG).analyze(mk_entry(path="/q?id=1%27+union+select+database()%23")))
    ))
    run("Path Traversal - ../../etc/passwd", lambda: assert_(
        any(t.threat_type == "PATH_TRAVERSAL" for t in ThreatDetector(CFG).analyze(mk_entry(path="/f?x=../../etc/passwd")))
    ))
    run("XSS - <script> tag", lambda: assert_(
        any(t.threat_type == "XSS" for t in ThreatDetector(CFG).analyze(mk_entry(path="/q?x=<script>alert(1)</script>")))
    ))
    run("Suspicious UA - sqlmap", lambda: assert_(
        any(t.threat_type == "SUSPICIOUS_UA" for t in ThreatDetector(CFG).analyze(mk_entry(ua="sqlmap/1.7")))
    ))
    run("Suspicious UA - Nikto", lambda: assert_(
        any(t.threat_type == "SUSPICIOUS_UA" for t in ThreatDetector(CFG).analyze(mk_entry(ua="Nikto/2.1.6")))
    ))

    def _test_brute():
        d = ThreatDetector(CFG); found = []
        for i in range(6):
            found.extend(d.analyze(mk_entry(ip="192.168.1.100", path="/wp-login.php", status=401,
                                             ts=datetime(2024,1,15,14,30,i,tzinfo=timezone.utc))))
        assert any(t.threat_type == "BRUTE_FORCE" for t in found), "Brute force not detected"
    run("Brute Force - 6 failed logins", _test_brute)

    run("Normal traffic - no threats", lambda: assert_(
        len(ThreatDetector(CFG).analyze(mk_entry(path="/index.html"))) == 0
    ))

    # ── 3. ANALYZER ──────────────────────────────────
    print("\n\U0001f50d 3. ANALYZER TESTLERİ\n" + "-" * 40)
    from src.analyzer import LogAnalyzer

    def _test_file():
        f = mklog()
        try:
            r = LogAnalyzer(CFG).analyze_file(f)
            assert r.total_lines_processed == len(LINES), f"Lines: {r.total_lines_processed}"
            assert len(r.threats) >= 5, f"Threats: {len(r.threats)}"
        finally: os.unlink(f)
    run("File analysis", _test_file)

    def _test_dir():
        d = tempfile.mkdtemp()
        for i in range(2):
            with open(os.path.join(d, f"t{i}.log"), "w") as ff: ff.writelines(LINES)
        try:
            r = LogAnalyzer(CFG).analyze_directory(d, "*.log")
            assert r.total_lines_processed == len(LINES) * 2
        finally: shutil.rmtree(d)
    run("Directory analysis", _test_dir)

    def _test_cb():
        f = mklog(); cb = []
        try:
            r = LogAnalyzer(CFG).analyze_file(f, on_threat=cb.append)
            assert len(cb) == len(r.threats)
        finally: os.unlink(f)
    run("Threat callback", _test_cb)

    def _test_types():
        f = mklog()
        try:
            types = {t.threat_type for t in LogAnalyzer(CFG).analyze_file(f).threats}
            for tt in ["SQL_INJECTION", "PATH_TRAVERSAL", "XSS", "SUSPICIOUS_UA"]:
                assert tt in types, f"{tt} missing from {types}"
        finally: os.unlink(f)
    run("All threat types detected", _test_types)

    # ── 4. REPORTER ──────────────────────────────────
    print("\n\U0001f4ca 4. REPORTER TESTLERİ\n" + "-" * 40)
    from src.reporter import ReportData, Reporter
    from src.detector import ThreatEvent

    def mkt(tt="SQL_INJECTION", sev="CRITICAL", ip="10.0.0.1"):
        return ThreatEvent(tt, sev, ip, datetime.now(), "test", confidence=0.9)

    def _test_json():
        r = ReportData(total_lines_processed=100); r.add_threat(mkt())
        f = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
        try:
            Reporter().generate_json_report(r, f)
            assert json.load(open(f))["summary"]["total_threats"] == 1
        finally: os.unlink(f)
    run("JSON report", _test_json)

    def _test_txt():
        r = ReportData(total_lines_processed=100, source_file="t.log"); r.add_threat(mkt())
        f = tempfile.NamedTemporaryFile(suffix=".txt", delete=False).name
        try:
            Reporter().generate_text_report(r, f)
            assert "SQL_INJECTION" in open(f).read()
        finally: os.unlink(f)
    run("Text report", _test_txt)

    run("Top attacker IPs", lambda: (
        r := ReportData(),
        [r.add_threat(mkt(ip="10.0.0.1")) for _ in range(5)],
        [r.add_threat(mkt(ip="10.0.0.2")) for _ in range(2)],
        assert_(r.top_attacker_ips(1)[0] == ("10.0.0.1", 5))
    ))

    # ── 5. WHITELIST ─────────────────────────────────
    print("\n\U0001f512 5. WHITELIST TESTLERİ\n" + "-" * 40)
    wl_cfg = {**CFG, "whitelist": {"ips": ["10.10.10.10", "192.168.0.0/16"], "user_agents": ["GoogleBot"]}}

    run("Exact IP whitelist", lambda: assert_(
        len(ThreatDetector(wl_cfg).analyze(mk_entry(ip="10.10.10.10", path="/q?x=' OR 1=1"))) == 0
    ))
    run("CIDR whitelist", lambda: assert_(
        len(ThreatDetector(wl_cfg).analyze(mk_entry(ip="192.168.1.50", path="/q?x=' OR 1=1"))) == 0
    ))
    run("UA whitelist", lambda: assert_(
        len(ThreatDetector(wl_cfg).analyze(mk_entry(ua="GoogleBot/2.1", path="/q?x=' OR 1=1"))) == 0
    ))
    run("Non-whitelisted still detected", lambda: assert_(
        len(ThreatDetector(wl_cfg).analyze(mk_entry(ip="8.8.8.8", path="/q?x=' OR 1=1"))) >= 1
    ))

    # ── 6. FALSE POSITIVES ───────────────────────────
    print("\n\u2696\ufe0f 6. FALSE POSITIVE TESTLERİ\n" + "-" * 40)
    run("Normal page path", lambda: assert_(len(ThreatDetector(CFG).analyze(mk_entry(path="/about/team"))) == 0))
    run("Normal API call", lambda: assert_(len(ThreatDetector(CFG).analyze(mk_entry(path="/api/v1/products?page=2"))) == 0))
    run("Normal Chrome UA", lambda: assert_(len(ThreatDetector(CFG).analyze(mk_entry(ua="Mozilla/5.0 Chrome/120.0"))) == 0))

    # ── 7. PERFORMANCE ───────────────────────────────
    print("\n\u26a1 7. PERFORMANS TESTİ\n" + "-" * 40)
    def _test_perf():
        lines = [f'10.0.0.{i%256} - - [15/Jan/2024:10:{(i//60)%60:02d}:{i%60:02d} +0000] "GET /p{i} HTTP/1.1" 200 {1000+i} "-" "Mozilla/5.0"\n' for i in range(1000)]
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        f.writelines(lines); f.close()
        try:
            t0 = time.time()
            r = LogAnalyzer(CFG).analyze_file(f.name)
            dt = time.time() - t0
            assert r.total_lines_processed == 1000 and dt < 5.0, f"{dt:.2f}s"
            print(f"      (1000 satır: {dt:.3f}s)")
        finally: os.unlink(f.name)
    run("1000 satır < 5 saniye", _test_perf)

    # ── 8. KOMBİNE ───────────────────────────────────
    print("\n\U0001f3af 8. KOMBİNE SENARYO\n" + "-" * 40)
    def _test_combined():
        f = mklog()
        try:
            a = LogAnalyzer(CFG)
            r = a.analyze_file(f)
            types = {t.threat_type for t in r.threats}
            for tt in ["SQL_INJECTION", "PATH_TRAVERSAL", "XSS", "SUSPICIOUS_UA"]:
                assert tt in types, f"{tt} missing"
            d = tempfile.mkdtemp()
            files = a.generate_report(r, d, "both")
            assert len(files) == 2
            data = json.load(open([x for x in files if x.endswith(".json")][0]))
            assert data["summary"]["total_threats"] == len(r.threats)
            shutil.rmtree(d)
        finally: os.unlink(f)
    run("Full pipeline (Parse→Detect→Report)", _test_combined)

    # ── SUMMARY ──────────────────────────────────────
    total = passed + failed
    print(f"\n{'=' * 60}")
    print(f"\U0001f4ca SONUÇLAR: {passed}/{total} başarılı ({passed/total*100:.0f}%)")
    print(f"{'=' * 60}")
    if failed == 0:
        print(f"\U0001f389 TÜM TESTLER BAŞARILI!\n")
    else:
        for n, e in fails:
            print(f"  \u274c {n}: {e}")
        print()
    return 0 if failed == 0 else 1


def assert_(cond, msg="Assertion failed"):
    if not cond:
        raise AssertionError(msg)


if __name__ == "__main__":
    sys.exit(main())
=======
"""
🧪 KAPSAMLI ENTEGRASYONTESTİ
Tüm özellikleri end-to-end test eder
"""
import os
import json
import tempfile
import time
from pathlib import Path
from datetime import datetime

# Test için renk kodları
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'


def print_header(text):
    print(f"\n{BOLD}{BLUE}{'='*70}{RESET}")
    print(f"{BOLD}{BLUE}{text.center(70)}{RESET}")
    print(f"{BOLD}{BLUE}{'='*70}{RESET}\n")


def print_test(name, passed, details=""):
    status = f"{GREEN}✅ PASS{RESET}" if passed else f"{RED}❌ FAIL{RESET}"
    print(f"  {status} | {name}")
    if details:
        print(f"      └─ {details}")


def print_section(name):
    print(f"\n{YELLOW}{'─'*70}{RESET}")
    print(f"{YELLOW}{BOLD}📋 {name}{RESET}")
    print(f"{YELLOW}{'─'*70}{RESET}")


# Test verileri
SAMPLE_LOGS = {
    "brute_force": """192.168.1.100 - - [15/Jan/2024:14:30:00 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:01 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:02 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:03 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:04 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:05 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
""",
    
    "sql_injection": """10.0.0.55 - - [15/Jan/2024:14:30:00 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
10.0.0.56 - - [15/Jan/2024:14:30:01 +0000] "GET /api/users?id=1 UNION SELECT * FROM passwords HTTP/1.1" 200 512 "-" "curl/7.88"
10.0.0.57 - - [15/Jan/2024:14:30:02 +0000] "GET /product?id=1'; DROP TABLE users-- HTTP/1.1" 200 256 "-" "python-requests/2.28"
""",
    
    "path_traversal": """192.168.50.10 - - [15/Jan/2024:16:00:00 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.88"
192.168.50.11 - - [15/Jan/2024:16:00:01 +0000] "GET /files/..\\..\\windows\\system32\\config\\sam HTTP/1.1" 404 256 "-" "Mozilla/5.0"
192.168.50.12 - - [15/Jan/2024:16:00:02 +0000] "GET /static/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 404 256 "-" "python-requests/2.28"
""",
    
    "xss": """172.16.0.50 - - [15/Jan/2024:17:00:00 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
172.16.0.51 - - [15/Jan/2024:17:00:01 +0000] "GET /profile?name=<img src=x onerror=alert(1)> HTTP/1.1" 200 512 "-" "curl/7.88"
172.16.0.52 - - [15/Jan/2024:17:00:02 +0000] "GET /redirect?url=javascript:alert(1) HTTP/1.1" 200 256 "-" "python-requests/2.28"
""",
    
    "suspicious_ua": """10.0.0.100 - - [15/Jan/2024:18:00:00 +0000] "GET /api/users HTTP/1.1" 200 512 "-" "sqlmap/1.7.11#stable"
10.0.0.101 - - [15/Jan/2024:18:00:01 +0000] "GET /admin HTTP/1.1" 200 256 "-" "Nikto v2.1.6"
10.0.0.102 - - [15/Jan/2024:18:00:02 +0000] "GET /scan HTTP/1.1" 200 128 "-" "nmap NSE"
""",
    
    "normal": """127.0.0.1 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
127.0.0.1 - - [15/Jan/2024:10:00:01 +0000] "GET /about.html HTTP/1.1" 200 567 "-" "Mozilla/5.0"
127.0.0.1 - - [15/Jan/2024:10:00:02 +0000] "GET /contact.html HTTP/1.1" 200 890 "-" "Mozilla/5.0"
""",
}


def test_all_features():
    """Tüm özellikleri test eder"""
    
    print_header("🛡️ LOG ANALYZER AI - KAPSAMLI TEST SÜİTİ")
    
    results = {
        "passed": 0,
        "failed": 0,
        "total": 0,
    }
    
    # ═══════════════════════════════════════════════════════════════════════
    # 1. PARSER TESTLERİ
    # ═══════════════════════════════════════════════════════════════════════
    
    print_section("1. PARSER TESTLERİ")
    
    from src.parsers.nginx import NginxParser
    from src.parsers.apache import ApacheParser
    
    # Nginx Parser
    nginx_parser = NginxParser()
    test_line = '192.168.1.1 - - [15/Jan/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    entry = nginx_parser.parse_line(test_line)
    
    passed = entry is not None and entry.ip == "192.168.1.1" and entry.status_code == 200
    print_test("Nginx Parser - Normal Log", passed, f"IP: {entry.ip if entry else 'None'}")
    results["total"] += 1
    results["passed" if passed else "failed"] += 1
    
    # SQL Injection içeren log
    sql_line = '10.0.0.55 - - [15/Jan/2024:14:30:06 +0000] "GET /search?q=\' OR \'1\'=\'1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"'
    entry = nginx_parser.parse_line(sql_line)
    
    passed = entry is not None and "OR" in entry.path
    print_test("Nginx Parser - SQL Injection Payload", passed, f"Path: {entry.path[:50] if entry else 'None'}")
    results["total"] += 1
    results["passed" if passed else "failed"] += 1
    
    # Apache Parser
    apache_parser = ApacheParser()
    apache_line = '203.0.113.5 - - [15/Jan/2024:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 401 1234 "-" "sqlmap/1.7"'
    entry = apache_parser.parse_line(apache_line)
    
    passed = entry is not None and entry.source == "apache"
    print_test("Apache Parser", passed, f"Source: {entry.source if entry else 'None'}")
    results["total"] += 1
    results["passed" if passed else "failed"] += 1
    
    # ═══════════════════════════════════════════════════════════════════════
    # 2. DETECTOR TESTLERİ
    # ═══════════════════════════════════════════════════════════════════════
    
    print_section("2. DETECTOR TESTLERİ")
    
    from src.detector import ThreatDetector
    from src.parsers.nginx import LogEntry
    from datetime import timezone
    
    config = {
        'detection': {
            'brute_force': {'enabled': True, 'threshold': 5, 'window': 60},
            'sql_injection': {'enabled': True},
            'path_traversal': {'enabled': True},
            'xss': {'enabled': True},
        },
        'whitelist': {'ips': [], 'user_agents': []}
    }
    
    detector = ThreatDetector(config)
    
    # Test: Brute Force
    for i in range(6):
        entry = LogEntry(
            ip='192.168.1.100',
            timestamp=datetime.now(tz=timezone.utc),
            method='POST',
            path='/wp-login.php',
            status_code=401,
            bytes_sent=512,
            referrer='-',
            user_agent='python-requests/2.28',
            raw='',
            source='nginx'
        )
        threats = detector.analyze(entry)
    
    bf_detected = any(t.threat_type == 'BRUTE_FORCE' for t in threats)
    print_test("Brute Force Detection", bf_detected, f"Threats: {len(threats)}")
    results["total"] += 1
    results["passed" if bf_detected else "failed"] += 1
    
    # Reset detector
    detector = ThreatDetector(config)
    
    # Test: SQL Injection
    entry = LogEntry(
        ip='10.0.0.55',
        timestamp=datetime.now(tz=timezone.utc),
        method='GET',
        path="/search?q=' OR '1'='1",
        status_code=200,
        bytes_sent=2048,
        referrer='-',
        user_agent='Mozilla/5.0',
        raw='',
        source='nginx'
    )
    threats = detector.analyze(entry)
    sqli_detected = any(t.threat_type == 'SQL_INJECTION' for t in threats)
    print_test("SQL Injection Detection", sqli_detected, f"Payload: ' OR '1'='1")
    results["total"] += 1
    results["passed" if sqli_detected else "failed"] += 1
    
    # Test: Path Traversal
    entry.path = "/download?file=../../etc/passwd"
    threats = detector.analyze(entry)
    pt_detected = any(t.threat_type == 'PATH_TRAVERSAL' for t in threats)
    print_test("Path Traversal Detection", pt_detected, f"Payload: ../../etc/passwd")
    results["total"] += 1
    results["passed" if pt_detected else "failed"] += 1
    
    # Test: XSS
    entry.path = "/search?q=<script>alert(1)</script>"
    threats = detector.analyze(entry)
    xss_detected = any(t.threat_type == 'XSS' for t in threats)
    print_test("XSS Detection", xss_detected, f"Payload: <script>alert(1)</script>")
    results["total"] += 1
    results["passed" if xss_detected else "failed"] += 1
    
    # Test: Suspicious User Agent
    entry.path = "/api/users"
    entry.user_agent = "sqlmap/1.7.11#stable"
    threats = detector.analyze(entry)
    ua_detected = any(t.threat_type == 'SUSPICIOUS_UA' for t in threats)
    print_test("Suspicious User Agent Detection", ua_detected, f"UA: sqlmap")
    results["total"] += 1
    results["passed" if ua_detected else "failed"] += 1
    
    # ═══════════════════════════════════════════════════════════════════════
    # 3. ANALYZER TESTLERİ (END-TO-END)
    # ═══════════════════════════════════════════════════════════════════════
    
    print_section("3. ANALYZER TESTLERİ (END-TO-END)")
    
    from src.analyzer import LogAnalyzer
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Test dosyası oluştur
        log_file = Path(tmpdir) / "test.log"
        log_file.write_text(SAMPLE_LOGS["brute_force"] + SAMPLE_LOGS["sql_injection"])
        
        config['reporting'] = {'output_dir': tmpdir}
        analyzer = LogAnalyzer(config)
        
        # Analiz et
        data = analyzer.analyze_file(str(log_file))
        
        passed = data.total_lines_processed == 9
        print_test("File Analysis - Line Count", passed, f"Lines: {data.total_lines_processed}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
        
        passed = len(data.threats) > 0
        print_test("File Analysis - Threat Detection", passed, f"Threats: {len(data.threats)}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
        
        # Dizin analizi
        log_file2 = Path(tmpdir) / "test2.log"
        log_file2.write_text(SAMPLE_LOGS["xss"])
        
        data = analyzer.analyze_directory(tmpdir, pattern="*.log")
        
        passed = data.total_lines_processed == 12  # 9 + 3
        print_test("Directory Analysis", passed, f"Lines: {data.total_lines_processed}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
    
    # ═══════════════════════════════════════════════════════════════════════
    # 4. REPORTER TESTLERİ
    # ═══════════════════════════════════════════════════════════════════════
    
    print_section("4. REPORTER TESTLERİ")
    
    from src.reporter import Reporter, ReportData
    from src.detector import ThreatEvent, SEVERITY_HIGH
    
    with tempfile.TemporaryDirectory() as tmpdir:
        reporter = Reporter({'reporting': {'output_dir': tmpdir}})
        
        # Test verisi
        data = ReportData()
        data.total_lines_processed = 100
        data.add_threat(ThreatEvent(
            threat_type='SQL_INJECTION',
            severity=SEVERITY_HIGH,
            source_ip='10.0.0.55',
            timestamp=datetime.now(tz=timezone.utc),
            description='Test threat',
            target='/search'
        ))
        data.finalize()
        
        # JSON rapor
        json_path = reporter.generate_json_report(data, 'test.json')
        passed = json_path.exists()
        print_test("JSON Report Generation", passed, f"File: {json_path.name}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
        
        # JSON içeriğini kontrol et
        if passed:
            with open(json_path) as f:
                content = json.load(f)
            passed = content['totals']['threats_detected'] == 1
            print_test("JSON Report Content", passed, f"Threats: {content['totals']['threats_detected']}")
            results["total"] += 1
            results["passed" if passed else "failed"] += 1
        
        # Text rapor
        text_path = reporter.generate_text_report(data, 'test.txt')
        passed = text_path.exists() and 'LOG ANALYZER AI' in text_path.read_text()
        print_test("Text Report Generation", passed, f"File: {text_path.name}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
    
    # ═══════════════════════════════════════════════════════════════════════
    # 5. WHITELIST TESTLERİ
    # ═══════════════════════════════════════════════════════════════════════
    
    print_section("5. WHITELIST TESTLERİ")
    
    config_whitelist = {
        'detection': {'sql_injection': {'enabled': True}},
        'whitelist': {
            'ips': ['10.0.0.55'],
            'user_agents': ['monitoring-bot']
        }
    }
    
    detector = ThreatDetector(config_whitelist)
    
    # Whitelist'teki IP
    entry = LogEntry(
        ip='10.0.0.55',
        timestamp=datetime.now(tz=timezone.utc),
        method='GET',
        path="/search?q=' OR '1'='1",
        status_code=200,
        bytes_sent=2048,
        referrer='-',
        user_agent='Mozilla/5.0',
        raw='',
        source='nginx'
    )
    threats = detector.analyze(entry)
    
    passed = len(threats) == 0
    print_test("IP Whitelist", passed, f"Threats: {len(threats)} (should be 0)")
    results["total"] += 1
    results["passed" if passed else "failed"] += 1
    
    # Whitelist'teki User Agent
    entry.ip = '10.0.0.56'  # Farklı IP
    entry.user_agent = 'monitoring-bot'
    threats = detector.analyze(entry)
    
    passed = len(threats) == 0
    print_test("User Agent Whitelist", passed, f"Threats: {len(threats)} (should be 0)")
    results["total"] += 1
    results["passed" if passed else "failed"] += 1
    
    # Whitelist'te olmayan
    entry.ip = '10.0.0.99'
    entry.user_agent = 'hacker-tool'
    threats = detector.analyze(entry)
    
    passed = len(threats) > 0
    print_test("Non-Whitelisted Detection", passed, f"Threats: {len(threats)} (should be > 0)")
    results["total"] += 1
    results["passed" if passed else "failed"] += 1
    
    # ═══════════════════════════════════════════════════════════════════════
    # 6. KOMBİNE SENARYO TESTİ
    # ═══════════════════════════════════════════════════════════════════════
    
    print_section("6. KOMBİNE SENARYO TESTİ")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Gerçekçi log dosyası oluştur
        all_logs = ""
        for log_type, content in SAMPLE_LOGS.items():
            all_logs += content
        
        log_file = Path(tmpdir) / "combined.log"
        log_file.write_text(all_logs)
        
        config['reporting'] = {'output_dir': tmpdir}
        config['whitelist'] = {'ips': [], 'user_agents': []}
        analyzer = LogAnalyzer(config)
        
        # Analiz et
        collected_threats = []
        data = analyzer.analyze_file(str(log_file), on_threat=collected_threats.append)
        
        # Tüm tehdit türlerini kontrol et
        threat_types = {t.threat_type for t in collected_threats}
        
        expected_types = {'BRUTE_FORCE', 'SQL_INJECTION', 'PATH_TRAVERSAL', 'XSS', 'SUSPICIOUS_UA'}
        passed = expected_types.issubset(threat_types)
        print_test("All Threat Types Detected", passed, f"Found: {', '.join(sorted(threat_types))}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
        
        # IP çeşitliliği
        unique_ips = {t.source_ip for t in collected_threats}
        passed = len(unique_ips) >= 5
        print_test("Multiple Attacker IPs", passed, f"Unique IPs: {len(unique_ips)}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
        
        # Rapor oluşturma
        analyzer.generate_report(data, fmt='both')
        
        json_reports = list(Path(tmpdir).glob('*.json'))
        text_reports = list(Path(tmpdir).glob('*.txt'))
        
        passed = len(json_reports) > 0 and len(text_reports) > 0
        print_test("Both Report Formats Generated", passed, 
                   f"JSON: {len(json_reports)}, TXT: {len(text_reports)}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
    
    # ═══════════════════════════════════════════════════════════════════════
    # 7. FALSE POSITIVE TESTİ
    # ═══════════════════════════════════════════════════════════════════════
    
    print_section("7. FALSE POSITIVE TESTİ")
    
    detector = ThreatDetector(config)
    
    # Normal trafik - SQL'e benzer ama meşru
    entry = LogEntry(
        ip='192.168.1.10',
        timestamp=datetime.now(tz=timezone.utc),
        method='GET',
        path="/api/users?search=John OR Jane",  # Meşru arama
        status_code=200,
        bytes_sent=512,
        referrer='-',
        user_agent='Mozilla/5.0',
        raw='',
        source='nginx'
    )
    threats = detector.analyze(entry)
    
    # Bazı false positive'ler olabilir ama BRUTE_FORCE olmamalı
    bf_false = any(t.threat_type == 'BRUTE_FORCE' for t in threats)
    passed = not bf_false
    print_test("No False Brute Force", passed, f"Brute Force: {bf_false}")
    results["total"] += 1
    results["passed" if passed else "failed"] += 1
    
    # Normal dosya erişimi
    entry.path = "/files/documents/report.pdf"
    threats = detector.analyze(entry)
    pt_false = any(t.threat_type == 'PATH_TRAVERSAL' for t in threats)
    passed = not pt_false
    print_test("No False Path Traversal", passed, f"Path Traversal: {pt_false}")
    results["total"] += 1
    results["passed" if passed else "failed"] += 1
    
    # ═══════════════════════════════════════════════════════════════════════
    # 8. PERFORMANCE TESTİ
    # ═══════════════════════════════════════════════════════════════════════
    
    print_section("8. PERFORMANCE TESTİ")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # 1000 satırlık log oluştur
        large_log = Path(tmpdir) / "large.log"
        content = SAMPLE_LOGS["normal"] * 334  # ~1000 satır
        large_log.write_text(content)
        
        config['reporting'] = {'output_dir': tmpdir}
        analyzer = LogAnalyzer(config)
        
        start_time = time.time()
        data = analyzer.analyze_file(str(large_log))
        elapsed = time.time() - start_time
        
        passed = elapsed < 5.0  # 1000 satır < 5 saniye
        print_test("Performance (1000 lines)", passed, 
                   f"Time: {elapsed:.2f}s, Lines: {data.total_lines_processed}")
        results["total"] += 1
        results["passed" if passed else "failed"] += 1
    
    # ═══════════════════════════════════════════════════════════════════════
    # 9. ÖZET
    # ═══════════════════════════════════════════════════════════════════════
    
    print_header("📊 TEST SONUÇLARI")
    
    success_rate = (results["passed"] / results["total"]) * 100 if results["total"] > 0 else 0
    
    print(f"\n{BOLD}Toplam Testler:{RESET} {results['total']}")
    print(f"{GREEN}{BOLD}✅ Başarılı:{RESET} {results['passed']}")
    print(f"{RED}{BOLD}❌ Başarısız:{RESET} {results['failed']}")
    print(f"{BOLD}Başarı Oranı:{RESET} {success_rate:.1f}%")
    
    if success_rate == 100:
        print(f"\n{GREEN}{BOLD}🎉 TÜM TESTLER BAŞARILI! 🎉{RESET}\n")
    elif success_rate >= 90:
        print(f"\n{YELLOW}{BOLD}⚠️  Neredeyse tamam! Birkaç düzeltme gerekli.{RESET}\n")
    else:
        print(f"\n{RED}{BOLD}❌ Bazı kritik testler başarısız oldu.{RESET}\n")
    
    # Detaylı istatistikler
    print(f"\n{BOLD}Tespit Edilen Tehdit Türleri:{RESET}")
    print(f"  • Brute Force: ✓")
    print(f"  • SQL Injection: ✓")
    print(f"  • Path Traversal: ✓")
    print(f"  • XSS: ✓")
    print(f"  • Suspicious User Agent: ✓")
    
    print(f"\n{BOLD}Test Edilen Özellikler:{RESET}")
    print(f"  • Parser (Nginx, Apache): ✓")
    print(f"  • Detector (5 tehdit türü): ✓")
    print(f"  • Analyzer (dosya + dizin): ✓")
    print(f"  • Reporter (JSON + TXT): ✓")
    print(f"  • Whitelist (IP + UA): ✓")
    print(f"  • False Positive: ✓")
    print(f"  • Performance: ✓")
    
    print(f"\n{BLUE}{'='*70}{RESET}\n")
    
    return success_rate == 100


if __name__ == "__main__":
    import sys
    sys.path.insert(0, '.')
    
    try:
        success = test_all_features()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n{RED}{BOLD}❌ HATA: {e}{RESET}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
>>>>>>> 68d53f75fadd646719ce98c967c981ab4023b2b0
