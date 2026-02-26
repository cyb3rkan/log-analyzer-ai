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
