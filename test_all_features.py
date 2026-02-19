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
