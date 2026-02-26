#!/usr/bin/env python3
"""Canlı İzleme (Watch) Otomatik Test

Tek komutla çalışır — 2 terminal gerekmez.
Arka planda log yazar, watch gerçek zamanlı tespit eder.

Kullanım:
    python test_watch_demo.py
"""

import os
import sys
import time
import random
import tempfile
import threading
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.analyzer import LogAnalyzer
from src.detector import ThreatEvent

CONFIG = {
    "detection": {
        "brute_force": {"enabled": True, "threshold": 3, "window": 60},
        "sql_injection": {"enabled": True},
        "path_traversal": {"enabled": True},
        "xss": {"enabled": True},
        "suspicious_ua": {"enabled": True},
    },
    "whitelist": {"ips": [], "user_agents": []},
}

# ── Nginx formatında saldırı satırları ───────────────────────────────────────
def _ts():
    return datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")

def _ip():
    return f"{random.randint(100,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

ATTACK_SEQUENCE = [
    ("NORMAL",          lambda: f'10.0.0.1 - - [{_ts()}] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 Chrome/120"\n'),
    ("SQL_INJECTION",   lambda: f'{_ip()} - - [{_ts()}] "GET /search?q=\' UNION SELECT * FROM users-- HTTP/1.1" 200 2048 "-" "Mozilla/5.0"\n'),
    ("SUSPICIOUS_UA",   lambda: f'{_ip()} - - [{_ts()}] "GET /admin HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n'),
    ("PATH_TRAVERSAL",  lambda: f'{_ip()} - - [{_ts()}] "GET /download?file=../../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.88"\n'),
    ("XSS",             lambda: f'{_ip()} - - [{_ts()}] "GET /comment?text=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'),
    ("NORMAL",          lambda: f'10.0.0.2 - - [{_ts()}] "GET /style.css HTTP/1.1" 200 8192 "-" "Mozilla/5.0 Safari/605.1"\n'),
    ("BRUTE_FORCE #1",  lambda: f'198.51.100.77 - - [{_ts()}] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.31"\n'),
    ("BRUTE_FORCE #2",  lambda: f'198.51.100.77 - - [{_ts()}] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.31"\n'),
    ("BRUTE_FORCE #3",  lambda: f'198.51.100.77 - - [{_ts()}] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.31"\n'),
    ("SQLi (encoded)",  lambda: f'{_ip()} - - [{_ts()}] "GET /dvwa/vulnerabilities/sqli/?id=1%27+union+select+1,+table_name+from+information_schema.tables HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n'),
    ("NIKTO",           lambda: f'{_ip()} - - [{_ts()}] "GET /cgi-bin/test-cgi HTTP/1.1" 404 0 "-" "Nikto/2.1.6"\n'),
    ("NORMAL",          lambda: f'10.0.0.3 - - [{_ts()}] "GET /api/v1/products?page=2 HTTP/1.1" 200 4096 "-" "Mozilla/5.0 Firefox/121"\n'),
]

# ── Thread-safe counter ──────────────────────────────────────────────────────
threat_count = 0
lock = threading.Lock()

def on_threat(threat: ThreatEvent):
    global threat_count
    with lock:
        threat_count += 1
    colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[96m", "LOW": "\033[92m"}
    c = colors.get(threat.severity, "")
    print(f"  🚨 {c}[{threat.severity}]\033[0m {threat.threat_type} | {threat.source_ip} | {threat.description}")


def writer(filepath):
    """Arka planda log dosyasına yazar."""
    time.sleep(0.5)
    print(f"\n  📝 Saldırı logları yazılıyor...\n")
    for label, gen_fn in ATTACK_SEQUENCE:
        line = gen_fn()
        with open(filepath, "a") as f:
            f.write(line)
            f.flush()
        icon = "⚪" if "NORMAL" in label else "🔴"
        print(f"  {icon} Yazıldı → {label}")
        time.sleep(0.8)
    print(f"\n  ✅ Tüm loglar yazıldı.\n")
    time.sleep(2)


def main():
    print(f"\n{'='*60}")
    print(f"  🛡️  CANLI İZLEME (WATCH) DEMO")
    print(f"{'='*60}\n")

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    tmp.close()
    filepath = tmp.name
    print(f"  📄 Geçici log: {filepath}")
    print(f"{'─'*60}")

    analyzer = LogAnalyzer(CONFIG)

    # Writer thread
    t = threading.Thread(target=writer, args=(filepath,), daemon=True)
    t.start()

    # Auto-stop: writer bitince watch'u durdur
    def stopper():
        t.join()
        time.sleep(2)
        analyzer.stop_watching()

    threading.Thread(target=stopper, daemon=True).start()

    # Watch başlat
    try:
        analyzer.watch_file(filepath, "nginx", on_threat=on_threat, poll_interval=0.2)
    except KeyboardInterrupt:
        analyzer.stop_watching()

    # Sonuçlar
    print(f"{'─'*60}")
    total = len(ATTACK_SEQUENCE)
    attacks = sum(1 for label, _ in ATTACK_SEQUENCE if "NORMAL" not in label)
    print(f"  📊 SONUÇLAR")
    print(f"  {'─'*40}")
    print(f"  Yazılan satır     : {total}")
    print(f"  Saldırı satırı    : {attacks}")
    print(f"  Normal satır      : {total - attacks}")
    print(f"  Tespit edilen     : {threat_count}")
    print()

    if threat_count >= attacks - 1:
        print(f"  🎉 CANLI İZLEME BAŞARILI!")
    else:
        print(f"  ⚠️  Beklenen: ~{attacks}, Tespit: {threat_count}")
    print(f"{'='*60}\n")

    os.unlink(filepath)
    return 0 if threat_count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
