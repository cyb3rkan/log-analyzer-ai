#!/usr/bin/env python3
"""Sahte Saldırı Log Üretici — Canlı İzleme Testi İçin

Bu script nginx formatında gerçekçi saldırı logları üretir.
Watch modu ile birlikte kullanılır.

Kullanım (2 terminal gerekli):

  Terminal 1 — Watch başlat:
    python log_analyzer.py watch --file access.log

  Terminal 2 — Log üret:
    python live_log_generator.py

Her saniye bir log satırı yazar. Ctrl+C ile durur.
"""

import os
import random
import time
from datetime import datetime, timezone

LOG_FILE = "access.log"

# ── Gerçekçi Saldırı Payloadları ────────────────────────────────────────────

ATTACKS = [
    # (ağırlık, label, ip, method, path, status, ua)

    # Normal trafik (daha sık)
    (30, "NORMAL",
     None, "GET", "/index.html", 200, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    (20, "NORMAL",
     None, "GET", "/style.css", 200, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"),
    (15, "NORMAL",
     None, "GET", "/api/v1/products?page=2&limit=20", 200, "Mozilla/5.0 Firefox/121.0"),
    (10, "NORMAL",
     None, "POST", "/api/v1/login", 200, "okhttp/4.12.0"),

    # SQL Injection — plain
    (5, "SQL_INJECTION",
     None, "GET", "/search?q=' OR '1'='1'--", 200, "Mozilla/5.0"),
    (5, "SQL_INJECTION",
     None, "GET", "/search?q=1 UNION SELECT username,password FROM users--", 200, "Mozilla/5.0"),
    (4, "SQL_INJECTION",
     None, "GET", "/products?id=1; DROP TABLE orders--", 200, "Mozilla/5.0"),

    # SQL Injection — URL-encoded (sqlmap tarzı)
    (5, "SQL_INJECTION (encoded)",
     None, "GET", "/dvwa/vulnerabilities/sqli/?id=1%27+union+select+1,+table_name+from+information_schema.tables+%23", 200, "sqlmap/1.7"),
    (4, "SQL_INJECTION (encoded)",
     None, "GET", "/dvwa/vulnerabilities/sqli/?id=5%27+OR+1%3D1%23&Submit=Submit", 200, "sqlmap/1.7"),
    (3, "SQL_INJECTION (encoded)",
     None, "GET", "/dvwa/vulnerabilities/sqli/?id=1%27+union+select+database()%2C1+%23", 200, "sqlmap/1.7"),

    # XSS
    (4, "XSS",
     None, "GET", "/comment?text=<script>alert(document.cookie)</script>", 200, "Mozilla/5.0"),
    (3, "XSS",
     None, "GET", "/search?q=<img+src=x+onerror=alert(1)>", 200, "Mozilla/5.0"),

    # Path Traversal
    (4, "PATH_TRAVERSAL",
     None, "GET", "/download?file=../../../etc/passwd", 404, "curl/7.88.1"),
    (3, "PATH_TRAVERSAL",
     None, "GET", "/static/..%2f..%2f..%2fetc%2fshadow", 403, "Mozilla/5.0"),

    # Brute Force (failed logins)
    (6, "BRUTE_FORCE",
     "198.51.100.77", "POST", "/wp-login.php", 401, "python-requests/2.31.0"),
    (5, "BRUTE_FORCE",
     "198.51.100.77", "POST", "/admin/login", 403, "python-requests/2.31.0"),

    # Suspicious User Agents
    (4, "SUSPICIOUS_UA (sqlmap)",
     None, "GET", "/admin", 200, "sqlmap/1.7.11#stable"),
    (3, "SUSPICIOUS_UA (nikto)",
     None, "GET", "/cgi-bin/test-cgi", 404, "Nikto/2.1.6"),
    (2, "SUSPICIOUS_UA (nmap)",
     None, "GET", "/", 200, "Nmap Scripting Engine"),
    (2, "SUSPICIOUS_UA (dirbuster)",
     None, "GET", "/.env", 404, "DirBuster-1.0-RC1"),
]

# Saldırgan IP havuzu (her çalıştırmada farklı)
ATTACKER_IPS = [f"{random.randint(100,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                for _ in range(8)]
NORMAL_IPS = [f"10.0.{random.randint(0,10)}.{random.randint(1,254)}" for _ in range(5)]


def random_ip(is_normal: bool) -> str:
    if is_normal:
        return random.choice(NORMAL_IPS)
    return random.choice(ATTACKER_IPS)


def nginx_timestamp() -> str:
    """Nginx/Apache combined format timestamp."""
    return datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def generate_line() -> tuple[str, str]:
    """Ağırlıklı rastgele bir log satırı üret. (label, line) döner."""
    weights = [a[0] for a in ATTACKS]
    choice = random.choices(ATTACKS, weights=weights, k=1)[0]
    _, label, fixed_ip, method, path, status, ua = choice

    ip = fixed_ip or random_ip("NORMAL" in label)
    ts = nginx_timestamp()
    size = random.randint(100, 8192)

    line = f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    return label, line


def main():
    # Dosya yoksa oluştur
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    print(f"\n{'='*60}")
    print(f"  📝 Sahte Log Üretici")
    print(f"{'='*60}")
    print(f"  Dosya : {os.path.abspath(LOG_FILE)}")
    print(f"  Format: nginx combined")
    print(f"  Hız   : ~1 satır/saniye")
    print(f"  Dur   : Ctrl+C")
    print(f"{'='*60}")
    print()
    print(f"  Başka bir terminalde watch'u başlat:")
    print(f"  → python log_analyzer.py watch --file {LOG_FILE}")
    print()
    print(f"{'─'*60}\n")

    count = 0
    threat_count = 0

    try:
        while True:
            label, line = generate_line()
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()

            count += 1
            is_attack = "NORMAL" not in label

            if is_attack:
                threat_count += 1
                print(f"  🔴 #{count:3d} | {label}")
            else:
                print(f"  ⚪ #{count:3d} | {label}")

            # Rastgele hız: normal trafik hızlı, saldırı bazen art arda
            if is_attack and random.random() < 0.3:
                time.sleep(0.2)  # Burst saldırı
            else:
                time.sleep(random.uniform(0.5, 1.5))

    except KeyboardInterrupt:
        print(f"\n{'─'*60}")
        print(f"  📊 Toplam: {count} satır ({threat_count} saldırı, {count - threat_count} normal)")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
