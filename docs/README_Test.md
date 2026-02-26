# 🧪 Log Analyzer AI - Test Rehberi

## 📋 İçindekiler

- [Test Ortamı Kurulumu](#test-ortamı-kurulumu)
- [Unit Testler](#unit-testler)
- [Manuel Test Senaryoları](#manuel-test-senaryoları)
- [Test Verileri](#test-verileri)
- [Performance Testleri](#performance-testleri)
- [Güvenlik Testleri](#güvenlik-testleri)

---

## 🔧 Test Ortamı Kurulumu

### Bağımlılıkları Yükle

```bash
# Test bağımlılıkları (opsiyonel)
pip install pytest pytest-cov pytest-mock

# Temel bağımlılıklar
pip install -r requirements.txt
```

### Test Verilerini Hazırla

```bash
# Test log dosyası oluştur
mkdir -p test_data
cat > test_data/sample.log << 'EOF'
192.168.1.100 - - [15/Jan/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [15/Jan/2024:14:30:01 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:02 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:03 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:04 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:05 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
10.0.0.55 - - [15/Jan/2024:14:30:06 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
10.0.0.56 - - [15/Jan/2024:14:30:07 +0000] "GET /files/../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.88"
10.0.0.57 - - [15/Jan/2024:14:30:08 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
10.0.0.58 - - [15/Jan/2024:14:30:09 +0000] "GET /api/users HTTP/1.1" 200 512 "-" "sqlmap/1.7.11"
EOF
```

---

## 🧪 Unit Testler

### pytest ile Otomatik Testler

```bash
# Tüm testleri çalıştır
pytest tests/ -v

# Sadece parser testleri
pytest tests/test_parsers.py -v

# Sadece detector testleri
pytest tests/test_detector.py -v

# Coverage raporu ile
pytest tests/ --cov=src --cov-report=html
# Rapor: htmlcov/index.html

# Belirli bir test fonksiyonu
pytest tests/test_detector.py::TestBruteForceDetection::test_threat_at_threshold -v
```

### Manuel Test Çalıştırma (pytest olmadan)

```bash
# Parser testleri
python -c "
import sys
sys.path.insert(0, '.')
from src.parsers.nginx import NginxParser

line = '192.168.1.1 - - [15/Jan/2024:14:30:00 +0000] \"GET /index.html HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"'
p = NginxParser()
entry = p.parse_line(line)
assert entry is not None
assert entry.ip == '192.168.1.1'
assert entry.status_code == 200
print('[OK] NginxParser test passed!')
"

# Detector testleri
python -c "
import sys
from datetime import datetime, timezone
sys.path.insert(0, '.')
from src.parsers.nginx import LogEntry
from src.detector import ThreatDetector

config = {
    'detection': {
        'sql_injection': {'enabled': True},
        'brute_force': {'enabled': True, 'threshold': 5, 'window': 60}
    },
    'whitelist': {'ips': [], 'user_agents': []}
}

d = ThreatDetector(config)
entry = LogEntry(
    ip='10.0.0.55',
    timestamp=datetime.now(tz=timezone.utc),
    method='GET',
    path=\"/search?q=' OR '1'='1\",
    status_code=200,
    bytes_sent=1024,
    referrer='-',
    user_agent='Mozilla/5.0',
    raw='',
    source='nginx'
)

threats = d.analyze(entry)
sqli = [t for t in threats if t.threat_type == 'SQL_INJECTION']
assert len(sqli) >= 1
print('[OK] SQL Injection detection test passed!')
"
```

---

## 📝 Manuel Test Senaryoları

### Senaryo 1: Temel Log Analizi

**Amaç:** Tek dosya analizinin doğru çalıştığını doğrula

```bash
# Test dosyası oluştur
cat > test.log << 'EOF'
127.0.0.1 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
127.0.0.1 - - [15/Jan/2024:10:00:01 +0000] "GET /about.html HTTP/1.1" 200 567 "-" "Mozilla/5.0"
EOF

# Analiz et
python log_analyzer.py analyze --file test.log

# Beklenen çıktı:
# ✅ 2 satır işlendi
# ✅ Tehdit tespit edilmedi (normal trafik)
# ✅ Rapor oluşturuldu
```

**✅ Test başarılı:** Hiçbir tehdit tespit edilmedi, 2 satır işlendi

**❌ Test başarısız:** Hata mesajı veya beklenmeyen tehdit tespiti

---

### Senaryo 2: Brute Force Tespiti

**Amaç:** Brute force saldırısının doğru tespit edildiğini doğrula

```bash
# Brute force test dosyası oluştur
cat > brute_force.log << 'EOF'
203.0.113.10 - - [15/Jan/2024:14:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
203.0.113.10 - - [15/Jan/2024:14:00:01 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
203.0.113.10 - - [15/Jan/2024:14:00:02 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
203.0.113.10 - - [15/Jan/2024:14:00:03 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
203.0.113.10 - - [15/Jan/2024:14:00:04 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
203.0.113.10 - - [15/Jan/2024:14:00:05 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
203.0.113.10 - - [15/Jan/2024:14:00:06 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
203.0.113.10 - - [15/Jan/2024:14:00:07 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
EOF

# Analiz et
python log_analyzer.py analyze --file brute_force.log

# Beklenen çıktı:
# 🔴 HIGH - BRUTE_FORCE
# Source: 203.0.113.10
# Target: /wp-login.php
# Attempts: 8 in 60 seconds
```

**✅ Test başarılı:** Brute force tespit edildi, kaynak IP doğru

**❌ Test başarısız:** Brute force tespit edilmedi veya yanlış IP

---

### Senaryo 3: SQL Injection Tespiti

**Amaç:** Çeşitli SQL injection pattern'lerinin tespit edildiğini doğrula

```bash
# SQL injection test dosyası
cat > sqli.log << 'EOF'
10.0.0.100 - - [15/Jan/2024:15:00:00 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
10.0.0.101 - - [15/Jan/2024:15:00:01 +0000] "GET /api/users?id=1 UNION SELECT * FROM passwords HTTP/1.1" 200 512 "-" "curl/7.88"
10.0.0.102 - - [15/Jan/2024:15:00:02 +0000] "GET /product?id=1'; DROP TABLE users-- HTTP/1.1" 200 256 "-" "python-requests/2.28"
EOF

python log_analyzer.py analyze --file sqli.log

# Beklenen: 3 SQL injection tespiti
```

**Test kontrol listesi:**
- [ ] `' OR '1'='1` tespit edildi
- [ ] `UNION SELECT` tespit edildi
- [ ] `DROP TABLE` tespit edildi

---

### Senaryo 4: Path Traversal Tespiti

```bash
cat > path_traversal.log << 'EOF'
192.168.50.10 - - [15/Jan/2024:16:00:00 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.88"
192.168.50.11 - - [15/Jan/2024:16:00:01 +0000] "GET /files/..\..\windows\system32\config\sam HTTP/1.1" 404 256 "-" "Mozilla/5.0"
192.168.50.12 - - [15/Jan/2024:16:00:02 +0000] "GET /static/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 404 256 "-" "python-requests/2.28"
EOF

python log_analyzer.py analyze --file path_traversal.log

# Beklenen: 3 path traversal tespiti
```

---

### Senaryo 5: XSS Tespiti

```bash
cat > xss.log << 'EOF'
172.16.0.50 - - [15/Jan/2024:17:00:00 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
172.16.0.51 - - [15/Jan/2024:17:00:01 +0000] "GET /profile?name=<img src=x onerror=alert(1)> HTTP/1.1" 200 512 "-" "curl/7.88"
172.16.0.52 - - [15/Jan/2024:17:00:02 +0000] "GET /redirect?url=javascript:alert(1) HTTP/1.1" 200 256 "-" "python-requests/2.28"
EOF

python log_analyzer.py analyze --file xss.log

# Beklenen: 3 XSS tespiti
```

---

### Senaryo 6: Whitelist İşlevselliği

```bash
# config.yaml'da whitelist ekle
cat > config_whitelist.yaml << 'EOF'
detection:
  sql_injection:
    enabled: true
whitelist:
  ips:
    - 10.0.0.55
  user_agents:
    - monitoring-bot
EOF

# Whitelist'teki IP ile test
cat > whitelist_test.log << 'EOF'
10.0.0.55 - - [15/Jan/2024:18:00:00 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
10.0.0.56 - - [15/Jan/2024:18:00:01 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
EOF

python log_analyzer.py analyze --file whitelist_test.log --config config_whitelist.yaml

# Beklenen: Sadece 10.0.0.56 için tehdit (10.0.0.55 whitelist'te)
```

**✅ Test başarılı:** Whitelist'teki IP için tehdit yok

---

### Senaryo 7: Gerçek Zamanlı İzleme

```bash
# Terminal 1: İzleme başlat
python log_analyzer.py watch --file /tmp/live.log

# Terminal 2: Canlı log üret
while true; do
  echo "$(date -u +'%d/%b/%Y:%H:%M:%S +0000') 192.168.1.100 - - [$(date -u +'%d/%b/%Y:%H:%M:%S +0000')] \"GET /index.html HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"" >> /tmp/live.log
  sleep 2
done

# Terminal 3: SQL injection gönder
echo "$(date -u +'%d/%b/%Y:%H:%M:%S +0000') 10.0.0.55 - - [$(date -u +'%d/%b/%Y:%H:%M:%S +0000')] \"GET /search?q=' OR '1'='1 HTTP/1.1\" 200 2048 \"-\" \"Mozilla/5.0\"" >> /tmp/live.log
```

**Beklenen:** Terminal 1'de SQL injection anında tespit edilmeli

---

### Senaryo 8: Dashboard Testi

```bash
# Dashboard'u başlat
python log_analyzer.py dashboard --port 8080 --file test_data/sample.log

# Tarayıcıda aç
# http://localhost:8080

# Test adımları:
# 1. Dashboard yükleniyor mu? ✓
# 2. İstatistikler güncelleniyor mu? ✓
# 3. Tehdit feed akıyor mu? ✓
# 4. Top IP'ler listesi doğru mu? ✓
# 5. Tehdit türleri grafiği doğru mu? ✓
```

---

## 📊 Test Verileri

### Hazır Test Dosyaları

```bash
# Geniş kapsamlı test seti oluştur
python << 'EOF'
import random
from datetime import datetime, timedelta

ips = ["192.168.1.100", "10.0.0.55", "203.0.113.10", "172.16.0.50"]
paths = ["/index.html", "/wp-login.php", "/api/users", "/search?q=test"]
sql_payloads = ["' OR '1'='1", "UNION SELECT", "DROP TABLE"]
xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

with open("comprehensive_test.log", "w") as f:
    base_time = datetime(2024, 1, 15, 14, 0, 0)
    
    # Normal trafik
    for i in range(100):
        ts = base_time + timedelta(seconds=i)
        ip = random.choice(ips[:2])
        path = random.choice(paths[:2])
        f.write(f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n')
    
    # Brute force
    for i in range(20):
        ts = base_time + timedelta(seconds=100 + i)
        f.write(f'203.0.113.10 - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"\n')
    
    # SQL injection
    for i, payload in enumerate(sql_payloads):
        ts = base_time + timedelta(seconds=120 + i)
        f.write(f'10.0.0.55 - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /search?q={payload} HTTP/1.1" 200 2048 "-" "Mozilla/5.0"\n')
    
    # XSS
    for i, payload in enumerate(xss_payloads):
        ts = base_time + timedelta(seconds=130 + i)
        f.write(f'172.16.0.50 - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /search?q={payload} HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n')

print("✅ comprehensive_test.log oluşturuldu (125 satır)")
EOF

# Test et
python log_analyzer.py analyze --file comprehensive_test.log
```

---

## ⚡ Performance Testleri

### Büyük Dosya Testi

```bash
# 100K satırlık test dosyası oluştur
python << 'EOF'
from datetime import datetime, timedelta
base = datetime(2024, 1, 15, 0, 0, 0)
with open("large_test.log", "w") as f:
    for i in range(100000):
        ts = base + timedelta(seconds=i)
        ip = f"192.168.{i%255}.{i%255}"
        f.write(f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n')
print("✅ 100K satırlık dosya oluşturuldu")
EOF

# Performans ölçümü
time python log_analyzer.py analyze --file large_test.log --report-only

# Beklenen: 100K satır < 30 saniye
```

### Memory Profiling

```bash
# memory_profiler yükle (opsiyonel)
pip install memory_profiler

# Memory profiling
python -m memory_profiler log_analyzer.py analyze --file large_test.log
```

---

## 🔐 Güvenlik Testleri

### False Positive Testi

```bash
# Meşru trafik - False positive olmamalı
cat > legitimate.log << 'EOF'
192.168.1.10 - - [15/Jan/2024:10:00:00 +0000] "GET /api/users?search=John OR Jane HTTP/1.1" 200 512 "-" "Mozilla/5.0"
192.168.1.11 - - [15/Jan/2024:10:00:01 +0000] "GET /files/documents/report.pdf HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
192.168.1.12 - - [15/Jan/2024:10:00:02 +0000] "GET /script-loader.js HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
EOF

python log_analyzer.py analyze --file legitimate.log

# Beklenen: Minimal veya sıfır tehdit
```

### Encoding Bypass Testi

```bash
# URL encoding bypass denemeleri
cat > encoding_test.log << 'EOF'
10.0.0.100 - - [15/Jan/2024:11:00:00 +0000] "GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 2048 "-" "curl/7.88"
10.0.0.101 - - [15/Jan/2024:11:00:01 +0000] "GET /files/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 404 256 "-" "curl/7.88"
10.0.0.102 - - [15/Jan/2024:11:00:02 +0000] "GET /search?q=%3cscript%3ealert(1)%3c%2fscript%3e HTTP/1.1" 200 1024 "-" "curl/7.88"
EOF

python log_analyzer.py analyze --file encoding_test.log

# Beklenen: Tüm encoded payload'lar tespit edilmeli
```

---

## 📈 Test Metrikleri

### Başarı Kriterleri

| Metrik | Hedef | Test Komutu |
|--------|-------|-------------|
| **Tespit Oranı** | >95% | Manuel test senaryolarının toplamı |
| **False Positive** | <5% | Legitimate trafik testi |
| **Performance** | 100K satır <30s | Büyük dosya testi |
| **Memory** | <500MB | memory_profiler |
| **Coverage** | >80% | pytest --cov |

### Test Raporu Şablonu

```bash
# Test raporu oluştur
cat > test_report.md << 'EOF'
# Test Raporu - $(date +%Y-%m-%d)

## Test Özeti
- ✅ Parser testleri: PASS
- ✅ Detector testleri: PASS
- ✅ Integration testleri: PASS
- ⚠️ Performance: PASS (22 saniye)

## Tespit İstatistikleri
- Brute Force: 10/10 (100%)
- SQL Injection: 9/10 (90%)
- XSS: 10/10 (100%)
- Path Traversal: 10/10 (100%)

## False Positive
- Meşru trafik: 0/100 (0%)

## Notlar
- SQL injection: Bir encoding edge case kaçırıldı
- Action: Pattern regex'i güncellendi
EOF

cat test_report.md
```

---

## 🐛 Bilinen Sorunlar ve Çözümler

### Sorun: Tespit Edilmeyen SQL Injection

**Belirti:** Bazı SQL injection payload'ları tespit edilmiyor

**Debug:**
```bash
python << 'EOF'
import sys
sys.path.insert(0, '.')
from src.detector import SQL_INJECTION_PATTERNS

payload = "YOUR_MISSED_PAYLOAD"
for i, pattern in enumerate(SQL_INJECTION_PATTERNS):
    if pattern.search(payload):
        print(f"✅ Pattern {i} matched: {pattern.pattern}")
    else:
        print(f"❌ Pattern {i} no match: {pattern.pattern}")
EOF
```

**Çözüm:** Yeni pattern ekle veya mevcut pattern'i güncelle

---

### Sorun: Yüksek Memory Kullanımı

**Debug:**
```bash
# Memory profiling
python -m memory_profiler << 'EOF'
from log_analyzer import *
import sys
sys.argv = ['log_analyzer.py', 'analyze', '--file', 'large_test.log']
cli()
EOF
```

**Çözüm:** Streaming parse kullan, cache limitlerini ayarla

---

## ✅ Test Checklist

Test öncesi kontrol:

- [ ] Virtual environment aktif
- [ ] Bağımlılıklar yüklü (`pip list`)
- [ ] config.yaml mevcut
- [ ] Test verileri hazır
- [ ] Log dosya izinleri doğru

Test sonrası kontrol:

- [ ] Tüm testler geçti
- [ ] Rapor dosyaları oluştu
- [ ] Memory leak yok
- [ ] Performans hedefleri karşılandı
- [ ] Test raporu dokümante edildi

---

## 📞 Destek

Test ile ilgili sorunlar için:
- GitHub Issues: https://github.com/cyb3rkan/log-analyzer-ai/issues
- Test loglarını paylaş
- Hata mesajlarını ekle
- Ortam bilgilerini belirt (Python versiyon, OS, vb.)

---

**Happy Testing! 🧪✨**
