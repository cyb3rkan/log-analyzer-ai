# 🔧 Log Analyzer AI - Sorun Giderme Rehberi

## 📋 İçindekiler

- [Kurulum Sorunları](#kurulum-sorunları)
- [Çalıştırma Sorunları](#çalıştırma-sorunları)
- [Tespit Sorunları](#tespit-sorunları)
- [Performance Sorunları](#performance-sorunları)
- [Alert Sorunları](#alert-sorunları)
- [Dashboard Sorunları](#dashboard-sorunları)
- [IP Bloklama Sorunları](#ip-bloklama-sorunları)

---

## 🚀 Kurulum Sorunları

### ❌ "Module not found" Hatası

**Belirti:**
```
ModuleNotFoundError: No module named 'click'
```

**Çözüm:**
```bash
# Virtual environment aktif mi kontrol et
which python
# Çıktı: /path/to/venv/bin/python olmalı

# Eğer sistem Python'u gösteriyorsa:
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate     # Windows

# Bağımlılıkları tekrar yükle
pip install -r requirements.txt

# Hala çözülmezse:
pip install click pyyaml requests flask numpy pandas scikit-learn
```

---

### ❌ "Permission denied" - requirements.txt

**Belirti:**
```
ERROR: Could not install packages due to an EnvironmentError: [Errno 13] Permission denied
```

**Çözüm:**
```bash
# Virtual environment kullan (önerilen)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Veya --user flag kullan
pip install --user -r requirements.txt

# En son çare (önerilmez)
sudo pip install -r requirements.txt
```

---

### ❌ "No matching distribution found for rich"

**Belirti:**
```
ERROR: No matching distribution found for rich
```

**Çözüm:**
```bash
# Python versiyonunu kontrol et
python --version
# 3.11+ olmalı

# pip'i güncelle
pip install --upgrade pip

# Paket adını doğrula
pip search rich

# Eğer internet problemi varsa:
pip install rich --no-cache-dir
```

---

## 🏃 Çalıştırma Sorunları

### ❌ "config.yaml not found"

**Belirti:**
```
FileNotFoundError: config.yaml not found
```

**Çözüm:**
```bash
# Örnek konfigürasyonu kopyala
cp config.example.yaml config.yaml

# Mevcut mu kontrol et
ls -la config.yaml

# Farklı bir yol belirt
python log_analyzer.py --config /path/to/config.yaml analyze --file test.log
```

---

### ❌ "Log file not found"

**Belirti:**
```
FileNotFoundError: /var/log/nginx/access.log
```

**Çözüm:**
```bash
# Dosya gerçekten var mı?
ls -la /var/log/nginx/access.log

# Okuma izniniz var mı?
cat /var/log/nginx/access.log | head -1

# İzin yoksa:
sudo chmod +r /var/log/nginx/access.log

# Veya kullanıcıyı log grubuna ekle
sudo usermod -a -G adm $USER
# Oturum kapat/aç gerekli
```

---

### ❌ "YAML parsing error"

**Belirti:**
```
yaml.scanner.ScannerError: mapping values are not allowed here
```

**Çözüm:**
```bash
# YAML syntax'ı kontrol et
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Yaygın hatalar:
# 1. Tab yerine space kullanın (2 veya 4 space)
# 2. Colon'dan sonra space: "key: value" ✅ "key:value" ❌
# 3. String'lerde özel karakter varsa tırnak kullanın

# Online YAML validator:
# https://www.yamllint.com/
```

---

### ❌ "ImportError: cannot import name 'LogEntry'"

**Belirti:**
```
ImportError: cannot import name 'LogEntry' from 'src.parsers.nginx'
```

**Çözüm:**
```bash
# Python path'i kontrol et
python -c "import sys; print('\n'.join(sys.path))"

# Proje kök dizininde mi çalıştırıyorsunuz?
pwd
# /path/to/log-analyzer-ai olmalı

# __pycache__ dosyalarını temizle
find . -type d -name __pycache__ -exec rm -rf {} +
find . -name "*.pyc" -delete

# Tekrar dene
python log_analyzer.py analyze --file test.log
```

---

## 🔍 Tespit Sorunları

### ❌ SQL Injection Tespit Edilmiyor

**Belirti:**
Log'da açık SQL injection var ama tespit edilmiyor

**Debug:**
```bash
# Log satırını manuel test et
python << 'EOF'
import sys
sys.path.insert(0, '.')
from src.parsers.nginx import NginxParser
from src.detector import ThreatDetector

line = "YOUR_LOG_LINE_HERE"
parser = NginxParser()
entry = parser.parse_line(line)

if entry:
    print(f"✅ Parsed: {entry.path}")
    config = {
        'detection': {'sql_injection': {'enabled': True}},
        'whitelist': {'ips': [], 'user_agents': []}
    }
    detector = ThreatDetector(config)
    threats = detector.analyze(entry)
    print(f"Threats: {[t.threat_type for t in threats]}")
else:
    print("❌ Parse failed")
EOF
```

**Çözüm:**
```yaml
# config.yaml'da SQL injection aktif mi kontrol et
detection:
  sql_injection:
    enabled: true  # false olmasın!
```

**İleri Seviye Debug:**
```python
# Hangi pattern'lerin match etmediğini bul
from src.detector import SQL_INJECTION_PATTERNS

payload = "YOUR_SQL_PAYLOAD"
for i, pattern in enumerate(SQL_INJECTION_PATTERNS):
    if pattern.search(payload):
        print(f"✅ Pattern {i} matched")
    else:
        print(f"❌ Pattern {i} no match: {pattern.pattern}")
```

---

### ❌ Çok Fazla False Positive

**Belirti:**
Meşru trafik tehdit olarak işaretleniyor

**Çözüm 1: Threshold'ları Artır**
```yaml
detection:
  brute_force:
    threshold: 200  # Varsayılan 100'den artır
    window: 120     # Pencereyi genişlet
```

**Çözüm 2: Whitelist Kullan**
```yaml
whitelist:
  ips:
    - 192.168.1.50  # Güvenilir admin IP
    - 10.0.0.0/8    # Internal network
  user_agents:
    - monitoring-bot
    - health-checker
```

**Çözüm 3: Spesifik Path'leri Hariç Tut**
```bash
# Custom detection logic ekle (gelişmiş)
# src/detector.py içinde _is_monitored_path() metodu
```

---

### ❌ Hiçbir Tehdit Tespit Edilmiyor

**Debug Checklist:**

```bash
# 1. Konfigürasyon doğru mu?
cat config.yaml | grep "enabled: true"

# 2. Log parsing çalışıyor mu?
python << 'EOF'
import sys
sys.path.insert(0, '.')
from src.parsers.nginx import NginxParser

with open('your_log_file.log') as f:
    parser = NginxParser()
    parsed_count = 0
    for line in f:
        entry = parser.parse_line(line)
        if entry:
            parsed_count += 1
            if parsed_count == 1:
                print(f"First entry: {entry.ip} -> {entry.path}")
    print(f"Total parsed: {parsed_count}")
EOF

# 3. Detector çalışıyor mu?
python log_analyzer.py analyze --file test.log --config config.yaml -v
# -v: verbose mode, detayları gösterir

# 4. Log formatı doğru mu?
# Nginx mi? Apache mi?
python log_analyzer.py analyze --file test.log --format apache
```

---

## ⚡ Performance Sorunları

### ❌ Çok Yavaş Analiz

**Belirti:**
100K satır > 2 dakika sürüyor

**Çözüm:**

**1. Streaming Parse Kullan**
```python
# Tüm dosyayı memory'ye yüklemek yerine
# Generator kullan (zaten implement edilmiş)
```

**2. AI Analizini Disable Et**
```yaml
ai:
  provider: openai
  analyze_threshold: high  # Sadece yüksek şüpheliler
```

**3. Paralel İşleme (gelişmiş)**
```bash
# Büyük dosyayı parçala
split -l 10000 large.log chunk_

# Her chunk'ı paralel analiz et
for chunk in chunk_*; do
  python log_analyzer.py analyze --file $chunk &
done
wait

# Raporları birleştir
cat reports/*.json | jq -s 'add'
```

**4. Index Kullan (çok büyük dosyalar için)**
```bash
# Sadece son N satırı analiz et
tail -100000 /var/log/nginx/access.log > recent.log
python log_analyzer.py analyze --file recent.log
```

---

### ❌ Yüksek Memory Kullanımı

**Belirti:**
```
MemoryError: Unable to allocate memory
```

**Debug:**
```bash
# Memory profiling
pip install memory_profiler
python -m memory_profiler log_analyzer.py analyze --file large.log
```

**Çözüm:**

**1. Batch Size Küçült**
```yaml
performance:
  batch_size: 1000  # Varsayılan 10000
```

**2. Cache Limitlerini Ayarla**
```yaml
performance:
  cache_size: 500   # Varsayılan 1000
```

**3. Threat History'yi Sınırla**
```python
# src/analyzer.py içinde
MAX_THREAT_HISTORY = 1000  # Eski tehditleri sil
```

---

## 📢 Alert Sorunları

### ❌ Slack Alert Gelmiyor

**Debug:**
```bash
# 1. Webhook URL doğru mu?
echo $SLACK_WEBHOOK

# 2. Manuel test
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test message from Log Analyzer AI"}' \
  $SLACK_WEBHOOK

# 3. Config doğru mu?
grep -A 3 "slack:" config.yaml
```

**Çözüm:**

```yaml
# config.yaml
response:
  alerts:
    slack:
      enabled: true  # false olmasın!
      webhook_url: "${SLACK_WEBHOOK}"
```

```bash
# .env dosyası
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**Network Problemi:**
```bash
# Proxy kullanıyor musunuz?
export https_proxy=http://proxy.example.com:8080

# Firewall engelliyor mu?
telnet hooks.slack.com 443
```

---

### ❌ Telegram Alert Gelmiyor

**Debug:**
```bash
# 1. Token ve Chat ID doğru mu?
echo $TELEGRAM_TOKEN
echo $TELEGRAM_CHAT_ID

# 2. Bot API'ye erişim var mı?
curl https://api.telegram.org/bot$TELEGRAM_TOKEN/getMe

# 3. Chat ID doğru mu?
curl https://api.telegram.org/bot$TELEGRAM_TOKEN/getUpdates

# 4. Manuel mesaj gönder
curl -X POST \
  https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage \
  -d chat_id=$TELEGRAM_CHAT_ID \
  -d text="Test from Log Analyzer AI"
```

**Yaygın Hatalar:**

1. **Bot'a mesaj göndermediniz:**
   - Önce bota `/start` gönderin

2. **Chat ID yanlış:**
   - Negatif olmalı: `-123456789`
   - Grup chat ID'si farklıdır

3. **Bot admin değil (grup için):**
   - Botu gruba admin olarak ekleyin

---

## 🖥️ Dashboard Sorunları

### ❌ Dashboard Açılmıyor

**Belirti:**
```
curl: (7) Failed to connect to localhost port 8080
```

**Debug:**
```bash
# 1. Dashboard çalışıyor mu?
ps aux | grep "log_analyzer.py dashboard"

# 2. Port dinleniyor mu?
netstat -tuln | grep 8080
# veya
lsof -i :8080

# 3. Firewall engelliyor mu?
sudo ufw status
sudo ufw allow 8080/tcp

# 4. Başka bir process kullanıyor mu?
sudo lsof -i :8080
# Başka process varsa öldür veya farklı port kullan
```

**Çözüm:**

```bash
# Farklı port dene
python log_analyzer.py dashboard --port 3000

# Sadece localhost'tan erişim
python log_analyzer.py dashboard --host 127.0.0.1 --port 8080

# Tüm interface'lerden erişim (dikkat: güvenlik riski)
python log_analyzer.py dashboard --host 0.0.0.0 --port 8080
```

---

### ❌ Dashboard Yavaş/Donuyor

**Belirti:**
Dashboard 10+ saniye yükleniyor veya donuyor

**Çözüm:**

**1. WebSocket Bağlantısı**
```bash
# flask-socketio yüklü mü?
pip list | grep socketio

# Yoksa yükle
pip install flask-socketio eventlet
```

**2. Polling Interval'ı Artır**
```javascript
// dashboard/templates/dashboard.html
const REFRESH_INTERVAL = 10000;  // 5000'den 10000'e
```

**3. Threat Feed Limitini Azalt**
```javascript
// dashboard/templates/dashboard.html
const MAX_FEED_ROWS = 50;  // 100'den 50'ye
```

---

### ❌ Dashboard'da Veriler Güncellenmiyor

**Debug:**
```bash
# Browser console'u aç (F12)
# Network tab → XHR istekleri görüyor musunuz?

# API endpoint'leri çalışıyor mu?
curl http://localhost:8080/api/stats
curl http://localhost:8080/api/threats
curl http://localhost:8080/api/top-ips
```

**Çözüm:**

```bash
# Backend loglarını kontrol et
python log_analyzer.py dashboard --port 8080 --file test.log -v
# -v: verbose, tüm requestleri gösterir

# Browser cache'i temizle
# Ctrl+Shift+R (hard refresh)
```

---

## 🔒 IP Bloklama Sorunları

### ❌ "Permission denied" - iptables

**Belirti:**
```
PermissionError: [Errno 1] Operation not permitted
```

**Çözüm:**
```bash
# Root yetkisi gerekli
sudo python log_analyzer.py watch --file access.log --auto-block

# Veya sudo'suz çalıştır (bloklama olmadan)
python log_analyzer.py watch --file access.log
# (auto-block config'de disabled olmalı)
```

---

### ❌ IP Bloklanmıyor

**Debug:**
```bash
# 1. Auto-block aktif mi?
grep -A 3 "auto_block:" config.yaml
# enabled: true olmalı

# 2. iptables yüklü mü?
which iptables

# 3. Manuel test
sudo iptables -I INPUT -s 1.2.3.4 -j DROP
sudo iptables -L -n | grep 1.2.3.4
sudo iptables -D INPUT -s 1.2.3.4 -j DROP

# 4. Firewall servisi çalışıyor mu?
sudo systemctl status iptables
# veya
sudo systemctl status firewalld
```

**Çözüm:**

```yaml
# config.yaml - method doğru mu?
response:
  auto_block:
    enabled: true
    method: iptables  # veya firewalld
```

```bash
# iptables için:
sudo apt-get install iptables  # Debian/Ubuntu
sudo yum install iptables      # RHEL/CentOS

# firewalld için:
sudo apt-get install firewalld
sudo systemctl start firewalld
```

---

### ❌ Bloklanan IP Tekrar Geliyor

**Belirti:**
IP bloklandı ama hala logda görünüyor

**Açıklama:**
- Bu normal! Bloklama etkili ancak:
  1. Log parser geçmiş logları okuyor (bloklama öncesi)
  2. Paketler firewall'a ulaşıyor ama drop ediliyor (log'a düşüyor)

**Doğrulama:**
```bash
# Bloklanan IP gerçekten bloklu mu?
sudo iptables -L -n | grep 203.0.113.10

# Ping atsın bakalım
ping 203.0.113.10  # Timeout vermeli

# Telnet ile test
telnet YOUR_SERVER_IP 80  # Connection refused
```

---

### ❌ Yanlış IP Bloklandı!

**Belirti:**
Meşru kullanıcı bloklandı

**Acil Çözüm:**
```bash
# Hemen bloku kaldır
sudo iptables -D INPUT -s BLOCKED_IP -j DROP

# Tüm blokları listele
sudo iptables -L INPUT -n --line-numbers

# Spesifik satırı sil
sudo iptables -D INPUT 5  # 5. kural
```

**Kalıcı Çözüm:**
```yaml
# Whitelist'e ekle
whitelist:
  ips:
    - LEGITIMATE_IP
```

```yaml
# Threshold'ları ayarla (daha toleranslı)
detection:
  brute_force:
    threshold: 200  # 100'den artır
```

---

## 🔍 Genel Debug İpuçları

### Verbose Mode Kullan

```bash
# Detaylı log çıktısı
python log_analyzer.py analyze --file test.log -v

# Python logging level
export LOG_LEVEL=DEBUG
python log_analyzer.py analyze --file test.log
```

---

### Log Dosyalarını İncele

```bash
# Analyzer logları
tail -f logs/analyzer.log

# Dashboard logları
tail -f logs/dashboard.log

# System logları
sudo tail -f /var/log/syslog | grep log-analyzer
```

---

### Test Ortamı Kur

```bash
# Production'ı etkilemeyen test ortamı
cp config.yaml config.test.yaml

# Test config'i düzenle
nano config.test.yaml
# - auto_block: false
# - test log dosyaları kullan

# Test et
python log_analyzer.py --config config.test.yaml analyze --file test.log
```

---

## 🆘 Hala Çözülmedi mi?

### Bilgi Topla

```bash
# System bilgileri
uname -a
python --version
pip --version

# Yüklü paketler
pip list

# Config dosyası (hassas bilgileri gizle!)
cat config.yaml | grep -v "api_key\|token\|password"

# Log dosyası (son 50 satır)
tail -50 /var/log/nginx/access.log

# Hata mesajı (tam stack trace)
python log_analyzer.py analyze --file test.log 2>&1 | tee error.log
```

---

### Issue Aç

GitHub'da issue açarken şunları ekle:

1. **Problem açıklaması**
2. **Adım adım reproduce etme**
3. **Beklenen davranış**
4. **Gerçek davranış**
5. **Ortam bilgileri** (OS, Python version, vb.)
6. **Hata logları**
7. **Config dosyası** (hassas bilgiler gizli)

---

### Community

- **GitHub Issues:** https://github.com/cyb3rkan/log-analyzer-ai/issues
- **Discussions:** https://github.com/cyb3rkan/log-analyzer-ai/discussions

---

**Umarım sorununuz çözülmüştür! 🔧✨**
