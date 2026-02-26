# 🚀 Log Analyzer AI - Hızlı Başlangıç Kılavuzu

## ⏱️ 5 Dakikada Başla

### Adım 1: Kurulum (2 dakika)

```bash
# Repository'yi klonla veya ZIP'i aç
cd log-analyzer-ai

# Virtual environment oluştur (opsiyonel ama önerilen)
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate

# Bağımlılıkları yükle
pip install -r requirements.txt
```

### Adım 2: Konfigürasyon (1 dakika)

```bash
# Örnek konfigürasyonu kopyala
cp config.example.yaml config.yaml

# Konfigürasyonu düzenle (opsiyonel)
nano config.yaml   # veya favori editörünüzü kullanın
```

**Minimal çalışma için gerekli ayarlar:**
```yaml
detection:
  brute_force:
    enabled: true
    threshold: 100
  sql_injection:
    enabled: true

response:
  auto_block:
    enabled: false  # İlk çalıştırmada kapalı tutun!
```

### Adım 3: İlk Analiz (2 dakika)

```bash
# Test log dosyası oluştur
cat > test.log << 'EOF'
192.168.1.100 - - [15/Jan/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [15/Jan/2024:14:30:01 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:02 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:03 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:04 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.100 - - [15/Jan/2024:14:30:05 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.28"
10.0.0.55 - - [15/Jan/2024:14:30:06 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
10.0.0.56 - - [15/Jan/2024:14:30:07 +0000] "GET /files/../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.88"
10.0.0.57 - - [15/Jan/2024:14:30:08 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
EOF

# İlk analizini yap!
python log_analyzer.py analyze --file test.log
```

**Beklenen çıktı:**
```
🛡️ LOG ANALYZER AI - LIVE MONITORING
──────────────────────────────────────
🔴 HIGH [14:30:05] Brute Force Attack Detected
   • Source: 192.168.1.100
   • Target: /wp-login.php
   • Attempts: 6 in 60 seconds

🔴 HIGH [14:30:06] SQL Injection Attempt
   • Source: 10.0.0.55
   • Payload: "' OR '1'='1"

📊 İşlenen: 9 satır | 🚨 Tehdit: 4
✅ Rapor kaydedildi: ./reports/
```

---

## 📋 Temel Komutlar

### Tek Dosya Analizi
```bash
# Nginx log analizi
python log_analyzer.py analyze --file /var/log/nginx/access.log

# Apache log analizi
python log_analyzer.py analyze --file /var/log/apache2/access.log --format apache

# Sadece rapor oluştur (bloklama yok)
python log_analyzer.py analyze --file access.log --report-only

# JSON formatında rapor
python log_analyzer.py analyze --file access.log --output json
```

### Dizin Analizi (Toplu)
```bash
# Tüm .log dosyalarını analiz et
python log_analyzer.py analyze --dir /var/log/nginx/ --pattern "*.log"

# Sadece bugünün logları
python log_analyzer.py analyze --dir /var/log/ --pattern "*$(date +%Y%m%d)*.log"
```

### Gerçek Zamanlı İzleme
```bash
# Temel izleme
python log_analyzer.py watch --file /var/log/nginx/access.log

# Otomatik IP bloklama ile (ROOT GEREKLİ!)
sudo python log_analyzer.py watch --file /var/log/nginx/access.log --auto-block

# Apache logunu izle
python log_analyzer.py watch --file /var/log/apache2/access.log --format apache
```

### Web Dashboard
```bash
# Dashboard'u başlat
python log_analyzer.py dashboard --port 8080

# Arka planda log izleme ile
python log_analyzer.py dashboard --port 8080 --file /var/log/nginx/access.log

# Farklı portta
python log_analyzer.py dashboard --host 0.0.0.0 --port 3000
```

Dashboard URL: **http://localhost:8080**

---

## 🎯 İlk Hedefler

### ✅ Kontrol Listesi

- [ ] **1. Projeyi çalıştır**
  ```bash
  python log_analyzer.py analyze --file test.log
  ```

- [ ] **2. Kendi log dosyanı analiz et**
  ```bash
  python log_analyzer.py analyze --file /var/log/nginx/access.log
  ```

- [ ] **3. Gerçek zamanlı izlemeyi dene** (Ctrl+C ile durdur)
  ```bash
  python log_analyzer.py watch --file /var/log/nginx/access.log
  ```

- [ ] **4. Dashboard'u aç**
  ```bash
  python log_analyzer.py dashboard --port 8080
  # Tarayıcıda http://localhost:8080
  ```

- [ ] **5. Rapor üret ve incele**
  ```bash
  python log_analyzer.py analyze --file test.log --output both
  ls -lh reports/
  cat reports/report_*.txt
  ```

---

## ⚙️ Konfigürasyon İpuçları

### Tespit Hassasiyetini Ayarla

**Daha az false positive için:**
```yaml
detection:
  brute_force:
    threshold: 200    # Varsayılan: 100
    window: 120       # 2 dakika pencere
```

**Daha agresif tespit için:**
```yaml
detection:
  brute_force:
    threshold: 50     # Daha düşük eşik
    window: 30        # Daha kısa pencere
```

### Whitelist Ekle
```yaml
whitelist:
  ips:
    - 127.0.0.1
    - 10.0.0.0/8
    - 192.168.1.50    # Kendi admin IP'niz
  user_agents:
    - GoogleBot
    - monitoring-bot  # Kendi botunuz
```

### Alert Ayarları

**Slack entegrasyonu:**
```bash
# .env dosyası oluştur
echo "SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL" > .env
```

```yaml
# config.yaml
response:
  alerts:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK}"
```

**Telegram entegrasyonu:**
```bash
echo "TELEGRAM_TOKEN=your_bot_token" >> .env
echo "TELEGRAM_CHAT_ID=your_chat_id" >> .env
```

---

## 🔥 Gerçek Dünya Senaryoları

### Senaryo 1: Üretim Sunucusunda İzleme
```bash
# Servis olarak çalıştır (systemd)
sudo cp log-analyzer.service /etc/systemd/system/
sudo systemctl enable log-analyzer
sudo systemctl start log-analyzer
sudo journalctl -u log-analyzer -f
```

### Senaryo 2: Günlük Rapor Otomasyonu
```bash
# Cron job ekle (her gün saat 00:00)
0 0 * * * cd /opt/log-analyzer-ai && python log_analyzer.py analyze --dir /var/log/nginx/ --output both
```

### Senaryo 3: Incident Response
```bash
# Şüpheli IP'yi hızlıca analiz et
grep "203.0.113.5" /var/log/nginx/access.log > suspicious.log
python log_analyzer.py analyze --file suspicious.log --report-only

# Sonuçları incele
cat reports/report_*.txt | grep -A 5 "203.0.113.5"
```

---

## 💡 Pro İpuçları

### 1. Performans İyileştirme
```bash
# Büyük dosyalar için (>100MB)
# Önce son 10000 satırı analiz et
tail -10000 /var/log/nginx/access.log > recent.log
python log_analyzer.py analyze --file recent.log
```

### 2. Log Rotasyonu ile Çalışma
```bash
# Tüm rotasyonlu logları dahil et
python log_analyzer.py analyze --dir /var/log/nginx/ --pattern "access.log*"
```

### 3. ML Model Eğitimi (İleri Seviye)
```bash
# Temiz trafikle model eğit
python log_analyzer.py train --file clean_traffic.log --contamination 0.01

# Eğitilen model otomatik yüklenir
python log_analyzer.py analyze --file new_traffic.log
```

### 4. Dashboard + Arka Plan İzleme
```bash
# Tek komutla her şey
python log_analyzer.py dashboard \
  --port 8080 \
  --file /var/log/nginx/access.log &

# Dashboard: http://localhost:8080
# Arkada canlı log analizi çalışıyor
```

### 5. Rapor Otomasyonu
```bash
# Analiz yap ve Slack'e gönder
python log_analyzer.py analyze --file access.log
# Alert config.yaml'da aktifse otomatik Slack'e gider
```

---

## 🐛 Sorun Giderme

### Problem: "Permission denied" hatası
**Çözüm:**
```bash
# Log dosyasına okuma izni ver
sudo chmod +r /var/log/nginx/access.log

# Veya log grubuna ekle
sudo usermod -a -G adm $USER
# Oturum kapat/aç
```

### Problem: "Module not found" hatası
**Çözüm:**
```bash
# Virtual environment aktif mi kontrol et
which python
# Çıktı: /path/to/venv/bin/python olmalı

# Bağımlılıkları tekrar yükle
pip install -r requirements.txt
```

### Problem: IP bloklama çalışmıyor
**Çözüm:**
```bash
# 1. Root yetkisi gerekli
sudo python log_analyzer.py watch --file access.log --auto-block

# 2. iptables yüklü mü kontrol et
which iptables

# 3. Kuralları kontrol et
sudo iptables -L -n | grep INPUT
```

### Problem: Dashboard açılmıyor
**Çözüm:**
```bash
# Port kullanımda mı kontrol et
netstat -tuln | grep 8080

# Farklı port dene
python log_analyzer.py dashboard --port 3000

# Firewall kurallarını kontrol et
sudo ufw status
```

---

## 📚 Sonraki Adımlar

1. **README.md'yi oku** → Kapsamlı dokümantasyon
2. **config.yaml'ı özelleştir** → Kendi ihtiyaçlarına göre ayarla
3. **Slack/Telegram entegrasyonu kur** → Gerçek zamanlı bildirimler
4. **ML modeli eğit** → Daha hassas tespit
5. **Sistemd servisi yap** → Otomatik başlatma

---

## 🎓 Eğitim Kaynakları

### Log Formatları
- **Nginx:** `/var/log/nginx/access.log` (combined format)
- **Apache:** `/var/log/apache2/access.log` (combined format)
- **Syslog:** `/var/log/syslog` (RFC 3164/5424)
- **Windows:** XML export edilmiş Event Log

### Tespit Türleri
- **Brute Force:** Login sayfalarına yoğun istek
- **SQL Injection:** `' OR '1'='1`, `UNION SELECT`, vb.
- **Path Traversal:** `../../etc/passwd`, `..\..\windows\system32`
- **XSS:** `<script>`, `javascript:`, `onerror=`
- **DDoS:** Aşırı istek oranı
- **Port Scanning:** Çok sayıda farklı port denemesi
- **Suspicious UA:** sqlmap, nikto, nmap gibi tarayıcılar

---

## 🎉 Hazırsın!

Artık **Log Analyzer AI**'ı kullanmaya hazırsın! 

```bash
# İlk gerçek analizini yap
python log_analyzer.py analyze --file /var/log/nginx/access.log

# Dashboard'u aç ve izlemeye başla
python log_analyzer.py dashboard --port 8080 --file /var/log/nginx/access.log
```

**Mutlu analizler! 🛡️🚀**

---

### 🆘 Yardım Gerekiyorsa

```bash
# Komut yardımı
python log_analyzer.py --help
python log_analyzer.py analyze --help
python log_analyzer.py watch --help
python log_analyzer.py dashboard --help

# Issue aç
# GitHub: https://github.com/cyb3rkan/log-analyzer-ai/issues
```

### ⭐ Projeyi Beğendin mi?

GitHub'da yıldız vermeyi unutma! 🌟
