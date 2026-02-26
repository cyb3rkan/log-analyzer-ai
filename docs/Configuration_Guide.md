# ⚙️ Log Analyzer AI - Konfigürasyon Rehberi

## 📋 İçindekiler

- [Temel Konfigürasyon](#temel-konfigürasyon)
- [Tespit Ayarları](#tespit-ayarları)
- [Müdahale Ayarları](#müdahale-ayarları)
- [Alert Ayarları](#alert-ayarları)
- [AI Ayarları](#ai-ayarları)
- [İleri Seviye Ayarlar](#ileri-seviye-ayarlar)

---

## 🎯 Temel Konfigürasyon

### config.yaml Dosyası

Ana konfigürasyon dosyası `config.yaml` şu yapıdadır:

```yaml
log_sources:        # Log dosya kaynakları
detection:          # Tehdit tespit ayarları
response:           # Otomatik müdahale ayarları
ai:                 # AI/ML ayarları
whitelist:          # Beyaz liste
dashboard:          # Dashboard ayarları
reporting:          # Raporlama ayarları
```

### Minimal Çalışır Konfigürasyon

```yaml
# Sadece gerekli minimum ayarlar

detection:
  brute_force:
    enabled: true
    threshold: 100
    window: 60
  
  sql_injection:
    enabled: true

response:
  auto_block:
    enabled: false

whitelist:
  ips: []
  user_agents: []
```

---

## 🔍 Tespit Ayarları

### Brute Force Detection

```yaml
detection:
  brute_force:
    enabled: true
    threshold: 100      # Dakikada maksimum istek sayısı
    window: 60          # Zaman penceresi (saniye)
```

**Kullanım Senaryoları:**

**Yüksek trafikli site (daha toleranslı):**
```yaml
brute_force:
  enabled: true
  threshold: 200
  window: 120
```

**Kritik endpoint (daha katı):**
```yaml
brute_force:
  enabled: true
  threshold: 50
  window: 30
```

**Disable:**
```yaml
brute_force:
  enabled: false
```

---

### DDoS Detection

```yaml
detection:
  ddos:
    enabled: true
    threshold: 1000     # IP başına dakikada maksimum istek
    window: 60
```

**Öneriler:**

| Site Tipi | Threshold | Window |
|-----------|-----------|--------|
| Küçük blog | 500 | 60 |
| E-ticaret | 1000 | 60 |
| API servisi | 2000 | 60 |
| CDN arkası | 5000 | 120 |

---

### SQL Injection Detection

```yaml
detection:
  sql_injection:
    enabled: true
    use_ai: false       # AI destekli analiz (opsiyonel)
```

**Pattern-based (varsayılan):**
- Hızlı
- Düşük false positive
- Bilinen pattern'leri yakalar

**AI-destekli:**
```yaml
sql_injection:
  enabled: true
  use_ai: true
```
- Yeni/bilinmeyen pattern'leri yakalar
- OpenAI API key gerektirir
- Daha yavaş ama daha kapsamlı

---

### Path Traversal Detection

```yaml
detection:
  path_traversal:
    enabled: true
```

Tespit edilen pattern'ler:
- `../` ve `..\\`
- `/etc/passwd`, `/etc/shadow`
- `c:\\windows\\system32`
- URL encoded versiyonları (`%2e%2e%2f`)

---

### XSS Detection

```yaml
detection:
  xss:
    enabled: true
```

Tespit edilen pattern'ler:
- `<script>` tags
- `javascript:` protocol
- Event handlers (`onclick`, `onerror`)
- `document.cookie` erişimi
- HTML entity encoding

---

### Port Scanning Detection

```yaml
detection:
  port_scan:
    enabled: true
    threshold: 20       # Farklı port sayısı eşiği
    window: 60          # Saniye
```

**Not:** Henüz implement edilmemiş (roadmap'te)

---

## 🛡️ Müdahale Ayarları

### Otomatik IP Bloklama

```yaml
response:
  auto_block:
    enabled: false      # Varsayılan: kapalı (güvenlik için)
    method: iptables    # iptables, firewalld veya api
    duration: 3600      # Saniye (0 = kalıcı)
```

**⚠️ ÖNEMLİ:**
- Root/sudo yetkisi gerektirir
- Production'da dikkatli kullanın
- Önce test edin!

**Bloklama Metodları:**

**1. iptables (Linux):**
```yaml
auto_block:
  enabled: true
  method: iptables
  duration: 3600
```

Gereksinimler:
```bash
# Root yetkisi
sudo python log_analyzer.py watch --file access.log --auto-block

# iptables yüklü mü kontrol
which iptables
```

**2. firewalld (RHEL/CentOS):**
```yaml
auto_block:
  enabled: true
  method: firewalld
  duration: 3600
```

**3. API (Custom):**
```yaml
auto_block:
  enabled: true
  method: api
  api_endpoint: https://firewall.example.com/block
  api_key: ${FIREWALL_API_KEY}
```

---

### Bloklama Politikaları

**Sadece kritik tehditler:**
```yaml
auto_block:
  enabled: true
  severity_threshold: HIGH  # Sadece HIGH ve CRITICAL blokla
  duration: 7200
```

**Geçici bloklama:**
```yaml
auto_block:
  enabled: true
  duration: 1800  # 30 dakika
```

**Kalıcı bloklama:**
```yaml
auto_block:
  enabled: true
  duration: 0     # Kalıcı (manuel kaldırılmalı)
```

---

## 📢 Alert Ayarları

### Slack Entegrasyonu

```yaml
response:
  alerts:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK}"
```

**Kurulum:**

1. Slack Webhook oluştur:
   - https://api.slack.com/messaging/webhooks
   - Webhook URL'i kopyala

2. Environment variable ayarla:
```bash
echo "SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL" >> .env
```

3. Test et:
```bash
python log_analyzer.py analyze --file test.log
# Slack'te notification gelecek
```

**Custom Mesaj:**
```yaml
slack:
  enabled: true
  webhook_url: "${SLACK_WEBHOOK}"
  channel: "#security-alerts"
  username: "Log Analyzer AI"
  icon_emoji: ":shield:"
```

---

### Telegram Entegrasyonu

```yaml
response:
  alerts:
    telegram:
      enabled: true
      bot_token: "${TELEGRAM_TOKEN}"
      chat_id: "${TELEGRAM_CHAT_ID}"
```

**Kurulum:**

1. Bot oluştur:
   - @BotFather ile konuş
   - `/newbot` komutunu kullan
   - Token'ı kaydet

2. Chat ID bul:
   - Botunuza mesaj gönderin
   - https://api.telegram.org/bot<TOKEN>/getUpdates
   - `chat.id` değerini bulun

3. Environment variable ayarla:
```bash
echo "TELEGRAM_TOKEN=123456:ABCdefGHIjklMNOpqrsTUVwxyz" >> .env
echo "TELEGRAM_CHAT_ID=123456789" >> .env
```

---

### Email Alert (Gelişmiş)

```yaml
response:
  alerts:
    email:
      enabled: true
      smtp_host: smtp.gmail.com
      smtp_port: 587
      smtp_user: "${EMAIL_USER}"
      smtp_pass: "${EMAIL_PASS}"
      from_addr: alerts@example.com
      to_addrs:
        - security@example.com
        - admin@example.com
```

**Not:** Email alert henüz implement edilmemiş (roadmap'te)

---

### Alert Filtreleme

**Sadece yüksek öncelikli tehditler için alert:**
```yaml
alerts:
  severity_filter: HIGH  # LOW, MEDIUM, HIGH, CRITICAL
  slack:
    enabled: true
```

**Spesifik tehdit türleri için alert:**
```yaml
alerts:
  threat_types:
    - BRUTE_FORCE
    - SQL_INJECTION
  slack:
    enabled: true
```

---

## 🤖 AI Ayarları

### OpenAI Entegrasyonu

```yaml
ai:
  provider: openai
  model: gpt-4
  api_key: "${OPENAI_API_KEY}"
  analyze_threshold: medium
```

**Kurulum:**
```bash
echo "OPENAI_API_KEY=sk-your-api-key" >> .env
```

**Model Seçimi:**

| Model | Hız | Doğruluk | Maliyet |
|-------|-----|----------|---------|
| gpt-3.5-turbo | ⚡⚡⚡ | ⭐⭐ | $ |
| gpt-4 | ⚡⚡ | ⭐⭐⭐ | $$$ |
| gpt-4-turbo | ⚡⚡⚡ | ⭐⭐⭐ | $$ |

**Threshold Ayarları:**

```yaml
ai:
  analyze_threshold: low     # Her şüpheli aktiviteyi AI'ya gönder
  analyze_threshold: medium  # Orta şüpheli olanları gönder (varsayılan)
  analyze_threshold: high    # Sadece yüksek şüpheli olanları gönder
```

---

### ML Model Ayarları

```yaml
ai:
  anomaly_detection:
    enabled: true
    model_path: ./models/anomaly_model.pkl
    contamination: 0.05     # Beklenen anomali oranı
    retrain_interval: 7     # Günde bir yeniden eğit
```

**Model Eğitimi:**
```bash
# Temiz trafikle model eğit
python log_analyzer.py train --file clean_traffic.log --contamination 0.01

# Eğitilen model otomatik kullanılır
ls models/
# anomaly_model.pkl
# anomaly_scaler.pkl
```

---

## 🏷️ Whitelist (Beyaz Liste)

### IP Whitelist

```yaml
whitelist:
  ips:
    - 127.0.0.1           # Localhost
    - 10.0.0.0/8          # Private network
    - 192.168.1.50        # Admin IP
    - 203.0.113.100       # Monitoring server
```

**CIDR Notation:**
- `192.168.1.0/24` → 192.168.1.0 - 192.168.1.255
- `10.0.0.0/8` → 10.0.0.0 - 10.255.255.255

---

### User Agent Whitelist

```yaml
whitelist:
  user_agents:
    - GoogleBot
    - BingBot
    - Googlebot-Image
    - monitoring-bot
    - UptimeRobot
```

**Regex Support (Gelişmiş):**
```yaml
whitelist:
  user_agents_regex:
    - "(?i)googlebot"         # Case-insensitive
    - "(?i)bot.*monitoring"   # Pattern matching
```

---

### Path Whitelist

```yaml
whitelist:
  paths:
    - /health
    - /metrics
    - /api/public/*
```

**Not:** Path whitelist henüz implement edilmemiş (roadmap'te)

---

## 📊 Log Kaynakları

### Tek Log Dosyası

```yaml
log_sources:
  - name: nginx
    path: /var/log/nginx/access.log
    format: combined
    watch: true
```

### Çoklu Log Dosyaları

```yaml
log_sources:
  - name: nginx-main
    path: /var/log/nginx/access.log
    format: combined
    watch: true
  
  - name: nginx-api
    path: /var/log/nginx/api.access.log
    format: combined
    watch: true
  
  - name: apache
    path: /var/log/apache2/access.log
    format: apache
    watch: true
  
  - name: syslog
    path: /var/log/syslog
    format: syslog
    watch: false
```

### Format Türleri

**Desteklenen formatlar:**
- `combined` - Nginx combined format
- `apache` - Apache combined format
- `syslog` - Syslog RFC 3164/5424
- `common` - Common log format
- `custom` - Custom format (regex ile)

---

## 🖥️ Dashboard Ayarları

```yaml
dashboard:
  host: 0.0.0.0       # Tüm interface'lerde dinle
  port: 8080
  debug: false
  auto_reload: false
```

**Güvenlik Ayarları:**
```yaml
dashboard:
  host: 127.0.0.1     # Sadece localhost
  port: 8080
  auth:
    enabled: true
    username: admin
    password_hash: ${DASHBOARD_PASSWORD_HASH}
```

**Not:** Auth henüz implement edilmemiş

---

## 📈 Raporlama Ayarları

```yaml
reporting:
  output_dir: ./reports
  daily: true
  weekly: true
  format: both          # json, text veya both
  
  # Email raporu (gelişmiş)
  email_reports:
    enabled: false
    recipients:
      - security@example.com
    schedule: "0 8 * * *"  # Her gün sabah 8'de
```

---

## 🔧 İleri Seviye Ayarlar

### Performance Tuning

```yaml
performance:
  max_threads: 4
  buffer_size: 10000
  cache_size: 1000
  batch_processing: true
```

### Logging

```yaml
logging:
  level: INFO           # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: ./logs/analyzer.log
  max_size: 10485760    # 10 MB
  backup_count: 5
  format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
```

### Custom Patterns

```yaml
detection:
  custom_patterns:
    - name: "Custom SQL Injection"
      pattern: "(?i)(EXEC|EXECUTE)\\s+xp_"
      severity: HIGH
      threat_type: SQL_INJECTION
    
    - name: "API Key Leak"
      pattern: "api[_-]?key[=:]\\s*['\"]?[A-Za-z0-9]{32,}['\"]?"
      severity: CRITICAL
      threat_type: DATA_LEAK
```

---

## 🌍 Environment Variables

Hassas bilgileri `.env` dosyasında saklayın:

```bash
# .env dosyası
SLACK_WEBHOOK=https://hooks.slack.com/services/XXX
TELEGRAM_TOKEN=123456:ABCDEF
TELEGRAM_CHAT_ID=123456789
OPENAI_API_KEY=sk-xxxxx
FIREWALL_API_KEY=your-firewall-api-key
DATABASE_URL=postgresql://user:pass@localhost/logdb
```

**config.yaml'da kullanım:**
```yaml
response:
  alerts:
    slack:
      webhook_url: "${SLACK_WEBHOOK}"  # .env'den okunur
```

---

## 📝 Örnek Konfigürasyonlar

### Küçük Blog/Website

```yaml
log_sources:
  - name: nginx
    path: /var/log/nginx/access.log
    format: combined
    watch: true

detection:
  brute_force:
    enabled: true
    threshold: 50
    window: 60
  sql_injection:
    enabled: true
  xss:
    enabled: true

response:
  auto_block:
    enabled: false
  alerts:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK}"

whitelist:
  ips:
    - 127.0.0.1

reporting:
  output_dir: ./reports
  daily: true
```

---

### E-ticaret Sitesi

```yaml
log_sources:
  - name: nginx-web
    path: /var/log/nginx/access.log
    format: combined
    watch: true
  - name: nginx-api
    path: /var/log/nginx/api.log
    format: combined
    watch: true

detection:
  brute_force:
    enabled: true
    threshold: 100
    window: 60
  ddos:
    enabled: true
    threshold: 2000
    window: 120
  sql_injection:
    enabled: true
    use_ai: true
  xss:
    enabled: true
  path_traversal:
    enabled: true

response:
  auto_block:
    enabled: true
    method: iptables
    duration: 7200
  alerts:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK}"
    telegram:
      enabled: true
      bot_token: "${TELEGRAM_TOKEN}"
      chat_id: "${TELEGRAM_CHAT_ID}"

whitelist:
  ips:
    - 10.0.0.0/8
    - 192.168.1.50    # Admin
  user_agents:
    - GoogleBot
    - BingBot

ai:
  provider: openai
  model: gpt-4-turbo
  api_key: "${OPENAI_API_KEY}"
  analyze_threshold: medium

reporting:
  output_dir: ./reports
  daily: true
  weekly: true
  format: both
```

---

### API Servisi

```yaml
log_sources:
  - name: api
    path: /var/log/api/access.log
    format: combined
    watch: true

detection:
  brute_force:
    enabled: true
    threshold: 200
    window: 60
  ddos:
    enabled: true
    threshold: 5000
    window: 120
  sql_injection:
    enabled: true
    use_ai: true

response:
  auto_block:
    enabled: true
    method: api
    api_endpoint: https://firewall.example.com/block
    api_key: "${FIREWALL_API_KEY}"
    duration: 3600
  alerts:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK}"

whitelist:
  ips:
    - 10.0.0.0/8      # Internal
  user_agents:
    - monitoring-bot
    - health-check

ai:
  provider: openai
  model: gpt-4
  api_key: "${OPENAI_API_KEY}"
  anomaly_detection:
    enabled: true
    contamination: 0.01

reporting:
  output_dir: ./reports
  daily: true
  weekly: true
```

---

## 🆘 Troubleshooting

### Problem: Konfigürasyon yüklenmiyor

**Kontrol:**
```bash
# YAML syntax doğrula
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Eğer hata varsa, satır numarasını gösterir
```

### Problem: Environment variable okunmuyor

**Kontrol:**
```bash
# .env dosyası mevcut mu?
ls -la .env

# Değişken set mi?
echo $SLACK_WEBHOOK
```

**Çözüm:**
```bash
# .env dosyasını load et
export $(cat .env | xargs)
```

---

## 📚 Daha Fazla Bilgi

- [Quick Start Guide](Quick_Start.md) - Hızlı başlangıç
- [Test Guide](README_Test.md) - Test senaryoları
- [API Documentation](API_Reference.md) - API referansı (yakında)

---

**Mutlu konfigürasyonlar! ⚙️✨**
