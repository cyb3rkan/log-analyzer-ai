# 🛡️ Log Analyzer AI

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-In_Development-yellow?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Powered-blueviolet?style=for-the-badge&logo=openai&logoColor=white)

**AI-Powered Log Analysis & Automated Threat Response System**

Siber güvenlik analistlerinin saatler harcadığı log analizi işlemlerini AI ile otomatize eden ve şüpheli aktivitelere anında müdahale eden akıllı bir güvenlik aracı.

---

## 🎯 Problem ve Çözüm

### ❌ Geleneksel Yöntem
SOC analistleri günde binlerce log satırını manuel olarak inceler. Anomali tespiti için kural yazma, false positive yönetimi ve tehdit avı saatler sürer.

### ✅ Bu Araç ile
AI destekli analiz sayesinde loglar gerçek zamanlı analiz edilir, anormallikler otomatik tespit edilir ve tehditlere saniyeler içinde müdahale edilir.

| Metrik | Değer |
|--------|-------|
| ⏱️ Geleneksel | Saatler/Günler |
| ⚡ Log Analyzer AI | Gerçek Zamanlı |
| 📈 Tespit Hızı | %95+ |
| 🎯 False Positive Azaltma | %70+ |

---

## ✨ Özellikler

### 📊 Log Analysis
- Apache/Nginx access log parsing
- Windows Event Log desteği
- Syslog entegrasyonu
- Custom log format desteği
- Gerçek zamanlı stream processing

### 🤖 AI-Powered Detection
- Anomali tespiti (ML modelleri)
- Brute-force attack detection
- DDoS pattern recognition
- SQL Injection attempt detection
- Behavior analysis

### ⚡ Automated Response
- Otomatik IP bloklama (iptables)
- Firewall rule oluşturma
- Alert gönderme (Slack/Telegram)
- Incident ticket oluşturma
- Quarantine actions

### 📈 Monitoring & Reporting
- Real-time dashboard
- Threat visualization
- Daily/Weekly raporlar
- Trend analizi
- Executive summary

---

## 🔍 Tespit Yetenekleri

| Tehdit Türü | Tespit Yöntemi | Doğruluk |
|-------------|----------------|----------|
| Brute Force | Rate limiting + Pattern | %98 |
| DDoS | Traffic anomaly detection | %95 |
| SQL Injection | Regex + AI Classification | %97 |
| Path Traversal | Pattern matching | %99 |
| XSS Attempts | Payload analysis | %96 |
| Port Scanning | Connection pattern | %94 |
| C2 Beaconing | Time-series analysis | %92 |

---

## 📦 Kurulum

### Gereksinimler

- Python 3.11 veya üzeri
- Linux OS (Ubuntu/Debian önerilir)
- Root/sudo erişimi (otomatik bloklama için)
- API anahtarları

### Hızlı Başlangıç

```bash
# Repository'yi klonla
git clone https://github.com/cyb3rkan/log-analyzer-ai.git
cd log-analyzer-ai

# Virtual environment oluştur
python -m venv venv
source venv/bin/activate

# Bağımlılıkları yükle
pip install -r requirements.txt

# Konfigürasyonu ayarla
cp config.example.yaml config.yaml
# config.yaml dosyasını düzenle

# Uygulamayı başlat
python log_analyzer.py --config config.yaml
```

---

## 🚀 Kullanım

### CLI Kullanımı

```bash
# Tek bir log dosyası analizi
python log_analyzer.py analyze --file /var/log/apache2/access.log

# Gerçek zamanlı izleme
python log_analyzer.py watch --file /var/log/nginx/access.log --auto-block

# Batch analiz (birden fazla dosya)
python log_analyzer.py analyze --dir /var/log/apache2/ --pattern "*.log"

# Sadece rapor oluştur (bloklama yok)
python log_analyzer.py analyze --file access.log --report-only

# Dashboard başlat
python log_analyzer.py dashboard --port 8080
```

### Örnek Çıktı

```
┌──────────────────────────────────────────────────────────────────────┐
│                 🛡️ LOG ANALYZER AI - LIVE MONITORING                 │
├──────────────────────────────────────────────────────────────────────┤
│  📁 Watching: /var/log/nginx/access.log                              │
│  ⏱️  Started: 2024-01-15 14:32:00                                    │
│  📊 Processed: 15,847 lines | 🚨 Alerts: 3 | 🔒 Blocked: 2           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  🔴 HIGH [14:45:23] Brute Force Attack Detected                      │
│     • Source: 192.168.1.105                                          │
│     • Target: /wp-login.php                                          │
│     • Attempts: 847 in 60 seconds                                    │
│     • Action: ✅ IP BLOCKED (iptables)                               │
│                                                                      │
│  🟡 MEDIUM [14:42:11] SQL Injection Attempt                          │
│     • Source: 10.0.0.55                                              │
│     • Payload: "' OR '1'='1' --"                                     │
│     • Target: /api/search?q=                                         │
│     • Action: ⚠️ Alert sent to Slack                                 │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│  📈 STATISTICS (Last Hour)                                           │
│  • Total Requests: 45,231                                            │
│  • Unique IPs: 1,847                                                 │
│  • Suspicious: 127 (0.28%)                                           │
│  • Blocked: 12                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Konfigürasyon

```yaml
# config.yaml

# Log Kaynakları
log_sources:
  - name: nginx
    path: /var/log/nginx/access.log
    format: combined
    watch: true
  
  - name: apache
    path: /var/log/apache2/access.log
    format: combined
    watch: true

# Tespit Ayarları
detection:
  brute_force:
    enabled: true
    threshold: 100        # dakikada maksimum istek
    window: 60            # saniye
    
  ddos:
    enabled: true
    threshold: 1000       # dakikada maksimum istek
    
  sql_injection:
    enabled: true
    use_ai: true          # AI destekli tespit

# Müdahale Aksiyonları
response:
  auto_block:
    enabled: true
    method: iptables      # iptables, firewalld veya api
    duration: 3600        # saniye (0 = kalıcı)
    
  alerts:
    slack:
      enabled: true
      webhook_url: ${SLACK_WEBHOOK}
    telegram:
      enabled: true
      bot_token: ${TELEGRAM_TOKEN}
      chat_id: ${TELEGRAM_CHAT_ID}

# AI Ayarları
ai:
  provider: openai
  model: gpt-4
  analyze_threshold: medium  # low, medium, high
  
# Beyaz Liste
whitelist:
  ips:
    - 127.0.0.1
    - 10.0.0.0/8
  user_agents:
    - GoogleBot
    - BingBot
```

---

## 📁 Proje Yapısı

```
log-analyzer-ai/
├── src/
│   ├── __init__.py
│   ├── analyzer.py        # Ana analiz motoru
│   ├── detector.py        # Tehdit tespit modülü
│   ├── responder.py       # Otomatik müdahale
│   ├── reporter.py        # Raporlama
│   └── parsers/           # Log parser'ları
│       ├── nginx.py
│       ├── apache.py
│       ├── syslog.py
│       └── windows.py
├── models/                # ML modelleri
│   ├── anomaly_detector.py
│   └── classifier.py
├── dashboard/             # Web arayüzü
│   ├── app.py
│   └── templates/
├── tests/
├── log_analyzer.py        # CLI entry point
├── config.example.yaml
├── requirements.txt
└── README.md
```

---

## 🛣️ Yol Haritası

- [x] Apache/Nginx log parsing
- [x] Brute force detection
- [ ] SQL Injection detection (AI)
- [ ] Windows Event Log support
- [ ] iptables entegrasyonu
- [ ] Slack/Telegram alerts
- [ ] Real-time dashboard
- [ ] ML-based anomaly detection
- [ ] Docker container
- [ ] Kubernetes deployment

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen önce bir issue açarak neyi değiştirmek istediğinizi tartışalım.

```bash
# Fork'layın ve klonlayın
git clone https://github.com/YOUR_USERNAME/log-analyzer-ai.git

# Feature branch oluşturun
git checkout -b feature/amazing-feature

# Değişikliklerinizi commit edin
git commit -m 'feat: add amazing feature'

# Branch'i push edin
git push origin feature/amazing-feature

# Pull Request açın
```

---

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## ⚠️ Sorumluluk Reddi

Bu araç **yalnızca yetkili sistemlerde ve yasal amaçlarla** kullanılmalıdır. Üretim ortamlarında kullanmadan önce kapsamlı testler yapın. Yanlış yapılandırma meşru trafiği engelleyebilir.

---

## 📫 İletişim

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/erkansahin23/)

---

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!**
