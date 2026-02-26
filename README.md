# 🛡️ Log Analyzer AI

AI destekli güvenlik log analiz ve tehdit tespit sistemi.

Web sunucu loglarını gerçek zamanlı analiz eder, saldırı girişimlerini tespit eder ve raporlar.

## ✨ Özellikler

- **Çoklu Format**: Nginx, Apache, Syslog, Windows Event Log
- **5 Tehdit Türü**: SQL Injection, XSS, Path Traversal, Brute Force, Suspicious UA
- **URL Decode**: `%27+UNION+SELECT` gibi encode edilmiş saldırıları tespit eder
- **AI Analiz**: OpenAI (GPT-4o) ile gelişmiş tehdit sınıflandırması
- **Gerçek Zamanlı**: `tail -f` tarzı canlı log izleme
- **Web Dashboard**: Chart.js ile anlık görselleştirme
- **Otomatik Yanıt**: IP engelleme (iptables/ufw) ve Slack bildirimleri
- **ML Anomali**: Isolation Forest ile sıfır-gün tespit

## 🚀 Hızlı Başlangıç

```bash
# 1. Bağımlılıkları kur
pip install -r requirements.txt

# 2. Ayarla
cp config.example.yaml config.yaml
cp .env.example .env
# .env dosyasına API key'lerini yaz (opsiyonel)

# 3. Log analiz et
python log_analyzer.py analyze --file access.log

# 4. AI ile analiz (OpenAI API key gerekli)
python log_analyzer.py ai-analyze --file access.log

# 5. Dashboard aç
python log_analyzer.py dashboard --port 8080
```

## 📖 Komutlar

| Komut | Açıklama |
|---|---|
| `analyze` | Log dosyası veya dizin analiz et |
| `ai-analyze` | AI ile gelişmiş analiz |
| `soc-analyze` | SOC analyst — korelasyon ve kampanya tespiti |
| `watch` | Gerçek zamanlı log izleme |
| `dashboard` | Web arayüzü başlat |
| `test-ai` | AI bağlantı testi |
| `train` | ML modeli eğit |

### Örnekler

```bash
# Tek dosya analiz
python log_analyzer.py analyze --file /var/log/nginx/access.log

# Apache formatında
python log_analyzer.py analyze --file access.log --format apache

# Tüm dizin
python log_analyzer.py analyze --directory /var/log/nginx --pattern "*.log"

# AI analiz (ilk 30 satır)
python log_analyzer.py ai-analyze --file access.log --lines 30

# SOC analyst modu — korelasyon, kampanya tespiti, gürültü azaltma
python log_analyzer.py soc-analyze --file access.log --lines 100

# AI bağlantı testi
python log_analyzer.py test-ai

# Gerçek zamanlı izleme
python log_analyzer.py watch --file /var/log/nginx/access.log

# Dashboard (opsiyonel: önceden analiz)
python log_analyzer.py dashboard --port 8080 --file access.log
```

## 📁 Proje Yapısı

```
log-analyzer-ai/
├── log_analyzer.py           # CLI giriş noktası
├── config.example.yaml       # Örnek ayar dosyası
├── .env.example              # Ortam değişkenleri şablonu
├── requirements.txt          # Python bağımlılıkları
├── src/                      # Ana kaynak kodlar
│   ├── analyzer.py           # Analiz motoru
│   ├── detector.py           # Tehdit tespit (kural tabanlı)
│   ├── reporter.py           # Rapor oluşturma (JSON/TXT)
│   ├── responder.py          # Otomatik yanıt (IP ban, Slack)
│   └── parsers/              # Log format ayrıştırıcılar
│       ├── nginx.py
│       ├── apache.py
│       ├── syslog.py
│       └── windows.py
├── models/                   # AI/ML modülleri
│   ├── classifier.py         # OpenAI sınıflandırıcı
│   └── anomaly_detector.py   # Isolation Forest
├── dashboard/                # Flask web arayüzü
│   ├── app.py
│   └── templates/
├── tests/                    # Unit testler
├── test_all_features.py      # Entegrasyon testleri
└── docs/                     # Dokümantasyon
```

## 🧪 Test

```bash
# Entegrasyon testleri (hızlı)
python test_all_features.py

# Unit testler (detaylı)
pytest tests/ -v
```

## 📄 Dokümantasyon

- [Kurulum Rehberi](docs/INSTALL.md) — Adım adım kurulum
- [Konfigürasyon](docs/CONFIG.md) — Tüm ayarlar
- [AI Kullanımı](docs/AI_GUIDE.md) — OpenAI kurulumu
- [Sorun Giderme](docs/TROUBLESHOOT.md) — Sık karşılaşılan hatalar

## 📝 Lisans

MIT License
