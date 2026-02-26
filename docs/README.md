# 📚 Log Analyzer AI - Dokümantasyon

Hoş geldiniz! Bu klasörde Log Analyzer AI ile ilgili tüm detaylı dokümantasyonu bulabilirsiniz.

---

## 📖 Dokümantasyon İndeksi

### 🚀 [Quick Start Guide](Quick_Start.md)
**5 dakikada başla!**
- Kurulum adımları
- İlk analiz
- Temel komutlar
- Gerçek dünya senaryoları
- Pro ipuçları

**Kime göre:** Yeni başlayanlar, hızlı başlangıç isteyenler

---

### 🧪 [Test Guide](README_Test.md)
**Kapsamlı test rehberi**
- Unit testler
- Manuel test senaryoları
- Performance testleri
- Güvenlik testleri
- Test metrikleri

**Kime göre:** Geliştiriciler, QA mühendisleri, güvenlik uzmanları

---

### ⚙️ [Configuration Guide](Configuration_Guide.md)
**Detaylı konfigürasyon**
- Tespit ayarları (brute force, SQL injection, XSS, vb.)
- Müdahale ayarları (IP bloklama, alertler)
- AI/ML ayarları
- Whitelist yönetimi
- Örnek konfigürasyonlar

**Kime göre:** Sistem yöneticileri, DevOps, güvenlik mühendisleri

---

### 🔧 [Troubleshooting Guide](Troubleshooting.md)
**Sorun giderme rehberi**
- Kurulum sorunları
- Çalıştırma sorunları
- Tespit sorunları
- Performance sorunları
- Alert ve dashboard sorunları

**Kime göre:** Herkes (sorun yaşayanlar)

---

## 🎯 Hızlı Erişim

### İlk Kez Kullanıyorsanız
1. 📖 [Quick Start Guide](Quick_Start.md) okuyun
2. ⚙️ [Configuration Guide](Configuration_Guide.md) ile ayarları özelleştirin
3. 🧪 [Test Guide](README_Test.md) ile test edin
4. 🔧 Sorun çıkarsa [Troubleshooting](Troubleshooting.md) bakın

---

### Geliştiriciyseniz
1. 🧪 [Test Guide](README_Test.md) - Unit test yazma
2. ⚙️ [Configuration Guide](Configuration_Guide.md) - Advanced features
3. 📖 [Quick Start Guide](Quick_Start.md) - CLI komutları

---

### Sistem Yöneticisiyseniz
1. 📖 [Quick Start Guide](Quick_Start.md) - Production deployment
2. ⚙️ [Configuration Guide](Configuration_Guide.md) - Security hardening
3. 🔧 [Troubleshooting](Troubleshooting.md) - Common issues

---

## 📋 Ek Kaynaklar

### Ana Proje Dosyaları
- **README.md** (kök dizin) - Proje genel bakış
- **config.example.yaml** - Örnek konfigürasyon
- **requirements.txt** - Python bağımlılıkları

### Kod Dokümantasyonu
- **src/parsers/** - Log parser'ları (Nginx, Apache, Syslog, Windows)
- **src/detector.py** - Tehdit tespit motoru
- **src/responder.py** - Otomatik müdahale sistemi
- **src/analyzer.py** - Ana analiz motoru
- **models/** - ML modelleri (anomaly detection, classifier)
- **dashboard/** - Web dashboard

---

## 🌟 Öne Çıkan Özellikler

### Log Parsing
✅ Nginx, Apache, Syslog, Windows Event Log  
✅ Custom format desteği  
✅ URL encoding/decoding  
✅ Gerçek zamanlı streaming  

### Threat Detection
✅ Brute Force  
✅ SQL Injection  
✅ XSS  
✅ Path Traversal  
✅ DDoS  
✅ Suspicious User Agents  

### Automated Response
✅ IP bloklama (iptables/firewalld)  
✅ Slack/Telegram alerts  
✅ Whitelist yönetimi  
✅ Configurable severity thresholds  

### Analytics
✅ JSON + Text reports  
✅ Daily/Weekly scheduling  
✅ ML-based anomaly detection  
✅ Real-time dashboard  

---

## 💡 Örnek Kullanım Senaryoları

### 1. Basit Log Analizi
```bash
python log_analyzer.py analyze --file /var/log/nginx/access.log
```
Detaylar: [Quick Start - Senaryo 1](Quick_Start.md#senaryo-1-üretim-sunucusunda-izleme)

### 2. Gerçek Zamanlı İzleme + IP Bloklama
```bash
sudo python log_analyzer.py watch --file /var/log/nginx/access.log --auto-block
```
Detaylar: [Configuration Guide - Auto Block](Configuration_Guide.md#otomatik-ip-bloklama)

### 3. Dashboard ile Görselleştirme
```bash
python log_analyzer.py dashboard --port 8080 --file /var/log/nginx/access.log
```
Detaylar: [Quick Start - Dashboard](Quick_Start.md#-4-dashboardu-aç)

### 4. Toplu Analiz + Rapor
```bash
python log_analyzer.py analyze --dir /var/log/nginx/ --pattern "*.log" --output both
```
Detaylar: [Test Guide - Senaryo 3](README_Test.md#senaryo-3-sql-injection-tespiti)

---

## 🆘 Yardım ve Destek

### Sorularınız mı var?
1. İlgili dokümantasyona göz atın
2. [Troubleshooting Guide](Troubleshooting.md) kontrol edin
3. GitHub Issues açın: https://github.com/cyb3rkan/log-analyzer-ai/issues

### Katkıda Bulunmak İster misiniz?
1. Fork yapın
2. Feature branch oluşturun
3. Değişiklikleri commit edin
4. Pull request açın

---

## 📊 Dokümantasyon Metrikleri

| Dosya | Satır Sayısı | Konu |
|-------|--------------|------|
| Quick_Start.md | 450+ | Hızlı başlangıç |
| README_Test.md | 700+ | Test senaryoları |
| Configuration_Guide.md | 800+ | Konfigürasyon |
| Troubleshooting.md | 600+ | Sorun giderme |

**Toplam:** 2500+ satır detaylı dokümantasyon

---

## 🔄 Güncelleme Geçmişi

### v1.0.0 (2024-01-15)
- ✅ İlk dokümantasyon sürümü
- ✅ 4 kapsamlı rehber
- ✅ 50+ örnek senaryo
- ✅ Troubleshooting database

---

## 📮 İletişim

- **GitHub:** https://github.com/cyb3rkan/log-analyzer-ai
- **LinkedIn:** https://www.linkedin.com/in/erkansahin23/

---

**Mutlu okumalar! 📚✨**

*Son güncelleme: 2024-01-15*
