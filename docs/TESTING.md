# 🧪 Test Rehberi

Projenin doğru çalıştığını doğrulama yöntemleri.

## Hızlı Doğrulama

```bash
# Tüm testleri çalıştır (35 test, ~1 saniye)
python test_all_features.py
```

Beklenen çıktı:
```
📊 SONUÇLAR: 35/35 başarılı (100%)
🎉 TÜM TESTLER BAŞARILI!
```

## Test Dosyaları

| Dosya | Ne Test Eder |
|---|---|
| `test_all_features.py` | Tüm özellikler (entegrasyon testi) |
| `test_watch_demo.py` | Canlı izleme (otomatik demo) |
| `live_log_generator.py` | Sahte saldırı log üretici |
| `tests/test_parsers.py` | Parser'lar (nginx, apache, syslog, windows) |
| `tests/test_detector.py` | Tehdit tespiti (5 tür + URL decode) |
| `tests/test_analyzer.py` | Analiz motoru |
| `tests/test_reporter.py` | Rapor oluşturma |

## Entegrasyon Testi Detayları

`test_all_features.py` şunları test eder:

### 1. Parser Testleri (7 test)
- Nginx normal log, URL-encoded satır, dosya parse, boş/geçersiz giriş
- Apache combined format
- Syslog SSH failed login
- Windows Event 4625

### 2. Detector Testleri (12 test)
- SQL Injection: plain, UNION SELECT, URL-encoded, plus-encoded, information_schema, database()
- Path Traversal: `../../etc/passwd`
- XSS: `<script>` tag
- Suspicious UA: sqlmap, Nikto
- Brute Force: 6 başarısız giriş
- Normal trafik: tehdit üretmemeli

### 3. Analyzer Testleri (4 test)
- Dosya analizi, dizin analizi, callback, tüm tehdit türleri

### 4. Reporter Testleri (3 test)
- JSON rapor, TXT rapor, top attacker IP'ler

### 5. Whitelist Testleri (4 test)
- IP whitelist, CIDR whitelist, UA whitelist, non-whitelisted tespit

### 6. False Positive Testleri (3 test)
- Normal sayfa, normal API çağrısı, normal Chrome UA

### 7. Performans Testi (1 test)
- 1000 satır < 5 saniye

### 8. Kombine Senaryo (1 test)
- Parse → Detect → Report tam pipeline

## Canlı İzleme Testi

### Otomatik Demo (Tek Komut)
```bash
python test_watch_demo.py
```

Arka planda sahte saldırılar yazar, watch gerçek zamanlı tespit eder. Beklenen:
```
🚨 [CRITICAL] SQL_INJECTION | 203.0.113.50 | SQL Injection from 203.0.113.50
🚨 [MEDIUM] SUSPICIOUS_UA | 198.51.100.10 | Suspicious UA: sqlmap/1.7
🚨 [HIGH] BRUTE_FORCE | 198.51.100.77 | Brute force: 3 failed attempts
...
🎉 CANLI İZLEME BAŞARILI!
```

### Manuel Test (İki Terminal)
```bash
# Terminal 1
python log_analyzer.py watch --file access.log

# Terminal 2
python live_log_generator.py
```

## AI Testi

```bash
# Bağlantı testi (API key gerekli)
python log_analyzer.py test-ai

# AI analiz
python log_analyzer.py ai-analyze --file test.log --lines 10

# SOC analiz
python log_analyzer.py soc-analyze --file test.log --lines 50
```

## Unit Testler (pytest)

```bash
# Tümü
pytest tests/ -v

# Sadece detector testleri
pytest tests/test_detector.py -v

# Coverage raporu
pytest tests/ --cov=src --cov-report=term-missing
```

## Örnek test.log ile Test

Proje ile birlikte gelen `test.log` dosyası 305 satır sqlmap trafiği içerir:

```bash
python log_analyzer.py analyze --file test.log
```

Beklenen:
```
Lines Processed: 305
Threats Detected: 437
  CRITICAL: 146 (SQL_INJECTION)
  MEDIUM: 291 (SUSPICIOUS_UA)
```

## Sorun Varsa

1. `python test_all_features.py` çalıştır — hangi test kırık?
2. `LOG_LEVEL=DEBUG python log_analyzer.py analyze -f test.log` — detaylı hata bilgisi
3. `python log_analyzer.py test-ai` — AI bağlantı diagnostiği