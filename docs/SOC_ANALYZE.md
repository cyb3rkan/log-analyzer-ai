# 🔍 SOC Analyze — Korelasyon ve Kampanya Tespiti

AI'ya Kıdemli SOC Analisti rolü vererek logları korelatif analiz eder.
Tekrarlayan alarmları gruplar, saldırı kampanyalarını tespit eder, gürültüyü azaltır.

**OpenAI API key gerektirir.**

## analyze vs ai-analyze vs soc-analyze Farkı

| | `analyze` | `ai-analyze` | `soc-analyze` |
|---|---|---|---|
| Motor | Regex kuralları | AI (satır bazlı) | AI (SOC korelasyon) |
| API Key | Gereksiz | Gerekli | Gerekli |
| 305 sqlmap satırı | 437 alert | ~300 alert | 1-2 kampanya |
| Gürültü | Yüksek | Yüksek | Minimum |
| Hız | Anlık | Yavaş | Orta |
| Kullanım | Günlük tarama | Detaylı analiz | Olay müdahale |

## Kullanım

```bash
python log_analyzer.py soc-analyze --file access.log
```

## Parametreler

| Parametre | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--file` | `-f` | — | Analiz edilecek log dosyası (zorunlu) |
| `--format` | `-F` | `nginx` | Log formatı |
| `--lines` | `-n` | `100` | AI'ya gönderilecek max satır sayısı |

## Çıktı Açıklaması

```
╔══════════════════════════════════════════╗
║  RISK LEVEL:          CRITICAL           ║
╚══════════════════════════════════════════╝

Incident Count: 2
Summary: Automated SQL injection campaign via sqlmap targeting DVWA

📉 Noise Reduction:
   Total Log Lines    : 305
   Distinct Incidents  : 2
   Reduction Ratio     : 99.3%

🎯 Findings (2 campaigns):

  [CRITICAL] Campaign #1
    IP          : 192.168.36.1
    Attack Type : SQL_INJECTION
    Attempts    : 280
    Tool        : sqlmap/1.7
    Detail      : Automated SQLi campaign targeting DVWA endpoints

  [HIGH] Campaign #2
    IP          : 127.0.0.1
    Attack Type : TOOL_SCAN
    Attempts    : 10
    Tool        : sqlmap/1.7
    Detail      : Initial reconnaissance probe

🛡️ Recommendations:
  • Block 192.168.36.1 at WAF level
  • Rate-limit requests to /dvwa/vulnerabilities/
  • Disable or restrict phpMyAdmin access
```

### Çıktı Alanları

- **Risk Level**: Genel risk seviyesi (CRITICAL / HIGH / MEDIUM / LOW)
- **Incident Count**: Farklı saldırı kampanyası sayısı
- **Noise Reduction**: Gürültü azaltma istatistikleri
  - `Total Log Lines`: Gönderilen toplam satır
  - `Distinct Incidents`: Gruplanan kampanya sayısı
  - `Reduction Ratio`: Elenen tekrarlayan alert yüzdesi
- **Findings**: Her kampanya için IP, saldırı türü, deneme sayısı, kullanılan araç
- **Recommendations**: Pratik defansif aksiyonlar (WAF kuralı, rate-limit, patch vb.)

## SOC Analisti Ne Yapar

AI şu kurallara göre çalışır:

1. **Her satırı ayrı olay saymaz** — Aynı IP + aynı saldırı türü = tek kampanya
2. **Davranış analizi** — Keyword değil, tool fingerprint ve tekrar sayısına bakar
3. **Severity mantığı**:
   - MEDIUM: Şüpheli pattern, düşük frekans
   - HIGH: Onaylanmış saldırı aracı veya exploit girişimi
   - CRITICAL: Otomatik kampanya, tekrarlı deneme, net kötü niyet
4. **False positive kontrolü** — Eğitim ortamları (DVWA), tek seferlik taramalar severity düşürür
5. **Saldırı talimatı vermez** — Sadece defansif öneriler

## Örnekler

```bash
# Temel kullanım
python log_analyzer.py soc-analyze -f access.log

# Daha fazla satır gönder (daha detaylı analiz)
python log_analyzer.py soc-analyze -f access.log --lines 200

# Apache formatında
python log_analyzer.py soc-analyze -f apache_access.log -F apache
```

## Ne Zaman Kullanmalı

- Çok sayıda alarm aldığında → kampanya mı yoksa false positive mı?
- Olay müdahale (incident response) sırasında → hızlı özet
- Haftalık/aylık log review'da → genel risk değerlendirmesi
- SIEM'e göndermeden önce → gürültüyü filtrele