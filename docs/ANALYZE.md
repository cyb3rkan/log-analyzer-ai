# 📊 Analyze — Log Dosyası Analizi

Kural tabanlı tehdit tespiti. API key gerektirmez, her zaman çalışır.

## Temel Kullanım

```bash
# Tek dosya analiz (varsayılan: nginx)
python log_analyzer.py analyze --file access.log

# Format belirterek
python log_analyzer.py analyze --file access.log --format apache

# Dizin analizi (tüm .log dosyaları)
python log_analyzer.py analyze --directory /var/log/nginx --pattern "*.log"
```

## Parametreler

| Parametre | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--file` | `-f` | — | Analiz edilecek log dosyası |
| `--directory` | `-d` | — | Analiz edilecek dizin |
| `--pattern` | `-p` | `*.log` | Dizin analizi için dosya deseni |
| `--format` | `-F` | `nginx` | Log formatı: `nginx`, `apache`, `syslog`, `windows` |
| `--output` | `-o` | `./reports` | Rapor çıktı dizini |
| `--report-format` | `-r` | `both` | Rapor formatı: `json`, `txt`, `both` |

## Desteklenen Formatlar

```bash
# Nginx (varsayılan)
python log_analyzer.py analyze -f access.log -F nginx

# Apache Combined
python log_analyzer.py analyze -f access.log -F apache

# Syslog (SSH logları vb.)
python log_analyzer.py analyze -f /var/log/auth.log -F syslog

# Windows Event Log (dışa aktarılmış)
python log_analyzer.py analyze -f security.log -F windows
```

## Çıktı Açıklaması

```
Analysis Summary
----------------------------------------
Lines Processed                 305
Threats Detected                437
Unique Attacker IPs             1
  CRITICAL                      146
  MEDIUM                        291
```

- **Lines Processed**: Okunan toplam log satırı
- **Threats Detected**: Tespit edilen tehdit sayısı (bir satırda birden fazla olabilir)
- **Unique Attacker IPs**: Farklı saldırgan IP sayısı
- **CRITICAL / HIGH / MEDIUM / LOW**: Severity dağılımı

## Rapor Dosyaları

Her analiz sonrası `./reports/` dizininde iki dosya oluşur:

```
reports/
├── report_20260225_143200.json   ← Programatik kullanım için
└── report_20260225_143200.txt    ← Okunabilir özet
```

### JSON Rapor İçeriği
```json
{
  "generated_at": "2026-02-25T14:32:00",
  "source_file": "access.log",
  "total_lines": 305,
  "total_threats": 437,
  "severity_counts": {"CRITICAL": 146, "MEDIUM": 291},
  "top_attackers": [{"ip": "192.168.36.1", "count": 437}],
  "threats": [...]
}
```

## Örnekler

```bash
# Sadece JSON rapor
python log_analyzer.py analyze -f access.log -r json

# Özel dizine rapor kaydet
python log_analyzer.py analyze -f access.log -o /tmp/reports

# Tüm nginx loglarını analiz et
python log_analyzer.py analyze -d /var/log/nginx -p "*.log"

# Debug modunda çalıştır (detaylı çıktı)
LOG_LEVEL=DEBUG python log_analyzer.py analyze -f access.log
```