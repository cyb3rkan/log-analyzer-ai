# 📄 Raporlar — Analiz Çıktıları

Her `analyze` komutu sonrasında `./reports/` dizininde raporlar oluşturulur.

## Rapor Formatları

```bash
# Hem JSON hem TXT (varsayılan)
python log_analyzer.py analyze -f access.log

# Sadece JSON
python log_analyzer.py analyze -f access.log -r json

# Sadece TXT
python log_analyzer.py analyze -f access.log -r txt

# Özel dizine kaydet
python log_analyzer.py analyze -f access.log -o /tmp/reports
```

## JSON Rapor

**Dosya:** `reports/report_YYYYMMDD_HHMMSS.json`

Programatik kullanım için (SIEM entegrasyonu, script'ler, dashboard).

```json
{
  "generated_at": "2026-02-25T14:32:00.123456",
  "source_file": "access.log",
  "total_lines": 305,
  "total_threats": 437,
  "severity_counts": {
    "CRITICAL": 146,
    "HIGH": 0,
    "MEDIUM": 291,
    "LOW": 0
  },
  "threat_type_counts": {
    "SQL_INJECTION": 146,
    "SUSPICIOUS_UA": 291
  },
  "top_attackers": [
    {"ip": "192.168.36.1", "count": 437}
  ],
  "threats": [
    {
      "timestamp": "2012-05-20T15:56:39+00:00",
      "source_ip": "192.168.36.1",
      "threat_type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "description": "SQL Injection from 192.168.36.1",
      "raw_line": "192.168.36.1 - - [20/May/2012:15:56:39 +0000] \"GET /dvwa/...\""
    }
  ]
}
```

### JSON Alanları

| Alan | Tür | Açıklama |
|---|---|---|
| `generated_at` | string | Rapor oluşturma zamanı (ISO 8601) |
| `source_file` | string | Analiz edilen dosya/dizin |
| `total_lines` | int | İşlenen toplam log satırı |
| `total_threats` | int | Tespit edilen toplam tehdit |
| `severity_counts` | object | Severity bazında dağılım |
| `threat_type_counts` | object | Tehdit türü bazında dağılım |
| `top_attackers` | array | En aktif saldırgan IP'ler (ilk 10) |
| `threats` | array | Tüm tehdit detayları |

## TXT Rapor

**Dosya:** `reports/report_YYYYMMDD_HHMMSS.txt`

Okunabilir metin formatında özet.

```
═══════════════════════════════════════════════
  LOG ANALYZER AI — THREAT REPORT
═══════════════════════════════════════════════

Generated : 2026-02-25 14:32:00
Source    : access.log
Lines     : 305
Threats   : 437

SEVERITY BREAKDOWN
  CRITICAL : 146
  MEDIUM   : 291

THREAT TYPES
  SQL_INJECTION  : 146
  SUSPICIOUS_UA  : 291

TOP ATTACKERS
  192.168.36.1   : 437 threats
═══════════════════════════════════════════════
```

## Raporları Kullanma

### Python'dan Okuma
```python
import json
with open("reports/report_20260225_143200.json") as f:
    data = json.load(f)
print(f"Toplam tehdit: {data['total_threats']}")
for attacker in data["top_attackers"]:
    print(f"  {attacker['ip']}: {attacker['count']} tehdit")
```

### jq ile Filtreleme (Komut Satırı)
```bash
# Sadece CRITICAL tehditler
cat reports/report_*.json | jq '.threats[] | select(.severity == "CRITICAL")'

# Top 5 saldırgan
cat reports/report_*.json | jq '.top_attackers[:5]'

# Sadece SQL injection
cat reports/report_*.json | jq '.threats[] | select(.threat_type == "SQL_INJECTION")'
```

### SIEM Entegrasyonu
JSON rapor formatı standart SIEM'lerle (Splunk, ELK, Wazuh) uyumludur. Rapor dizinini izleyerek otomatik gönderim yapılabilir.

## Rapor Dizini

```
reports/
├── .gitkeep                         ← Boş dizin koruması
├── report_20260225_143200.json
├── report_20260225_143200.txt
├── report_20260225_150000.json
└── report_20260225_150000.txt
```

`.gitignore` dosyasında `reports/report_*` hariç tutulur — raporlar Git'e yüklenmez.