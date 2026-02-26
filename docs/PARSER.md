# 📋 Desteklenen Log Formatları

Sistem 4 farklı log formatını ayrıştırır (parse eder). Her format için ayrı parser vardır.

## 1. Nginx (Varsayılan)

**Format:** Nginx combined log format

```
IP - USER [TIMESTAMP] "METHOD PATH PROTOCOL" STATUS SIZE "REFERER" "USER-AGENT"
```

**Örnek:**
```
192.168.36.1 - - [20/May/2012:15:56:39 +0000] "GET /dvwa/vulnerabilities/sqli/?id=1%27 HTTP/1.1" 200 512 "-" "sqlmap/1.7"
```

**Kullanım:**
```bash
python log_analyzer.py analyze -f /var/log/nginx/access.log -F nginx
```

**Ayrıştırılan Alanlar:**
- `ip`: Kaynak IP adresi
- `user`: Kimlik doğrulama kullanıcısı (genelde `-`)
- `timestamp`: Zaman damgası
- `method`: HTTP metodu (GET, POST, PUT, DELETE)
- `path`: İstenen URL yolu + query string
- `protocol`: HTTP versiyonu
- `status`: HTTP durum kodu (200, 401, 404 vb.)
- `size`: Yanıt boyutu (byte)
- `referer`: Referrer URL
- `user_agent`: Tarayıcı/araç bilgisi
- `raw`: Orijinal ham satır

## 2. Apache

**Format:** Apache combined log format (nginx ile çok benzer)

```
IP - USER [TIMESTAMP] "METHOD PATH PROTOCOL" STATUS SIZE "REFERER" "USER-AGENT"
```

**Örnek:**
```
10.0.0.1 - admin [15/Jan/2024:10:30:00 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "http://example.com" "Mozilla/5.0"
```

**Kullanım:**
```bash
python log_analyzer.py analyze -f /var/log/apache2/access.log -F apache
```

**Nginx'ten Farkı:** Timestamp ve regex formatı biraz farklı, ama ayrıştırılan alanlar aynı.

## 3. Syslog

**Format:** Linux syslog formatı (SSH, sudo, cron vb.)

```
MONTH DAY TIME HOSTNAME SERVICE[PID]: MESSAGE
```

**Örnek:**
```
Jan 15 10:30:22 web01 sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2
Jan 15 10:30:25 web01 sshd[1235]: Failed password for admin from 10.0.0.1 port 22 ssh2
```

**Kullanım:**
```bash
python log_analyzer.py analyze -f /var/log/auth.log -F syslog
```

**Ayrıştırılan Alanlar:**
- `timestamp`: Ay gün saat
- `hostname`: Sunucu adı
- `service`: Servis adı (sshd, sudo vb.)
- `pid`: Process ID
- `message`: Log mesajı
- `ip`: Mesajdan çıkarılan IP (varsa)

**Tespit Ettiği Tehditler:**
- SSH brute force (tekrarlı "Failed password")
- Başarısız sudo denemeleri
- Bilinmeyen kullanıcı girişimleri

## 4. Windows Event Log

**Format:** Dışa aktarılmış Windows Security Event Log

```
TIMESTAMP EventID: MESSAGE Source: IP Account: USER
```

**Örnek:**
```
2024-01-15T10:30:00 EventID: 4625 An account failed to log on. Source: 10.0.0.1 Account: Administrator
```

**Kullanım:**
```bash
python log_analyzer.py analyze -f security.log -F windows
```

**Desteklenen Event ID'ler:**
- `4625`: Başarısız giriş (logon failure)
- `4624`: Başarılı giriş
- `4648`: Explicit credential ile giriş
- `4672`: Özel yetki atanması

## Format Otomatik Tespiti

Şu an otomatik tespit yoktur — format belirtilmelidir. İpuçları:

| Dosya Yolu | Format |
|---|---|
| `/var/log/nginx/access.log` | `nginx` |
| `/var/log/apache2/access.log` | `apache` |
| `/var/log/auth.log` | `syslog` |
| `/var/log/syslog` | `syslog` |
| `security.evtx` (dışa aktarılmış) | `windows` |

## Özel Format Ekleme

Yeni bir parser eklemek için:

1. `src/parsers/` dizininde yeni dosya oluştur (örn: `haproxy.py`)
2. `BaseParser` sınıfından türet
3. `parse_line()` ve `parse_file()` metodlarını implement et
4. `src/parsers/__init__.py`'de kaydet

```python
# src/parsers/haproxy.py
from src.parsers import BaseParser, LogEntry

class HaproxyParser(BaseParser):
    def parse_line(self, line: str) -> LogEntry | None:
        # ... parsing logic
        pass
```