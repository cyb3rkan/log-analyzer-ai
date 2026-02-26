# 🛡️ Tehdit Tespit Türleri

Sistem 5 farklı tehdit türünü tespit eder. Her biri kural tabanlı regex pattern matching ile çalışır.

## 1. SQL Injection (CRITICAL)

Veritabanına yetkisiz erişim girişimleri.

**Tespit Edilen Patternler:**
- `' OR 1=1`, `" OR ""="`, `' OR 'a'='a`
- `UNION SELECT`, `UNION ALL SELECT`
- `information_schema`, `table_name`, `column_name`
- `database()`, `version()`, `user()`
- `DROP TABLE`, `INSERT INTO`, `UPDATE SET`
- `SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY`
- `LOAD_FILE(`, `INTO OUTFILE`

**URL-Encoded Saldırılar (v2.0'da eklendi):**
- `%27+UNION+SELECT` → `' UNION SELECT`
- `%27+OR+1%3D1%23` → `' OR 1=1#`
- `information_schema` encoded versiyonları

**Örnek Log:**
```
GET /search?q=' UNION SELECT username,password FROM users-- HTTP/1.1
GET /dvwa/vulnerabilities/sqli/?id=1%27+union+select+1,table_name+from+information_schema.tables
```

## 2. XSS — Cross-Site Scripting (HIGH)

Tarayıcıda kötü amaçlı JavaScript çalıştırma girişimleri.

**Tespit Edilen Patternler:**
- `<script>`, `</script>`, `<script src=`
- `javascript:`, `vbscript:`
- `onerror=`, `onload=`, `onclick=`, `onmouseover=`
- `alert(`, `prompt(`, `confirm(`
- `document.cookie`, `document.write`
- `eval(`, `String.fromCharCode`

**Örnek Log:**
```
GET /comment?text=<script>alert(document.cookie)</script> HTTP/1.1
GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1
```

## 3. Path Traversal (HIGH)

Sunucudaki hassas dosyalara yetkisiz erişim girişimleri.

**Tespit Edilen Patternler:**
- `../`, `..\\`, `..%2f`, `..%5c`
- `/etc/passwd`, `/etc/shadow`, `/etc/hosts`
- `wp-config.php`, `web.config`, `.htaccess`
- `/proc/self/`, `C:\\Windows\\`, `boot.ini`

**Örnek Log:**
```
GET /download?file=../../../etc/passwd HTTP/1.1
GET /static/..%2f..%2f..%2fetc%2fshadow HTTP/1.1
```

## 4. Brute Force (HIGH)

Kısa sürede çok sayıda başarısız giriş denemesi.

**Tespit Mantığı:**
- Aynı IP'den belirli sürede (varsayılan: 60 saniye) belirli sayıda (varsayılan: 5) başarısız giriş → alarm
- HTTP 401 veya 403 yanıtlarını sayar
- Login endpointlerini izler: `/login`, `/wp-login.php`, `/admin`, `/auth`

**Ayarlanabilir Parametreler (config.yaml):**
```yaml
detection:
  brute_force:
    enabled: true
    threshold: 5    # Kaç deneme sonra alarm
    window: 60      # Zaman penceresi (saniye)
```

**Örnek Log Dizisi:**
```
198.51.100.77 - - [...] "POST /wp-login.php HTTP/1.1" 401 512
198.51.100.77 - - [...] "POST /wp-login.php HTTP/1.1" 401 512
198.51.100.77 - - [...] "POST /wp-login.php HTTP/1.1" 401 512
198.51.100.77 - - [...] "POST /wp-login.php HTTP/1.1" 401 512
198.51.100.77 - - [...] "POST /wp-login.php HTTP/1.1" 401 512
→ 🚨 BRUTE_FORCE tespit!
```

## 5. Suspicious User-Agent (MEDIUM)

Bilinen saldırı araçları ve scanner'lar.

**Tespit Edilen Araçlar:**
- `sqlmap` — SQL injection aracı
- `nikto` — Web sunucu scanner
- `nmap` — Port/servis tarayıcı
- `dirbuster`, `gobuster` — Dizin keşif araçları
- `wpscan` — WordPress scanner
- `masscan` — Hızlı port tarayıcı
- `hydra` — Brute force aracı
- `burpsuite` — Web güvenlik testi
- `zgrab`, `censys` — İnternet tarayıcıları
- `python-requests` (bazı bağlamlarda)

**Örnek Log:**
```
GET /admin HTTP/1.1" 200 512 "-" "sqlmap/1.7.11#stable"
GET /cgi-bin/test-cgi HTTP/1.1" 404 0 "-" "Nikto/2.1.6"
```

## Severity Seviyeleri

| Seviye | Renk | Anlam |
|---|---|---|
| **CRITICAL** | 🔴 Kırmızı | Aktif saldırı — hemen müdahale gerekli |
| **HIGH** | 🟡 Sarı | Onaylanmış saldırı girişimi |
| **MEDIUM** | 🔵 Mavi | Şüpheli aktivite, izlenmeli |
| **LOW** | 🟢 Yeşil | Düşük riskli anomali |

## Tespit Akışı

```
Log Satırı
    │
    ▼
┌─────────────┐
│  URL Decode  │  ← %27+UNION → ' UNION
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌──────────────┐
│  Whitelist   │────▶│  Whitelist'te │ → Atla
│  Kontrolü    │     │  değilse ↓    │
└──────┬──────┘     └──────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Pattern Matching (5 tehdit türü)   │
│  SQLi → XSS → PathTrav → UA → BF   │
└──────┬──────────────────────────────┘
       │
       ▼
   ThreatEvent (type, severity, IP, description)
```

## Her Türü Açma/Kapama

`config.yaml`'da her tespit türü ayrı ayrı kontrol edilir:

```yaml
detection:
  sql_injection:
    enabled: true       # false yapınca SQLi tespiti kapanır
  xss:
    enabled: true
  path_traversal:
    enabled: true
  suspicious_ua:
    enabled: true
  brute_force:
    enabled: true
    threshold: 5
    window: 60
```