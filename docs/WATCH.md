# 👁️ Watch — Canlı Log İzleme

`tail -f` gibi çalışır: log dosyasını gerçek zamanlı izler, yeni satırlar eklendikçe analiz eder.

## Temel Kullanım

```bash
python log_analyzer.py watch --file /var/log/nginx/access.log
```

Çıktı:
```
🛡️  Watching: /var/log/nginx/access.log
Ctrl+C to stop

🚨 [CRITICAL] SQL_INJECTION | 203.0.113.50 | SQL Injection from 203.0.113.50
🚨 [MEDIUM] SUSPICIOUS_UA | 198.51.100.10 | Suspicious UA: sqlmap/1.7
🚨 [HIGH] PATH_TRAVERSAL | 192.0.2.99 | Path Traversal from 192.0.2.99
```

## Parametreler

| Parametre | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--file` | `-f` | — | İzlenecek log dosyası (zorunlu) |
| `--format` | `-F` | `nginx` | Log formatı |

## Nasıl Çalışır

1. Dosyanın **sonuna** atlar (mevcut logları atlar)
2. Yeni satır eklendiğinde anında okur
3. Her satırı parser'dan geçirir
4. Tehdit tespit edilirse terminale basar
5. `Ctrl+C` ile durur

**Not:** Watch yalnızca başlattıktan **sonra** eklenen satırları analiz eder. Mevcut logları analiz etmek için `analyze` komutunu kullan.

## Test Etme

### Yöntem 1: Otomatik Demo (Tek Terminal)

```bash
python test_watch_demo.py
```

Otomatik olarak log yazar ve watch'un tespit ettiğini gösterir.

### Yöntem 2: Manuel Test (İki Terminal)

```bash
# Terminal 1 — Watch başlat
python log_analyzer.py watch --file access.log

# Terminal 2 — Log generator başlat
python live_log_generator.py
```

Generator nginx formatında sahte saldırı logları üretir (SQL injection, XSS, brute force vb.).

### Yöntem 3: Tek Satır Test

```bash
# Terminal 1 — Watch başlat
touch test.log
python log_analyzer.py watch --file test.log

# Terminal 2 — Elle log yaz
echo '1.2.3.4 - - [25/Feb/2026:12:00:00 +0000] "GET /q?id=1 UNION SELECT * FROM users HTTP/1.1" 200 512 "-" "sqlmap/1.7"' >> test.log
```

## Gerçek Sunucuda Kullanım

```bash
# Nginx
python log_analyzer.py watch -f /var/log/nginx/access.log

# Apache
python log_analyzer.py watch -f /var/log/apache2/access.log -F apache

# SSH logları
python log_analyzer.py watch -f /var/log/auth.log -F syslog
```

## İpuçları

- Watch sadece **yeni** satırları okur, başlattıktan sonraki trafiği izler
- Dosya yoksa hata verir → önce `touch dosya.log` ile oluştur
- Brute force tespiti için threshold (varsayılan: 5 deneme / 60 saniye) `config.yaml`'dan ayarlanır
- Uzun süre çalıştırmak için `screen` veya `tmux` kullan:
  ```bash
  tmux new -s watcher
  python log_analyzer.py watch -f /var/log/nginx/access.log
  # Ctrl+B, D ile detach
  ```