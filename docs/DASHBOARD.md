# 📈 Dashboard — Web Arayüzü

Flask tabanlı gerçek zamanlı web dashboard'u. Analiz sonuçlarını tarayıcıda görselleştirir.

## Başlatma

```bash
# Basit başlatma
python log_analyzer.py dashboard

# Port belirterek
python log_analyzer.py dashboard --port 9090

# Önceden bir dosya analiz ederek başlat
python log_analyzer.py dashboard --file access.log --port 8080
```

Tarayıcıda aç: `http://localhost:8080`

## Parametreler

| Parametre | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--port` | `-p` | `8080` | Dashboard portu |
| `--host` | `-h` | `0.0.0.0` | Dinlenecek adres |
| `--file` | `-f` | — | Başlatırken analiz edilecek dosya |
| `--format` | `-F` | `nginx` | Log formatı |

## Dashboard Özellikleri

### Ana Sayfa
- **Tehdit Özeti**: Toplam tehdit, severity dağılımı
- **Pasta Grafik**: Tehdit türleri dağılımı (Chart.js)
- **Saldırgan Tablosu**: En aktif IP'ler ve tehdit sayıları
- **Zaman Çizelgesi**: Saat bazında saldırı yoğunluğu

### API Endpoints

Dashboard aynı zamanda bir REST API sunar:

```
GET /                  → Dashboard HTML sayfası
GET /api/status        → Sistem durumu (JSON)
GET /api/threats       → Tehdit listesi (JSON)
POST /api/analyze      → Dosya analizi tetikle
```

### API Kullanım Örneği

```bash
# Durum kontrolü
curl http://localhost:8080/api/status

# Tehdit listesi
curl http://localhost:8080/api/threats
```

## Uzaktan Erişim

Dashboard varsayılan olarak `0.0.0.0`'da dinler — aynı ağdaki tüm cihazlardan erişilebilir:

```bash
# Sunucuda başlat
python log_analyzer.py dashboard --port 8080

# Başka bilgisayardan aç
http://SUNUCU_IP:8080
```

### Güvenlik Notları

- Dashboard'u internete açmayın — sadece iç ağda kullanın
- Dışarıya açmak zorundaysanız nginx reverse proxy + auth ekleyin
- `FLASK_SECRET_KEY`'i `.env`'de rastgele bir değere ayarlayın

## Uzun Süreli Çalıştırma

```bash
# tmux ile
tmux new -s dashboard
python log_analyzer.py dashboard --port 8080 --file /var/log/nginx/access.log
# Ctrl+B, D ile detach, tmux attach -t dashboard ile geri dön

# systemd servisi olarak (opsiyonel)
# /etc/systemd/system/log-analyzer-dashboard.service dosyası oluşturarak
```