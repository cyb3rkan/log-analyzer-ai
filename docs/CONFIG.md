# ⚙️ Konfigürasyon Rehberi

## Dosyalar

| Dosya | Açıklama |
|---|---|
| `config.yaml` | Ana ayarlar (tespit kuralları, whitelist, dashboard) |
| `.env` | Gizli bilgiler (API key, webhook URL) |

Her ikisi de `.gitignore`'da — GitHub'a yüklenmez.

## config.yaml Yapısı

### Tespit Ayarları

```yaml
detection:
  brute_force:
    enabled: true
    threshold: 5        # Kaç başarısız giriş = alarm
    window: 60          # Zaman penceresi (saniye)
  sql_injection:
    enabled: true
    use_ai: false       # true yapınca AI de analiz eder
  path_traversal:
    enabled: true
  xss:
    enabled: true
  suspicious_ua:
    enabled: true
```

### Whitelist

```yaml
whitelist:
  ips:
    - 127.0.0.1          # Localhost
    # - "192.168.0.0/16"  # DİKKAT: Geniş aralıklar tehditleri kaçırır!
  user_agents:
    - GoogleBot
    - Bingbot
```

**⚠️ Uyarı:** `10.0.0.0/8` veya `192.168.0.0/16` gibi geniş CIDR blokları eklemeyin. Bu aralıklardaki TÜM trafik (saldırılar dahil) atlanır.

### AI Ayarları

```yaml
ai:
  provider: openai           # openai
  model: gpt-4o-mini         # Önerilen modeller aşağıda
  api_key: "${OPENAI_API_KEY}"  # .env'den otomatik çekilir
```

**Önerilen OpenAI modelleri:** `gpt-4o-mini` (ucuz/hızlı), `gpt-4o` (detaylı), `gpt-4-turbo` (maksimum)

### Otomatik Yanıt

```yaml
response:
  auto_block:
    enabled: false         # true = saldırgan IP'leri otomatik engelle
    method: iptables       # iptables veya ufw
    duration: 3600         # Engelleme süresi (saniye)
  alerts:
    slack:
      enabled: false
      webhook_url: "${SLACK_WEBHOOK}"
```

### Dashboard

```yaml
dashboard:
  host: 0.0.0.0
  port: 8080
```

## .env Değişkenleri

| Değişken | Zorunlu | Açıklama |
|---|---|---|
| `OPENAI_API_KEY` | Hayır | OpenAI API anahtarı |
| `SLACK_WEBHOOK` | Hayır | Slack webhook URL'si |
| `FLASK_SECRET_KEY` | Hayır | Dashboard güvenlik anahtarı |
| `LOG_LEVEL` | Hayır | Log seviyesi (INFO varsayılan) |

## Ayar İpuçları

### Yanlış alarm azaltma
- Güvendiğin IP'leri whitelist'e ekle
- Brute force threshold'u artır (yoğun sunucular için)

### Hassasiyeti artırma
- Brute force threshold'u düşür
- `use_ai: true` ile AI desteğini aç
- Clean traffic ile ML modeli eğit
