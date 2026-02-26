# ✅ Whitelist — Güvenli IP ve User-Agent Listesi

Whitelist'teki IP'ler ve User-Agent'lar analiz sırasında atlanır. False positive'leri azaltmak için kullanılır.

## Yapılandırma

`config.yaml` dosyasında:

```yaml
whitelist:
  ips:
    - 127.0.0.1           # Localhost
    - 10.0.0.5             # Monitoring sunucusu
    - 203.0.113.100        # Ofis IP'si
  user_agents:
    - GoogleBot            # Google crawler
    - Bingbot              # Bing crawler
    - UptimeRobot          # Uptime izleme
```

## IP Whitelist

### Tek IP
```yaml
ips:
  - 127.0.0.1
  - 10.0.0.5
```

### CIDR Bloğu
```yaml
ips:
  - "192.168.1.0/24"    # 192.168.1.0 — 192.168.1.255 (256 adres)
```

### ⚠️ Geniş CIDR Blokları — DİKKAT

```yaml
# ❌ TEHLİKELİ — Bunu YAPMA
ips:
  - "192.168.0.0/16"    # 65.536 IP atlanır!
  - "10.0.0.0/8"        # 16 milyon IP atlanır!
```

Bu kadar geniş bloklar saldırıları kaçırmana neden olur. Saldırgan iç ağdan geliyorsa (`192.168.x.x`) hiçbir alarm üretilmez.

```yaml
# ✅ DOĞRU — Sadece bildiğin IP'ler
ips:
  - 127.0.0.1
  - 192.168.1.50        # Monitoring sunucusu
  - 192.168.1.100       # Admin PC
```

**Kural:** Geniş CIDR blokları (1000+ adres) kullanırsan sistem uyarı verir:
```
Broad whitelist: 192.168.0.0/16 (65536 addrs) — may miss threats!
```

## User-Agent Whitelist

Belirli User-Agent string'leri içeren istekler atlanır (büyük/küçük harf duyarsız):

```yaml
user_agents:
  - GoogleBot
  - Bingbot
  - UptimeRobot
  - Pingdom
```

**Örnek:** User-Agent'ı `GoogleBot/2.1` olan bir istek SQL injection payload'ı içerse bile atlanır.

## Whitelist Nasıl Çalışır

```
Log Satırı Geldi
       │
       ▼
┌──────────────────┐
│ IP whitelist'te  │──── Evet ──→ ATLA (analiz yapma)
│ mi?              │
└───────┬──────────┘
        │ Hayır
        ▼
┌──────────────────┐
│ UA whitelist'te  │──── Evet ──→ ATLA (analiz yapma)
│ mi?              │
└───────┬──────────┘
        │ Hayır
        ▼
   Tehdit Analizi Başla
```

## Önerilen Whitelist

### Web Sunucu
```yaml
whitelist:
  ips:
    - 127.0.0.1
  user_agents:
    - GoogleBot
    - Bingbot
    - Googlebot-Image
    - YandexBot
    - UptimeRobot
```

### İç Ağ Testi
```yaml
whitelist:
  ips:
    - 127.0.0.1
    - 192.168.1.1         # Gateway
  user_agents: []          # Hiçbir UA'yı atlama
```

### Sıfır Whitelist (Maksimum Hassasiyet)
```yaml
whitelist:
  ips: []
  user_agents: []
```

Bu durumda localhost dahil her şey analiz edilir.

## Whitelist ve Watch

Watch (canlı izleme) sırasında da whitelist aktiftir. Whitelist'teki IP'lerden gelen saldırılar alarm üretmez.