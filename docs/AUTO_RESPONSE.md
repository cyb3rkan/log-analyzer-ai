# 🚀 Otomatik Yanıt — IP Engelleme ve Slack Bildirimleri

Tehdit tespit edildiğinde otomatik aksiyonlar alınabilir: saldırgan IP engelleme ve Slack bildirimi.

## ⚠️ Dikkat

Otomatik IP engelleme **varsayılan olarak kapalıdır**. Yanlış yapılandırma meşru trafiği engelleyebilir. Test ortamında deneyin, sonra production'a alın.

## IP Engelleme

### Yapılandırma

`config.yaml`:
```yaml
response:
  auto_block:
    enabled: true         # true = otomatik engelle
    method: iptables      # iptables veya ufw
    duration: 3600        # Engelleme süresi (saniye, 0 = kalıcı)
```

### Desteklenen Yöntemler

#### iptables
```yaml
method: iptables
```
Arka planda çalışan komut:
```bash
iptables -A INPUT -s SALDIRGAN_IP -j DROP
# duration sonra otomatik kaldırılır:
iptables -D INPUT -s SALDIRGAN_IP -j DROP
```

#### ufw (Uncomplicated Firewall)
```yaml
method: ufw
```
Arka planda çalışan komut:
```bash
ufw deny from SALDIRGAN_IP
```

### Gereksinimler

- **Root yetkisi** gerekir (`sudo` ile çalıştır)
- iptables veya ufw yüklü olmalı
- Test ortamında dene, sonra production'a al

### Örnek Senaryo

```
1. Watch modu çalışıyor
2. 192.168.36.1'den 5 başarısız giriş → BRUTE_FORCE tespit
3. auto_block enabled → iptables kuralı eklenir
4. 192.168.36.1 artık sunucuya erişemez
5. 3600 saniye sonra kural kaldırılır
```

## Slack Bildirimleri

### 1. Slack Webhook Oluştur

1. https://api.slack.com/apps adresine git
2. "Create New App" → "From scratch"
3. "Incoming Webhooks" → "Activate"
4. "Add New Webhook to Workspace"
5. Kanal seç (örn: `#security-alerts`)
6. Webhook URL'sini kopyala

### 2. Yapılandırma

`.env`:
```env
SLACK_WEBHOOK=https://hooks.slack.com/services/T0AFKGWP6V8/B0AGDR6QUV6/xxxxxxxxxxxx
```

`config.yaml`:
```yaml
response:
  alerts:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK}"
```

### 3. Slack Mesaj Formatı

Tehdit tespit edildiğinde Slack kanalına gelen mesaj:

```
🚨 Log Analyzer AI — Threat Detected
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Type     : SQL_INJECTION
Severity : CRITICAL
Source IP: 203.0.113.50
Details  : SQL Injection from 203.0.113.50
Time     : 2026-02-25 14:32:00
```

## İkisini Birlikte Kullanma

```yaml
response:
  auto_block:
    enabled: true
    method: ufw
    duration: 7200       # 2 saat engelle

  alerts:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK}"
```

Bu yapılandırmayla:
1. Tehdit tespit edilir
2. Saldırgan IP otomatik engellenir (2 saat)
3. Slack kanalına bildirim gönderilir
4. Rapor dosyasına kaydedilir

## Sadece Bildirim (Engelleme Olmadan)

Çoğu durumda önce sadece bildirim açıp izlemek daha güvenlidir:

```yaml
response:
  auto_block:
    enabled: false        # Engelleme kapalı

  alerts:
    slack:
      enabled: true       # Sadece bildirim
      webhook_url: "${SLACK_WEBHOOK}"
```

## Özel Webhook Test

```bash
# Webhook'un çalıştığını test et
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"🧪 Test — Log Analyzer AI webhook çalışıyor!"}' \
  https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

## Diğer Bildirim Kanalları

Şu an sadece Slack destekleniyor. Gelecekte eklenebilecekler:
- Discord webhook
- Telegram bot
- E-posta (SMTP)
- PagerDuty
- Microsoft Teams