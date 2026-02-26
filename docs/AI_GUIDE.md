# 🤖 AI Kullanım Rehberi

## Genel Bakış

Log Analyzer AI iki katmanlı tespit sistemi kullanır:

1. **Kural Tabanlı** (varsayılan) — Regex pattern matching, her zaman çalışır, API key gereksiz
2. **AI Destekli** (opsiyonel) — OpenAI ile gelişmiş analiz

AI olmadan da tüm temel özellikler çalışır. AI, ek bir analiz katmanı sağlar.

## OpenAI Kurulumu

### 1. API Key Al

1. https://platform.openai.com/api-keys adresine git
2. "Create new secret key" tıkla
3. Key'i kopyala

### 2. .env'ye Yaz

```env
OPENAI_API_KEY=sk-proj-...senin_keyin_buraya...
```

### 3. Test Et

```bash
python log_analyzer.py test-ai
```

Başarılı çıktı:
```
🤖 AI Connection Test

  Provider   : openai
  Model      : gpt-4o-mini
  API Key    : sk-proj-A3vq...usA

  ✅ CONNECTION SUCCESSFUL
  Test result: is_threat=False, type=NORMAL
```

### 4. Kullan

```bash
# AI ile batch analiz
python log_analyzer.py ai-analyze --file test.log --lines 30

# SOC analyst modu
python log_analyzer.py soc-analyze --file test.log --lines 100
```

## Önerilen Modeller

| Model | Hız | Maliyet | Kullanım |
|---|---|---|---|
| `gpt-4o-mini` | Hızlı | Ucuz | Günlük analiz, varsayılan |
| `gpt-4o` | Orta | Orta | Detaylı SOC analizi |
| `gpt-4-turbo` | Yavaş | Pahalı | Maksimum doğruluk |

Model değiştirmek için `config.yaml`:
```yaml
ai:
  provider: openai
  model: gpt-4o         # veya gpt-4o-mini, gpt-4-turbo
  api_key: "${OPENAI_API_KEY}"
```

## AI Komutları

### `ai-analyze` — AI ile Log Analizi

```bash
python log_analyzer.py ai-analyze --file test.log --lines 20
```

AI toplu analiz yapar ve şunları döndürür:
- Risk seviyesi (CRITICAL/HIGH/MEDIUM/LOW)
- Tespit edilen tehdit sayısı ve türleri
- Güvenlik önerileri
- İlk 5 satırın tek tek sınıflandırması

### `soc-analyze` — SOC Analyst Modu (Korelasyon)

```bash
python log_analyzer.py soc-analyze --file test.log --lines 100
```

`ai-analyze`'den **tamamen farklı** çalışır. AI'ya bir Kıdemli SOC Analisti rolü verir:

| Özellik | `ai-analyze` | `soc-analyze` |
|---|---|---|
| Yaklaşım | Her satırı ayrı değerlendir | Olayları korelatif analiz et |
| Çıktı | Satır başına tehdit | Kampanya başına olay |
| 300 sqlmap satırı | 300 ayrı alert | 1 kampanya |
| Gürültü | Yüksek | Minimum |
| Öneriler | Genel | Pratik SOC aksiyonları |

**SOC Modu şunları yapar:**

1. **Olay Korelasyonu** — Aynı IP + aynı saldırı türü = tek olay
2. **Kampanya Tespiti** — sqlmap taraması, brute force kampanyası gibi kalıplar
3. **Gürültü Azaltma** — 305 log satırı → 2 distinct campaign
4. **Davranış Analizi** — Keyword değil, davranış patternine bakılır
5. **False Positive Kontrolü** — Eğitim ortamları (DVWA), tek seferlik taramalar severity düşürür
6. **Defansif Öneriler** — Saldırı talimatı değil, WAF/rate-limit/monitoring tavsiyeleri

**Örnek çıktı:**
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

    [HIGH] Campaign #2
      IP          : 127.0.0.1
      Attack Type : TOOL_SCAN
      Attempts    : 10
      Tool        : sqlmap/1.7

  🛡️ Recommendations:
    • Block 192.168.36.1 at WAF level
    • Rate-limit requests to /dvwa/vulnerabilities/sqli/
    • Remove or restrict phpMyAdmin access
```

### `test-ai` — Bağlantı Testi

```bash
python log_analyzer.py test-ai
```

Kontrol eder:
- API key geçerli mi?
- `openai` paketi yüklü mü?
- Model erişilebilir mi?
- Yanıt doğru formatta mı?

## Sorun Giderme

### "Package missing" Hatası
```bash
pip install openai
```

### Rate Limit Hatası
- OpenAI rate limit'e takılmış olabilirsin, biraz bekle
- Daha düşük `--lines` değeri dene
- `gpt-4o-mini` daha yüksek rate limit'e sahip

### Model Bulunamıyor
Otomatik fallback sistemi alternatif modelleri dener (gpt-4o-mini → gpt-4o → gpt-4-turbo → gpt-3.5-turbo).
Manuel olarak değiştirmek için `config.yaml`'da `model:` alanını güncelle.

### Yanıt Alınamıyor
```bash
python log_analyzer.py test-ai
```
Bu komut detaylı hata bilgisi verir. API key'in geçerliliğini ve bakiyeni kontrol et.
