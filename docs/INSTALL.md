# 🔧 Kurulum Rehberi

## Gereksinimler

- Python 3.11 veya üzeri
- pip (Python paket yöneticisi)

## Adım 1: Projeyi İndir

```bash
git clone https://github.com/KULLANICI/log-analyzer-ai.git
cd log-analyzer-ai
```

## Adım 2: Bağımlılıkları Kur

```bash
pip install -r requirements.txt
```

**Not:** AI özelliği için `openai` paketi gereklidir. `requirements.txt` bunu zaten içerir.

## Adım 3: Ayar Dosyalarını Oluştur

```bash
cp config.example.yaml config.yaml
cp .env.example .env
```

## Adım 4: .env Dosyasını Düzenle

`.env` dosyasını açıp API key'lerini gir:

```env
# OpenAI (key al: https://platform.openai.com/api-keys)
OPENAI_API_KEY=sk-proj-...

# Slack bildirimleri (opsiyonel)
SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

## Adım 5: Doğrulama

```bash
# Testleri çalıştır
python test_all_features.py

# AI bağlantısını test et
python log_analyzer.py test-ai

# İlk analizi yap
python log_analyzer.py analyze --file test.log
```

## Hızlı Kullanım

```bash
# Nginx log analizi
python log_analyzer.py analyze --file /var/log/nginx/access.log

# Apache log analizi
python log_analyzer.py analyze --file /var/log/apache2/access.log --format apache

# AI ile analiz
python log_analyzer.py ai-analyze --file access.log

# Dashboard
python log_analyzer.py dashboard --port 8080
```

## Sorun mu var?

→ [Sorun Giderme](TROUBLESHOOT.md) rehberine bak.
