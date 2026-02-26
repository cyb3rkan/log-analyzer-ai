# 🔧 Sorun Giderme

## Sık Karşılaşılan Hatalar

### 1. `ModuleNotFoundError: No module named 'src'`

**Sebep:** Proje kök dizininden çalıştırılmıyor.

```bash
cd log-analyzer-ai     # Proje dizinine gir
python log_analyzer.py analyze --file test.log
```

### 2. `ModuleNotFoundError: No module named 'click'`

**Sebep:** Bağımlılıklar yüklenmemiş.

```bash
pip install -r requirements.txt
```

### 3. `0 threats detected` — Hiç tehdit bulunamıyor

**Olası sebepler:**

1. **Whitelist sorunu** — `config.yaml`'daki whitelist tüm IP'leri kapsıyor olabilir:
   ```yaml
   # ❌ YANLIŞ - tüm 192.168.x.x trafiği atlanır
   whitelist:
     ips:
       - "192.168.0.0/16"
   
   # ✅ DOĞRU - sadece belirli IP'ler
   whitelist:
     ips:
       - 127.0.0.1
   ```

2. **Yanlış format** — Log formatını kontrol et:
   ```bash
   python log_analyzer.py analyze --file test.log --format nginx
   python log_analyzer.py analyze --file test.log --format apache
   ```

3. **Bozuk log dosyası** — Dosyanın gerçek log satırları içerdiğinden emin ol.

### 4. AI çalışmıyor

**Adım adım kontrol:**

```bash
# 1. Bağlantı testi
python log_analyzer.py test-ai

# 2. Paket yüklü mü?
pip install openai

# 3. .env dosyasında key var mı?
cat .env | grep OPENAI

# 4. Key doğru mu? (https://platform.openai.com/api-keys)
```

### 5. `PermissionError` — İzin hatası

```bash
# Log dosyasını okuma izni
sudo chmod +r /var/log/nginx/access.log
# veya
sudo python log_analyzer.py analyze --file /var/log/nginx/access.log
```

### 6. Dashboard açılmıyor

```bash
# Port meşgul mü?
python log_analyzer.py dashboard --port 9090

# Firewall kontrolü
sudo ufw allow 8080
```

### 7. `config.yaml not found`

```bash
cp config.example.yaml config.yaml
```

## Debug Modu

Daha fazla bilgi için:
```bash
LOG_LEVEL=DEBUG python log_analyzer.py analyze --file test.log
```

## Testleri Çalıştır

Kurulumu doğrulamak için:
```bash
python test_all_features.py
```

Tüm testler `✅ PASS` olmalı.
