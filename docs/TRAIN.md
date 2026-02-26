# 🧠 Train — ML Anomali Tespiti

Isolation Forest algoritması ile normal trafik profilini öğrenir, anomalileri tespit eder.

## Nasıl Çalışır

1. **Eğitim**: Temiz (saldırısız) log dosyasıyla model eğitilir
2. **Model**: Normal trafik kalıplarını öğrenir (istek sıklığı, boyut, durum kodları vb.)
3. **Tespit**: Yeni loglar geldiğinde, modele uymayan kalıplar anomali olarak işaretlenir

Bu, kural tabanlı tespite ek bir katman sağlar. Kuralların yakalayamadığı sıfır-gün (zero-day) saldırıları tespit edebilir.

## Eğitim

```bash
python log_analyzer.py train --file clean_traffic.log
```

### Parametreler

| Parametre | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--file` | `-f` | — | Temiz trafik log dosyası (zorunlu) |
| `--format` | `-F` | `nginx` | Log formatı |
| `--output` | `-o` | `./models/trained_model.pkl` | Model kayıt yolu |

### Örnek

```bash
# 1. Temiz trafik topla (saldırı olmadığından emin olduğun bir dönem)
cp /var/log/nginx/access.log clean_traffic.log

# 2. Model eğit
python log_analyzer.py train -f clean_traffic.log

# Çıktı:
# Loaded 15000 entries
# Model saved: ./models/trained_model.pkl
```

## Temiz Trafik Nedir?

Model **normal** trafik kalıplarını öğrenir. Eğitim dosyasında saldırı satırları olmamalı.

**İyi eğitim verisi:**
- Bilinen güvenli dönemdeki loglar
- Bot/crawler trafiği filtrelenmiş
- En az 1000 satır (ideal: 10.000+)

**Kötü eğitim verisi:**
- Saldırı içeren loglar (model saldırıyı "normal" öğrenir)
- Çok az satır (< 100)
- Tek tip trafik (çeşitlilik lazım)

## Özellik Vektörü (Features)

Model şu özellikleri çıkarır:

| Özellik | Açıklama |
|---|---|
| `request_size` | İstek boyutu |
| `response_status` | HTTP durum kodu |
| `response_size` | Yanıt boyutu |
| `hour_of_day` | Gün içi saat |
| `path_length` | URL yolu uzunluğu |
| `path_depth` | URL derinliği (`/` sayısı) |
| `has_query` | Query string var mı (0/1) |
| `query_length` | Query string uzunluğu |
| `method_encoded` | HTTP metodu (numerik) |

## Model Dosyası

```
models/
├── trained_model.pkl     ← Eğitilmiş model (pickle)
├── classifier.py         ← AI sınıflandırıcı
└── anomaly_detector.py   ← Isolation Forest kodu
```

Model `pickle` formatında kaydedilir. Dosya boyutu genellikle 1-5 MB arasındadır.

## Kısıtlamalar

- Model sadece eğitim verisindeki trafik profilini bilir
- Eğitim verisi değişirse model yeniden eğitilmeli
- Regex kurallarının yerini almaz, tamamlar
- Çok az veri ile eğitilirse false positive oranı yüksek olur

## Kural Tabanlı vs ML Karşılaştırma

| | Kural Tabanlı | ML (Anomali) |
|---|---|---|
| Bilinen saldırılar | ✅ Kesin tespit | ⚠️ Belki |
| Sıfır-gün saldırıları | ❌ Kaçırabilir | ✅ Anomali olarak işaretler |
| False positive | Düşük | Orta-Yüksek |
| Eğitim gerekli mi | Hayır | Evet |
| Hız | Çok hızlı | Hızlı |

**Öneri:** İkisini birlikte kullan. Kural tabanlı tespit ana güvenlik katmanı, ML ise ek bir uyarı sistemi olarak çalışır.