# SQL-IDS Real-Time Streaming (Elasticsearch + Kibana)

Bu klasör, ensemble IDS modelini **satır satır (streaming)** işleyerek yalnızca tespit edilen **attack** kayıtlarını anlık olarak Elasticsearch’e yazar. Kibana dashboard’u SOC ortamı gibi canlı güncellenir.

## Proje yapısı

```text
project002/
├── docker-compose.yml
├── models/
│   ├── ensemble_model.pkl
│   └── tfidf_vectorizer.pkl
├── data/
│   └── *.csv
└── test/
    ├── run.py              # Real-time streaming pipeline
    ├── config.py           # paths, aliases, streaming flags
    ├── dataset_loader.py   # encoding + column + label normalization
    ├── model_evaluation.py # accuracy, F1, confusion matrix, JSON export
    ├── requirements.txt
    ├── README.md
    └── logs/run.log
```

## Yapılandırma (`config.py`)

| Sabit | Açıklama | Varsayılan |
|--------|-----------|------------|
| `REAL_TIME_MODE` | Satırlar arası bekleme | `True` |
| `SLEEP_INTERVAL` | Bekleme süresi (sn) | `0.5` |
| `INDEX_ONLY_ATTACKS` | Yalnızca attack ES’e gider | `True` |
| `TEST_DATASET_PATH` | Test CSV dosyası | `data/sqliv2.csv` |
| `MAX_ROWS` | Demo satır limiti (`0` = hepsi) | `0` |
| `KNOWN_DATASETS` | Hazır dosya kısayolları | aşağıda |

### Farklı dataset kullanma

`config.py` içinde yolu değiştirin veya preset kullanın:

```python
# Yöntem 1 — doğrudan dosya
TEST_DATASET_PATH = PROJECT_ROOT / "data" / "SQLiV3.csv"

# Yöntem 2 — preset
TEST_DATASET_PATH = KNOWN_DATASETS["sqliv3"]

# Büyük dosyada hızlı demo
MAX_ROWS = 500
SLEEP_INTERVAL = 0.3
```

| Preset | Dosya | Encoding | Kolonlar |
|--------|--------|----------|----------|
| `sqliv3` | `SQLiV3.csv` | UTF-8 | Sentence, Label |
| `sqliv2` | `sqliv2.csv` | UTF-16 | Sentence, Label |
| `sqli` | `sqli.csv` | UTF-16 | Sentence, Label |
| `merged` | `merged_cleaned_preprocessed.csv` | UTF-8 | Sentence, normalized_query, Label, dataset_source |

`dataset_loader.py` otomatik olarak:

- **Encoding:** UTF-8, UTF-16 (BOM), cp1252, latin-1
- **Ayırıcı:** virgül veya otomatik sniff (`;` vb.)
- **Metin kolonu:** `Sentence`, `payload`, `query`, `full_query`, …
- **Etiket:** `Label`, `class`, `target`, `is_sqli`, … → `0` / `1`
- **Etiket stringleri:** `sqli`, `malicious`, `benign`, `true`/`false`, …
- **Temizlik:** `Unnamed:*` kolonları, boş satırlar, geçersiz label

Kendi CSV’niz farklı isimdeyse `TEXT_COLUMN_ALIASES` / `LABEL_COLUMN_ALIASES` listesine ekleyin.

---

## 1. Docker başlatma

```bash
cd project002
docker compose up -d
```

- Elasticsearch: http://localhost:9200  
- Kibana: http://localhost:5601  

```bash
curl http://localhost:9200/_cluster/health?pretty
```

---

## 2. Python kurulumu

```powershell
cd test
..\..venv\Scripts\python.exe -m pip install -r requirements.txt
```

veya proje kökündeki `.venv`:

```powershell
.\.venv\Scripts\python.exe -m pip install -r test\requirements.txt
```

---

## 3. Real-time pipeline çalıştırma

```powershell
.\.venv\Scripts\python.exe test\run.py
```

### Akış (her satır)

```text
preprocess (TF-IDF, tek satır)
    → predict + predict_proba
    → attack ise → es.index() anında
    → normal ise → atla (INDEX_ONLY_ATTACKS)
    → sleep (REAL_TIME_MODE)
```

### Canlı konsol çıktısı

```text
[+] Row 120 processed -> ATTACK (SQL_Injection) | confidence: 0.98
[+] Row 121 processed -> NORMAL (skipped)
[!] Row 122 processed -> ATTACK (SQL_Injection) | confidence: 0.91 (index failed)
```

### Özet (sonda)

```text
Toplam işlenen kayıt
Toplam attack (tahmin)
Toplam normal (tahmin)
Elasticsearch'e gönderilen
Index başarısız
Attack / Normal yüzdesi
```

**Durdurmak:** `Ctrl+C` — stream güvenli şekilde kesilir.

### Model evaluation (stream bittikten sonra)

`run.py` yapısı:

```text
run.py
 ├── stream_predict_and_send()   # real-time ES + örnek toplama
 ├── evaluate_model()            # metrikler + rapor
 └── main()
```

| Ayar | Varsayılan |
|------|------------|
| `RUN_MODEL_EVALUATION` | `True` |
| `EXPORT_METRICS_JSON` | `True` |
| `METRICS_JSON_PATH` | `test/metrics_report.json` |

- **Binary:** `Label` (0/1) vs tahmin — sklearn `classification_report`, confusion matrix
- **Multi-class:** `attack_type` kolonu ve ≥2 sınıf varsa — `average="weighted"`
- Her satırda `y_true` / `y_pred` listeye eklenir; stream sonunda rapor basılır

---

## 4. Elasticsearch document (yalnızca attack)

```json
{
  "timestamp": "2026-06-01T14:32:01.456Z",
  "row_id": 120,
  "prediction": "attack",
  "confidence": 0.98,
  "attack_type": "SQL_Injection",
  "features": {
    "Sentence": "1' OR '1'='1",
    "Label": 1
  }
}
```

- `timestamp`: her kayıt için **o anki UTC**
- Normal trafik index’e **yazılmaz** (SOC feed)
- `attack_type`: CSV’de kolon varsa oradan; yoksa `SQL_Injection`

---

## 5. Kibana — Real-time SOC dashboard

### 5.1 Data view

1. **Stack Management** → **Data Views** → **Create**
2. Name: `sql_ids_predictions`
3. Index pattern: `sql_ids_predictions`
4. Timestamp field: **`timestamp`**
5. Save

### 5.2 Time filter (canlı akış)

Dashboard veya Discover’da:

- **Time range:** `Last 15 minutes` (veya `Last 1 hour` demo sırasında)
- Sağ üst **time picker** → Quick select → **Last 15 minutes**

Stream çalışırken zaman penceresini dar tutun; yeni attack’lar anında görünür.

### 5.3 Auto-refresh (5 saniye) — ZORUNLU demo ayarı

1. Dashboard’u açın
2. Sağ üst **Refresh** yanındaki interval
3. **5 seconds** seçin
4. Auto-refresh’i **açık** bırakın

Discover’da da aynı: üst menüden refresh interval → **5 s**.

### 5.4 Önerilen paneller

| Panel | Tip | Ayar |
|--------|-----|------|
| **Attack flow** | Line / Area (Lens) | X: `@timestamp` / `timestamp`, Date histogram **auto** veya 30s; Y: Count; Filter: `prediction: attack` |
| **Attack types** | Bar / Pie | Breakdown: `attack_type.keyword` veya `attack_type` |
| **Confidence** | Histogram | Field: `confidence`, interval `0.05` |
| **Live feed** | Data table | Columns: `timestamp`, `row_id`, `confidence`, `features.Sentence`; Sort: `timestamp` desc |
| **Prediction breakdown** | Pie | Slice: `prediction` (yalnızca attack indexlendiği için tek dilim olabilir; confidence dağılımı için histogram kullanın) |

> Index’e yalnızca `attack` gittiği için “Attack vs Normal” pie chart yerine **confidence histogram** ve **attack timeline** daha anlamlıdır.

### 5.5 Dashboard oluşturma adımları

1. **Analytics** → **Dashboard** → **Create dashboard**
2. **Add visualization** → Lens
3. **Attack Timeline:** Vertical axis = Count, Horizontal = `timestamp`, Date histogram interval = **Auto** veya **30 seconds**
4. İkinci panel: **Top attack types** → Bar chart → `attack_type`
5. Üçüncü panel: **Confidence histogram**
6. **Save dashboard** → ad: `SQL-IDS SOC Live`
7. Time: **Last 15 minutes**, Refresh: **5 seconds**
8. `run.py` çalıştırın — grafikler canlı dolacaktır

---

## 6. Örnek Kibana / Elasticsearch sorguları

### Son 15 dakikadaki attack’lar

```json
GET sql_ids_predictions/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "prediction": "attack" } },
        {
          "range": {
            "timestamp": {
              "gte": "now-15m"
            }
          }
        }
      ]
    }
  },
  "sort": [{ "timestamp": "desc" }],
  "size": 50
}
```

### Attack timeline (30 saniyelik bucket)

```json
GET sql_ids_predictions/_search
{
  "size": 0,
  "query": {
    "range": { "timestamp": { "gte": "now-15m" } }
  },
  "aggs": {
    "attack_flow": {
      "date_histogram": {
        "field": "timestamp",
        "fixed_interval": "30s"
      }
    }
  }
}
```

### Top attack types

```json
GET sql_ids_predictions/_search
{
  "size": 0,
  "aggs": {
    "top_attack_types": {
      "terms": {
        "field": "attack_type",
        "size": 10
      }
    }
  }
}
```

### Confidence histogram

```json
GET sql_ids_predictions/_search
{
  "size": 0,
  "aggs": {
    "confidence_hist": {
      "histogram": {
        "field": "confidence",
        "interval": 0.05
      }
    }
  }
}
```

### Canlı kayıt sayısı

```bash
curl "http://localhost:9200/sql_ids_predictions/_count?pretty"
```

---

## 7. Performans ve hata dayanıklılığı

| Özellik | Davranış |
|---------|----------|
| ES bağlantı | Başlangıçta retry + health wait |
| `es.index()` hata | Satır bazında retry; başarısızsa log + **devam** |
| Timeout | `ES_REQUEST_TIMEOUT` (varsayılan 30 sn) |
| Tek satır predict hatası | Log + sonraki satıra geç |

`config.py`:

```python
REAL_TIME_MODE = True   # False → sleep yok (hızlı test)
SLEEP_INTERVAL = 0.5    # 0.2 – 1.0 demo için ideal
INDEX_ONLY_ATTACKS = True
```

---

## 8. Sorun giderme

| Sorun | Çözüm |
|--------|--------|
| Kibana boş | `run.py` çalışıyor mu? Time range `Last 15 minutes`? |
| Grafik güncellenmiyor | Auto-refresh **5 s** açık mı? |
| Çok yavaş | `SQLiV3.csv` + `SLEEP_INTERVAL=0.2` |
| `ModuleNotFoundError` | `.venv` içine `pip install -r test/requirements.txt` |
| Index failed | `docker compose ps`, ES logları |

---

## 9. Eski batch mod

Önceki sürüm tüm veriyi toplu `bulk` ile gönderiyordu. Güncel `run.py` yalnızca **streaming + real-time index** kullanır. Toplu test için `REAL_TIME_MODE = False` ve `SLEEP_INTERVAL = 0` yaparak hızlandırabilirsiniz (yine satır satır index).
