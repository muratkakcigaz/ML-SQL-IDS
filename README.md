# SQL-IDS — SQL Injection Tespiti (Makine Öğrenmesi)

HTTP/SQL payload’ları üzerinden **SQL Injection (SQLi)** saldırılarını tespit eden bir makine öğrenmesi projesi. Metinler **TF-IDF** (`char_wb`, 3–5 gram) ile vektörleştirilir; **XGBoost**, **Random Forest**, **SGD** ve **Logistic Regression** modellerinin **soft voting ensemble**’ı ile sınıflandırma yapılır.

Eğitim ve deneyler **Jupyter notebook** akışıyla yürütülür. Canlı test ve SOC benzeri görselleştirme için `test/` altında **Elasticsearch + Kibana** ile **real-time streaming** pipeline bulunur.

---

## Özellikler

| Alan | Açıklama |
|------|----------|
| **Veri** | Birden fazla SQLi CSV (SQLiV3, sqliv2, sqli, birleştirilmiş set) |
| **Ön işleme** | Normalizasyon, etiket temizliği, tekrarların kaldırılması (`merge_clean_preprocess.ipynb`) |
| **Model** | TF-IDF + ensemble (`VotingClassifier`, soft voting) |
| **Değerlendirme** | Notebook metrikleri; streaming sonrası sklearn raporu (`test/model_evaluation.py`) |
| **Canlı akış** | Satır satır tahmin → yalnızca attack kayıtları ES’e → Kibana dashboard |
| **Dataset uyumu** | UTF-8 / UTF-16, farklı kolon adları (`test/dataset_loader.py`) |

---

## Proje yapısı

```text
project002/
├── data/                              # Ham ve işlenmiş CSV’ler
│   ├── SQLiV3.csv
│   ├── sqliv2.csv
│   ├── sqli.csv
│   └── merged_cleaned_preprocessed.csv
├── models/                            # Eğitilmiş artefaktlar
│   ├── ensemble_model.pkl             # Streaming / tahmin (ana model)
│   ├── tfidf_vectorizer.pkl           # Zorunlu (ensemble TF-IDF ile eğitildi)
│   ├── xgboost_model.pkl
│   ├── random_forest_model.pkl
│   ├── sgd_model.pkl
│   └── logistic_regression_model.pkl
├── plots/                             # Confusion matrix, metrik grafikleri
├── eda/                               # EDA notebook ve HTML raporları
├── merge_clean_preprocess.ipynb       # Veri birleştirme + temizleme
├── sql_ids_single_flow.ipynb          # Eğitim, validasyon, ensemble kaydı
├── requirements.txt                   # Notebook / ML bağımlılıkları
├── test/                              # Real-time IDS + Elastic Stack test ortamı
│   ├── docker-compose.yml             # Elasticsearch 8 + Kibana 8
│   ├── run.py                         # Streaming pipeline
│   ├── config.py
│   ├── dataset_loader.py
│   ├── model_evaluation.py
│   ├── requirements.txt
│   ├── metrics_report.json            # (çalıştırma sonrası)
│   └── README.md                      # Test ortamı detaylı dokümantasyon
└── README.md                          # Bu dosya
```

> **Not:** Kök dizinde `train.py`, `predict.py`, `preprocess.py` yoktur. Eğitim akışı notebook’lardadır.

---

## Hızlı başlangıç

### 1. Ortam

```powershell
cd project002
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -r test\requirements.txt
```

PowerShell script policy `Activate.ps1` engelliyorsa doğrudan `.venv\Scripts\python.exe` kullanın.

### 2. Model eğitimi (notebook)

Sıra önerisi:

1. `merge_clean_preprocess.ipynb` — veri birleştirme, `data/merged_cleaned_preprocessed.csv` üretimi  
2. `sql_ids_single_flow.ipynb` — train/val/test, modeller, `models/ensemble_model.pkl` ve `models/tfidf_vectorizer.pkl` kaydı  

### 3. Real-time test + Kibana (opsiyonel)

```powershell
cd test
docker compose up -d
cd ..
.\.venv\Scripts\python.exe test\run.py
```

- Elasticsearch: http://localhost:9200  
- Kibana: http://localhost:5601  
- Index: `sql_ids_predictions`  

Adım adım kurulum, Kibana dashboard ve dataset değiştirme: **[test/README.md](test/README.md)**

---

## Modeller

| Dosya | Kullanım |
|-------|----------|
| `ensemble_model.pkl` | Ana sınıflandırıcı (`test/run.py`) |
| `tfidf_vectorizer.pkl` | Her tahmin öncesi metin → sparse TF-IDF (**zorunlu**) |
| `*_model.pkl` (xgb, rf, sgd, lr) | Notebook analizi / ensemble bileşenleri |

Tahmin girişi: `Sentence` (veya `dataset_loader` alias’ları ile eşlenen metin kolonu). Çıkış: `0` = normal, `1` = attack.

---

## Veri setleri

| Dosya | Yaklaşık içerik |
|-------|------------------|
| `SQLiV3.csv` | SQLiV3, UTF-8 |
| `sqliv2.csv` | SQLiV2, UTF-16 |
| `sqli.csv` | Küçük SQLi seti, UTF-16 |
| `merged_cleaned_preprocessed.csv` | Birleştirilmiş + normalize (~1.6M satır) |

Streaming testte dataset seçimi: `test/config.py` → `TEST_DATASET_PATH` veya `KNOWN_DATASETS["sqliv3"]` vb.

```python
TEST_DATASET_PATH = KNOWN_DATASETS["sqliv3"]
MAX_ROWS = 500              # hızlı demo
SLEEP_INTERVAL = 0.3
```

---

## `test/run.py` akışı

```text
main()
 ├── Elasticsearch hazır olana kadar bekle
 ├── model + vectorizer + dataset yükle
 ├── stream_predict_and_send()    # satır satır predict, attack → ES
 ├── stream özeti (terminal)
 └── evaluate_model()             # accuracy, F1, confusion matrix, JSON
```

| Mod | Ayar (`test/config.py`) |
|-----|-------------------------|
| Real-time gecikme | `REAL_TIME_MODE`, `SLEEP_INTERVAL` |
| Yalnızca saldırıları indexle | `INDEX_ONLY_ATTACKS = True` |
| Performans raporu | `RUN_MODEL_EVALUATION = True` |
| JSON çıktı | `EXPORT_METRICS_JSON` → `test/metrics_report.json` |

---

## Bağımlılıklar

- **Kök `requirements.txt`:** pandas, scikit-learn, xgboost, matplotlib, seaborn, … (notebook)  
- **`test/requirements.txt`:** elasticsearch, xgboost, … (streaming pipeline)  

Ensemble içinde XGBoost olduğu için streaming ortamında `xgboost` kurulu olmalıdır.

---

## Lisans

Bu depodaki `LICENSE` dosyasına bakın.

---

## İlgili dokümantasyon

- **[test/README.md](test/README.md)** — Docker, Kibana SOC dashboard, dataset alias’ları, örnek ES sorguları  
- **`sql_ids_single_flow.ipynb`** — model eğitim ve metrik detayları  
- **`merge_clean_preprocess.ipynb`** — veri hazırlama pipeline’ı  
