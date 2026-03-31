# SQL-IDS (Machine Learning Tabanli SQL Injection Tespiti)

Bu proje, HTTP payload'lari uzerinden SQL Injection (SQLi) saldirilarini tespit etmek
icin TF-IDF + makine ogrenmesi modelleri kullanan moduler bir Python iskeletidir.

## Ozellikler

- URL Decoding + lowercasing + whitespace normalizasyonu
- SQL anahtar kelimelerini koruyan ozel tokenization
- TF-IDF vektorlestrirme
- XGBoost, Random Forest ve SVM modelleri
- Agirlikli oylama ile ensemble (Voting Classifier)
- Accuracy, Precision, Recall, F1-Score raporu
- Kaggle tabanli SQLi CSV dataset'leri icin esnek kolon tespiti

## Proje Yapisi

```text
project002/
├─ preprocess.py
├─ train.py
├─ predict.py
├─ requirements.txt
├─ data/
└─ models/
```

## Kurulum

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Veri Formati

`train.py`, Kaggle dataset'lerinde farkli isimler olabilecegi icin asagidaki kolonlari
otomatik tespit etmeye calisir:

- Payload kolonu: `payload`, `query`, `input`, `text`, `request`, `sentence`
- Label kolonu: `label`, `class`, `target`, `is_sqli`, `attack`

Etiketler binary olacak sekilde `0/1` formatina donusturulur.

## Egitim

```bash
python train.py --dataset data/your_kaggle_sqli_dataset.csv
```

Opsiyonel parametreler:

- `--model-output` (varsayilan: `models/sql_ids_bundle.joblib`)
- `--test-size` (varsayilan: `0.2`)
- `--max-features` (varsayilan: `5000`)
- `--random-state` (varsayilan: `42`)

## Tahmin

```bash
python predict.py --model-path models/sql_ids_bundle.joblib --payload "id=1' OR '1'='1"
python predict.py --payload "q=normal-search" --payload "username=admin' --"
```

## Notlar

- Bu yapi bir baslangic iskeletidir; gercek ortamlarda model tuning, veri dengeleme
  ve adversarial testler tavsiye edilir.
- Uretim ortami icin API katmani (FastAPI/Flask) eklenebilir.
