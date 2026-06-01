"""Central configuration for the SQL-IDS real-time streaming pipeline."""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (project root = parent of test/)
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

MODEL_PATH: Path = PROJECT_ROOT / "models" / "ensemble_model.pkl"
TFIDF_VECTORIZER_PATH: Path = PROJECT_ROOT / "models" / "tfidf_vectorizer.pkl"

# Test dataset — change path or use KNOWN_DATASETS key
TEST_DATASET_PATH: Path = PROJECT_ROOT / "data" / "sqliv2.csv"

# 0 = all rows; e.g. 500 for quick demo on large files
MAX_ROWS: int = 0

# Shortcut presets (TEST_DATASET_PATH = KNOWN_DATASETS["sqliv3"])
KNOWN_DATASETS: dict[str, Path] = {
    "sqliv3": PROJECT_ROOT / "data" / "SQLiV3.csv",
    "sqliv2": PROJECT_ROOT / "data" / "sqliv2.csv",
    "sqli": PROJECT_ROOT / "data" / "sqli.csv",
    "merged": PROJECT_ROOT / "data" / "merged_cleaned_preprocessed.csv",
}

LOG_DIR: Path = Path(__file__).resolve().parent / "logs"

# ---------------------------------------------------------------------------
# Canonical column names (after normalization)
# ---------------------------------------------------------------------------
TEXT_COLUMN: str = "Sentence"
LABEL_COLUMN: str = "Label"
ATTACK_TYPE_COLUMN: str = "attack_type"

# Aliases matched case-insensitively (first match in tuple order wins)
TEXT_COLUMN_ALIASES: tuple[str, ...] = (
    "sentence",
    "payload",
    "query",
    "input",
    "text",
    "request",
    "full_query",
    "normalized_query",
    "sql_query",
    "http_request",
    "url",
    "data",
)

LABEL_COLUMN_ALIASES: tuple[str, ...] = (
    "label",
    "labels",
    "class",
    "target",
    "is_sqli",
    "is_sql_injection",
    "attack",
    "malicious",
    "y",
)

ATTACK_TYPE_COLUMN_ALIASES: tuple[str, ...] = (
    "attack_type",
    "attack_category",
    "category",
    "type",
    "class_name",
    "threat_type",
)

PREDICTION_LABELS: dict[int, str] = {
    0: "normal",
    1: "attack",
}

DEFAULT_ATTACK_TYPE: str = "SQL_Injection"

# ---------------------------------------------------------------------------
# Real-time streaming simulation
# ---------------------------------------------------------------------------
REAL_TIME_MODE: bool = True
SLEEP_INTERVAL: float = 0.5

INDEX_ONLY_ATTACKS: bool = True

# ---------------------------------------------------------------------------
# Elasticsearch
# ---------------------------------------------------------------------------
ES_HOST: str = "http://localhost:9200"
ES_INDEX: str = "sql_ids_predictions"
ES_REQUEST_TIMEOUT: int = 30

ES_HEALTH_WAIT_TIMEOUT_SEC: int = 300
ES_HEALTH_POLL_INTERVAL_SEC: float = 5.0
ES_CONNECT_MAX_RETRIES: int = 10
ES_CONNECT_RETRY_BACKOFF_SEC: float = 3.0
ES_INDEX_MAX_RETRIES: int = 5

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = "INFO"
LOG_FILE_NAME: str = "run.log"
