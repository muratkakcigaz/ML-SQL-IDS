#!/usr/bin/env python3
"""SQL-IDS real-time streaming pipeline: row-by-row predict and index to Elasticsearch."""

from __future__ import annotations

import logging
import pickle
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ApiError, ConnectionError as ESConnectionError
from scipy.sparse import spmatrix

import config
from dataset_loader import load_test_dataset

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def setup_logging() -> logging.Logger:
    """Configure console (structured) and file logging."""
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = config.LOG_DIR / config.LOG_FILE_NAME

    logger = logging.getLogger("sql_ids_stream")
    logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@dataclass
class StreamStats:
    """Counters for the streaming run."""

    total_processed: int = 0
    attack_predictions: int = 0
    normal_predictions: int = 0
    indexed_attacks: int = 0
    indexed_documents: int = 0
    skipped_normals: int = 0
    index_failures: int = 0


# ---------------------------------------------------------------------------
# Elasticsearch
# ---------------------------------------------------------------------------

INDEX_MAPPING: dict[str, Any] = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "row_id": {"type": "integer"},
            "prediction": {"type": "keyword"},
            "confidence": {"type": "float"},
            "attack_type": {"type": "keyword"},
            "features": {"type": "object", "enabled": True},
        }
    }
}


def utc_timestamp() -> str:
    """Return current UTC time in ISO-8601 form for Elasticsearch."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def wait_for_elasticsearch(
    host: str,
    logger: logging.Logger,
    timeout_sec: int = config.ES_HEALTH_WAIT_TIMEOUT_SEC,
    poll_interval_sec: float = config.ES_HEALTH_POLL_INTERVAL_SEC,
) -> None:
    """Block until Elasticsearch cluster health is at least yellow."""
    deadline = time.monotonic() + timeout_sec
    attempt = 0

    while time.monotonic() < deadline:
        attempt += 1
        client: Optional[Elasticsearch] = None
        try:
            client = Elasticsearch(
                hosts=[host],
                request_timeout=config.ES_REQUEST_TIMEOUT,
            )
            health = client.cluster.health(wait_for_status="yellow", timeout="10s")
            status = health.get("status", "unknown")
            logger.info(
                "Elasticsearch is ready (status=%s, attempt=%d).",
                status,
                attempt,
            )
            return
        except ESConnectionError as exc:
            logger.warning(
                "Elasticsearch not ready (attempt=%d): %s",
                attempt,
                exc,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Elasticsearch health check failed (attempt=%d): %s",
                attempt,
                exc,
            )
        finally:
            if client is not None:
                client.close()

        time.sleep(poll_interval_sec)

    raise TimeoutError(
        f"Elasticsearch did not become ready within {timeout_sec}s at {host}"
    )


def create_es_client_with_retry(logger: logging.Logger) -> Elasticsearch:
    """Create an Elasticsearch client; retry on connection failure."""
    last_error: Optional[Exception] = None

    for attempt in range(1, config.ES_CONNECT_MAX_RETRIES + 1):
        try:
            client = Elasticsearch(
                hosts=[config.ES_HOST],
                request_timeout=config.ES_REQUEST_TIMEOUT,
                max_retries=0,
            )
            if client.ping():
                logger.info("Connected to Elasticsearch at %s", config.ES_HOST)
                return client
            raise ESConnectionError("Ping returned False")
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            wait = config.ES_CONNECT_RETRY_BACKOFF_SEC * attempt
            logger.warning(
                "Elasticsearch connection failed (attempt %d/%d): %s. "
                "Retrying in %.1fs...",
                attempt,
                config.ES_CONNECT_MAX_RETRIES,
                exc,
                wait,
            )
            time.sleep(wait)

    raise ConnectionError(
        f"Could not connect to Elasticsearch at {config.ES_HOST}"
    ) from last_error


def ensure_index(client: Elasticsearch, index: str, logger: logging.Logger) -> None:
    """Create index with mapping if it does not exist."""
    if client.indices.exists(index=index):
        logger.info("Index '%s' already exists.", index)
        return

    client.indices.create(index=index, mappings=INDEX_MAPPING["mappings"])
    logger.info("Created index '%s' with mapping.", index)


def index_document_with_retry(
    client: Elasticsearch,
    index: str,
    document: dict[str, Any],
    logger: logging.Logger,
) -> bool:
    """
    Index a single document with retries.

    Returns True on success. On persistent failure logs error and returns False
    (does not raise — streaming continues).
    """
    last_error: Optional[Exception] = None

    for attempt in range(1, config.ES_INDEX_MAX_RETRIES + 1):
        try:
            client.index(index=index, document=document)
            return True
        except (ESConnectionError, ApiError, TimeoutError) as exc:
            last_error = exc
            wait = config.ES_CONNECT_RETRY_BACKOFF_SEC * attempt
            logger.warning(
                "Index failed for row_id=%s (attempt %d/%d): %s. Retry in %.1fs.",
                document.get("row_id"),
                attempt,
                config.ES_INDEX_MAX_RETRIES,
                exc,
                wait,
            )
            time.sleep(wait)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            logger.warning(
                "Unexpected index error row_id=%s: %s",
                document.get("row_id"),
                exc,
            )
            time.sleep(config.ES_CONNECT_RETRY_BACKOFF_SEC)

    logger.error(
        "Giving up on row_id=%s after %d attempts: %s",
        document.get("row_id"),
        config.ES_INDEX_MAX_RETRIES,
        last_error,
    )
    return False


# ---------------------------------------------------------------------------
# Model & data
# ---------------------------------------------------------------------------


def load_model(logger: logging.Logger) -> Any:
    """Load the pickled ensemble classifier."""
    if not config.MODEL_PATH.is_file():
        raise FileNotFoundError(f"Model not found: {config.MODEL_PATH}")

    logger.info("Loading model from %s", config.MODEL_PATH)
    with config.MODEL_PATH.open("rb") as handle:
        model = pickle.load(handle)

    logger.info("Model type: %s", type(model).__name__)
    return model


def load_vectorizer(logger: logging.Logger) -> Any:
    """Load the TF-IDF vectorizer fitted during training."""
    if not config.TFIDF_VECTORIZER_PATH.is_file():
        raise FileNotFoundError(
            f"TF-IDF vectorizer not found: {config.TFIDF_VECTORIZER_PATH}"
        )

    logger.info("Loading vectorizer from %s", config.TFIDF_VECTORIZER_PATH)
    with config.TFIDF_VECTORIZER_PATH.open("rb") as handle:
        return pickle.load(handle)


def determine_feature_columns(df: pd.DataFrame) -> list[str]:
    """Columns stored under the Elasticsearch 'features' object."""
    return [col for col in df.columns if col != "index"]


def row_to_features(row: pd.Series, feature_columns: list[str]) -> dict[str, Any]:
    """Serialize a dataframe row into JSON-safe feature values."""
    features: dict[str, Any] = {}
    for col in feature_columns:
        value = row[col]
        if pd.isna(value):
            features[col] = None
        elif isinstance(value, (np.integer,)):
            features[col] = int(value)
        elif isinstance(value, (np.floating,)):
            features[col] = float(value)
        else:
            features[col] = str(value)
    return features


def prediction_label(raw: Any) -> str:
    """Map numeric prediction to 'attack' or 'normal'."""
    try:
        key = int(raw)
    except (TypeError, ValueError):
        return str(raw)
    return config.PREDICTION_LABELS.get(key, str(raw))


def resolve_attack_type(row: pd.Series, has_attack_type_col: bool) -> str:
    """Resolve attack type label for console and documents."""
    if has_attack_type_col:
        value = row.get(config.ATTACK_TYPE_COLUMN)
        if pd.notna(value) and str(value).strip():
            return str(value).strip()
    return config.DEFAULT_ATTACK_TYPE


def predict_single(
    model: Any,
    vectorizer: Any,
    text: str,
) -> tuple[int, Optional[float]]:
    """Vectorize one payload and return (class, attack confidence)."""
    X: spmatrix = vectorizer.transform([text])
    pred_raw = model.predict(X)[0]
    pred_int = int(pred_raw)

    confidence: Optional[float] = None
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(X)
            confidence = float(proba[0, 1])
        except Exception:  # noqa: BLE001
            confidence = None

    return pred_int, confidence


def build_normal_document(
    row_id: int,
    row: pd.Series,
    confidence: Optional[float],
    feature_columns: list[str],
) -> dict[str, Any]:
    """Build an Elasticsearch document for benign traffic (optional indexing)."""
    return {
        "timestamp": utc_timestamp(),
        "row_id": row_id,
        "prediction": "normal",
        "confidence": confidence,
        "features": row_to_features(row, feature_columns),
    }


def build_attack_document(
    row_id: int,
    row: pd.Series,
    confidence: Optional[float],
    attack_type: str,
    feature_columns: list[str],
    has_attack_type_col: bool,
) -> dict[str, Any]:
    """Build an Elasticsearch document for a detected attack."""
    doc: dict[str, Any] = {
        "timestamp": utc_timestamp(),
        "row_id": row_id,
        "prediction": "attack",
        "confidence": confidence,
        "features": row_to_features(row, feature_columns),
    }

    if has_attack_type_col:
        value = row.get(config.ATTACK_TYPE_COLUMN)
        if pd.notna(value) and str(value).strip():
            doc["attack_type"] = str(value).strip()
    else:
        doc["attack_type"] = config.DEFAULT_ATTACK_TYPE

    return doc


def print_realtime_line(
    row_id: int,
    prediction: str,
    attack_type: str,
    confidence: Optional[float],
    indexed: bool,
) -> None:
    """Print SOC-style real-time console output."""
    pred_upper = prediction.upper()
    if prediction == "attack":
        conf_str = f"{confidence:.2f}" if confidence is not None else "n/a"
        suffix = f" | confidence: {conf_str}"
        if indexed:
            print(
                f"[+] Row {row_id} processed -> {pred_upper} ({attack_type}){suffix}"
            )
        else:
            print(
                f"[!] Row {row_id} processed -> {pred_upper} ({attack_type}){suffix} "
                f"(index failed)"
            )
    else:
        print(f"[+] Row {row_id} processed -> {pred_upper} (skipped)")


def stream_process_dataset(
    client: Elasticsearch,
    model: Any,
    vectorizer: Any,
    df: pd.DataFrame,
    feature_columns: list[str],
    has_attack_type_col: bool,
    logger: logging.Logger,
) -> StreamStats:
    """
    Process each dataset row sequentially: predict, optionally index, sleep.

    Only attacks are sent to Elasticsearch when INDEX_ONLY_ATTACKS is True.
    """
    stats = StreamStats()
    total_rows = len(df)

    logger.info(
        "Starting real-time stream | rows=%d | real_time=%s | sleep=%.2fs | "
        "attacks_only=%s",
        total_rows,
        config.REAL_TIME_MODE,
        config.SLEEP_INTERVAL,
        config.INDEX_ONLY_ATTACKS,
    )

    for row_id in range(total_rows):
        row = df.iloc[row_id]
        text = str(row[config.TEXT_COLUMN])

        try:
            pred_int, confidence = predict_single(model, vectorizer, text)
        except Exception as exc:  # noqa: BLE001
            logger.error("Prediction failed for row_id=%d: %s", row_id, exc)
            stats.total_processed += 1
            if config.REAL_TIME_MODE:
                time.sleep(config.SLEEP_INTERVAL)
            continue

        label = prediction_label(pred_int)
        attack_type = resolve_attack_type(row, has_attack_type_col)
        stats.total_processed += 1

        if label == "attack":
            stats.attack_predictions += 1
            document = build_attack_document(
                row_id=row_id,
                row=row,
                confidence=confidence,
                attack_type=attack_type,
                feature_columns=feature_columns,
                has_attack_type_col=has_attack_type_col,
            )
            indexed = index_document_with_retry(
                client, config.ES_INDEX, document, logger
            )
            if indexed:
                stats.indexed_attacks += 1
                stats.indexed_documents += 1
            else:
                stats.index_failures += 1

            print_realtime_line(
                row_id, label, attack_type, confidence, indexed=indexed
            )
        else:
            stats.normal_predictions += 1
            stats.skipped_normals += 1
            indexed = False

            if not config.INDEX_ONLY_ATTACKS:
                document = build_normal_document(
                    row_id=row_id,
                    row=row,
                    confidence=confidence,
                    feature_columns=feature_columns,
                )
                indexed = index_document_with_retry(
                    client, config.ES_INDEX, document, logger
                )
                if indexed:
                    stats.indexed_documents += 1
                else:
                    stats.index_failures += 1
                stats.skipped_normals -= 1

            print_realtime_line(
                row_id, label, attack_type, confidence, indexed=indexed
            )

        if config.REAL_TIME_MODE and config.SLEEP_INTERVAL > 0:
            time.sleep(config.SLEEP_INTERVAL)

        if (row_id + 1) % 100 == 0:
            logger.info(
                "Progress: %d/%d | indexed attacks: %d",
                row_id + 1,
                total_rows,
                stats.indexed_attacks,
            )

    return stats


def print_summary(stats: StreamStats, logger: logging.Logger) -> None:
    """Print final streaming statistics."""
    total = stats.total_processed
    attack_pct = (stats.attack_predictions / total * 100) if total else 0.0
    normal_pct = (stats.normal_predictions / total * 100) if total else 0.0

    lines = [
        "",
        "=" * 55,
        "SQL-IDS Real-Time Stream — Özet",
        "=" * 55,
        f"Toplam işlenen kayıt     : {total:,}",
        f"Toplam attack (tahmin)   : {stats.attack_predictions:,}",
        f"Toplam normal (tahmin)   : {stats.normal_predictions:,}",
        f"Elasticsearch'e gönderilen: {stats.indexed_documents:,}",
        f"  (attack kayıtları)      : {stats.indexed_attacks:,}",
        f"Index başarısız          : {stats.index_failures:,}",
        f"Atlanan normal           : {stats.skipped_normals:,}",
        f"Attack yüzdesi           : {attack_pct:.2f}%",
        f"Normal yüzdesi           : {normal_pct:.2f}%",
        "=" * 55,
    ]
    summary = "\n".join(lines)
    print(summary)
    logger.info(
        "Stream complete — processed=%d attacks=%d indexed=%d failures=%d",
        total,
        stats.attack_predictions,
        stats.indexed_documents,
        stats.index_failures,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    """Entry point for the real-time streaming pipeline."""
    logger = setup_logging()
    exit_code = 0

    try:
        logger.info("SQL-IDS real-time streaming pipeline starting.")
        logger.info("Model path      : %s", config.MODEL_PATH)
        logger.info("Dataset path    : %s", config.TEST_DATASET_PATH)
        logger.info("ES host / index : %s / %s", config.ES_HOST, config.ES_INDEX)
        logger.info(
            "Mode: REAL_TIME=%s SLEEP=%.2fs INDEX_ONLY_ATTACKS=%s",
            config.REAL_TIME_MODE,
            config.SLEEP_INTERVAL,
            config.INDEX_ONLY_ATTACKS,
        )

        wait_for_elasticsearch(config.ES_HOST, logger)

        model = load_model(logger)
        vectorizer = load_vectorizer(logger)
        df, dataset_meta = load_test_dataset(logger)
        feature_columns = determine_feature_columns(df)
        has_attack_type_col = dataset_meta.has_attack_type
        logger.info(
            "Dataset '%s' | encoding=%s | rows=%d",
            dataset_meta.source_path.name,
            dataset_meta.encoding,
            dataset_meta.rows_after_clean,
        )

        client = create_es_client_with_retry(logger)
        try:
            ensure_index(client, config.ES_INDEX, logger)
            stats = stream_process_dataset(
                client=client,
                model=model,
                vectorizer=vectorizer,
                df=df,
                feature_columns=feature_columns,
                has_attack_type_col=has_attack_type_col,
                logger=logger,
            )
        finally:
            client.close()

        print_summary(stats, logger)
        logger.info("Pipeline finished successfully.")
    except FileNotFoundError as exc:
        logger.exception("Missing file: %s", exc)
        exit_code = 1
    except TimeoutError as exc:
        logger.exception("%s", exc)
        exit_code = 1
    except KeyboardInterrupt:
        logger.warning("Stream interrupted by user (Ctrl+C).")
        print("\n[!] Stream stopped by user.")
        exit_code = 130
    except Exception as exc:  # noqa: BLE001
        logger.exception("Pipeline failed: %s", exc)
        exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
