"""Load and normalize SQL-IDS test datasets (encoding, columns, labels)."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pandas as pd

import config

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DatasetMeta:
    """Summary of a loaded dataset."""

    source_path: Path
    encoding: str
    original_columns: tuple[str, ...]
    has_label: bool
    has_attack_type: bool
    rows_raw: int
    rows_after_clean: int


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def detect_csv_encoding(path: Path) -> str:
    """Detect CSV encoding from BOM / byte signature."""
    with path.open("rb") as handle:
        header = handle.read(4)

    if header.startswith(b"\xff\xfe") or header.startswith(b"\xfe\xff"):
        return "utf-16"
    if header.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def read_csv_auto_encoding(path: Path, logger: logging.Logger) -> tuple[pd.DataFrame, str]:
    """Read CSV with encoding detection and optional separator sniffing."""
    encodings = [
        detect_csv_encoding(path),
        "utf-8-sig",
        "utf-8",
        "cp1252",
        "latin-1",
    ]
    tried_enc: list[str] = []
    last_decode_error: Optional[UnicodeDecodeError] = None

    for encoding in encodings:
        if encoding in tried_enc:
            continue
        tried_enc.append(encoding)

        for sep, sep_label in ((",", "comma"), (None, "sniff")):
            try:
                read_kwargs: dict = {
                    "filepath_or_buffer": path,
                    "low_memory": False,
                    "encoding": encoding,
                }
                if sep is not None:
                    read_kwargs["sep"] = sep
                else:
                    read_kwargs["sep"] = None
                    read_kwargs["engine"] = "python"

                df = pd.read_csv(**read_kwargs)
                logger.info(
                    "CSV loaded: encoding='%s' separator=%s rows=%d file=%s",
                    encoding,
                    sep_label,
                    len(df),
                    path.name,
                )
                return df, encoding
            except UnicodeDecodeError as exc:
                last_decode_error = exc
                break  # next encoding
            except Exception as exc:  # noqa: BLE001
                if sep is None:
                    logger.debug(
                        "read_csv failed encoding=%s sep=sniff: %s",
                        encoding,
                        exc,
                    )
                continue

    msg = f"Could not decode {path} (encodings tried: {tried_enc})"
    if last_decode_error:
        raise last_decode_error from None
    raise UnicodeDecodeError("utf-8", b"", 0, 1, msg)


# ---------------------------------------------------------------------------
# Column detection
# ---------------------------------------------------------------------------


def _normalize_col_name(name: str) -> str:
    return str(name).strip().lower().replace(" ", "_")


def _build_column_lookup(columns: list[str]) -> dict[str, str]:
    """Map normalized name -> original column name."""
    lookup: dict[str, str] = {}
    for col in columns:
        key = _normalize_col_name(col)
        if key not in lookup:
            lookup[key] = col
    return lookup


def find_column(
    lookup: dict[str, str],
    aliases: tuple[str, ...],
) -> Optional[str]:
    """Return original column name for the first matching alias."""
    for alias in aliases:
        key = _normalize_col_name(alias)
        if key in lookup:
            return lookup[key]
    return None


def map_label_to_binary(raw: object) -> float:
    """Map assorted label formats to 0/1; unknown -> NaN."""
    if pd.isna(raw):
        return float("nan")
    if isinstance(raw, bool):
        return float(int(raw))
    if isinstance(raw, int):
        if raw in (0, 1):
            return float(raw)
        return float("nan")
    if isinstance(raw, float):
        if math.isnan(raw):
            return float("nan")
        if raw in (0.0, 1.0):
            return float(int(raw))
        return float("nan")

    s = str(raw).strip().lower()
    attack_tokens = {
        "1",
        "1.0",
        "+1",
        "true",
        "yes",
        "t",
        "y",
        "positive",
        "pos",
        "sqli",
        "sql_injection",
        "sql injection",
        "malicious",
        "attack",
        "harmful",
        "unsafe",
        "bad",
        "suspicious",
        "anomaly",
        "anomalous",
        "class_1",
        "label_1",
        "class1",
        "label1",
    }
    benign_tokens = {
        "0",
        "0.0",
        "+0",
        "false",
        "no",
        "f",
        "n",
        "negative",
        "neg",
        "benign",
        "normal",
        "safe",
        "legitimate",
        "clean",
        "good",
        "class_0",
        "label_0",
        "class0",
        "label0",
    }
    if s in attack_tokens:
        return 1.0
    if s in benign_tokens:
        return 0.0
    return float("nan")


def drop_unnamed_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Remove empty / Unnamed export columns."""
    drop_cols = [
        c
        for c in df.columns
        if str(c).startswith("Unnamed") or str(c).strip() == ""
    ]
    if drop_cols:
        df = df.drop(columns=drop_cols)
    return df


def normalize_schema(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    """
    Rename detected columns to canonical names: Sentence, Label, attack_type.

    Extra columns (e.g. normalized_query, dataset_source) are kept as-is.
    """
    lookup = _build_column_lookup(list(df.columns))
    rename_map: dict[str, str] = {}

    text_col = find_column(lookup, config.TEXT_COLUMN_ALIASES)
    if text_col is None:
        raise ValueError(
            f"No text/payload column found. Tried aliases: {config.TEXT_COLUMN_ALIASES}. "
            f"Available columns: {list(df.columns)}"
        )
    if text_col != config.TEXT_COLUMN:
        rename_map[text_col] = config.TEXT_COLUMN
        logger.info("Mapped text column '%s' -> '%s'", text_col, config.TEXT_COLUMN)

    label_col = find_column(lookup, config.LABEL_COLUMN_ALIASES)
    if label_col and label_col != config.LABEL_COLUMN:
        rename_map[label_col] = config.LABEL_COLUMN
        logger.info("Mapped label column '%s' -> '%s'", label_col, config.LABEL_COLUMN)

    attack_col = find_column(lookup, config.ATTACK_TYPE_COLUMN_ALIASES)
    if attack_col and attack_col != config.ATTACK_TYPE_COLUMN:
        rename_map[attack_col] = config.ATTACK_TYPE_COLUMN
        logger.info(
            "Mapped attack_type column '%s' -> '%s'",
            attack_col,
            config.ATTACK_TYPE_COLUMN,
        )

    if rename_map:
        df = df.rename(columns=rename_map)

    return df


def clean_dataset(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    """Apply row cleaning and label normalization."""
    df = drop_unnamed_columns(df)

    if config.TEXT_COLUMN not in df.columns:
        raise ValueError(f"Missing required column after normalize: {config.TEXT_COLUMN}")

    df[config.TEXT_COLUMN] = df[config.TEXT_COLUMN].fillna("").astype(str)
    df = df[df[config.TEXT_COLUMN].str.strip() != ""].copy()

    if config.LABEL_COLUMN in df.columns:
        before = len(df)
        df = df.dropna(subset=[config.LABEL_COLUMN]).copy()
        df["_label_bin"] = df[config.LABEL_COLUMN].apply(map_label_to_binary)
        invalid = df["_label_bin"].isna().sum()
        if invalid:
            logger.warning(
                "Dropped %d rows with unrecognized label values.",
                invalid,
            )
        df = df.dropna(subset=["_label_bin"]).copy()
        df[config.LABEL_COLUMN] = df["_label_bin"].astype(int)
        df = df.drop(columns=["_label_bin"])
        if len(df) < before:
            logger.info("Label cleaning: %d -> %d rows.", before, len(df))

    df = df.reset_index(drop=True)
    return df


def load_test_dataset(logger: logging.Logger) -> tuple[pd.DataFrame, DatasetMeta]:
    """
    Load TEST_DATASET_PATH with encoding detection and schema normalization.

    Supports project CSVs (SQLiV3, sqliv2, sqli, merged_cleaned_preprocessed)
    and common Kaggle-style column names.
    """
    path = config.TEST_DATASET_PATH
    if not path.is_file():
        known = ", ".join(config.KNOWN_DATASETS.keys())
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            f"Set TEST_DATASET_PATH in config.py or pick a key from KNOWN_DATASETS: {known}"
        )

    logger.info("Loading dataset: %s", path)
    df, encoding = read_csv_auto_encoding(path, logger)
    rows_raw = len(df)
    original_columns = tuple(df.columns.astype(str))

    if config.MAX_ROWS > 0:
        df = df.head(config.MAX_ROWS).copy()
        logger.info("MAX_ROWS=%d — using first %d rows only.", config.MAX_ROWS, len(df))

    df = normalize_schema(df, logger)
    df = clean_dataset(df, logger)

    meta = DatasetMeta(
        source_path=path,
        encoding=encoding,
        original_columns=original_columns,
        has_label=config.LABEL_COLUMN in df.columns,
        has_attack_type=config.ATTACK_TYPE_COLUMN in df.columns,
        rows_raw=rows_raw,
        rows_after_clean=len(df),
    )

    logger.info(
        "Dataset ready: %d rows | label=%s | attack_type=%s | columns=%s",
        meta.rows_after_clean,
        meta.has_label,
        meta.has_attack_type,
        list(df.columns),
    )
    return df, meta
