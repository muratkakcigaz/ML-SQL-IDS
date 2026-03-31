"""Shared utilities for SQL-IDS pipeline."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, List
from urllib.parse import unquote_plus

PAYLOAD_COLUMN_CANDIDATES = [
    "payload",
    "query",
    "input",
    "text",
    "request",
    "sentence",
]

LABEL_COLUMN_CANDIDATES = [
    "label",
    "class",
    "target",
    "is_sqli",
    "attack",
]

MALICIOUS_LABELS = {"1", "true", "yes", "sqli", "sqli_attack", "malicious", "attack"}


def ensure_directories(paths: Iterable[str]) -> None:
    """Create directories if they do not exist."""
    for path in paths:
        os.makedirs(path, exist_ok=True)


def url_decode(text: str) -> str:
    """Decode URL-encoded payload safely."""
    if not isinstance(text, str):
        text = str(text)
    return unquote_plus(text)


def normalize_text(text: str) -> str:
    """Lowercase text and collapse repeated spaces."""
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)
    return text


def clean_payload(text: str) -> str:
    """Apply URL decode and normalization to payload."""
    return normalize_text(url_decode(text))


def sql_tokenizer(text: str) -> List[str]:
    """
    Tokenize SQL-like payloads while preserving operators and symbols.

    The tokenizer keeps words, numbers and SQL operators/punctuation.
    """
    spaced = re.sub(r"([()=><!,'\";*+\-/])", r" \1 ", text)
    return re.findall(
        r"[a-z_][a-z0-9_]*|\d+|[=><!]+|[()=><!,'\";*+\-/]",
        spaced,
    )


def to_binary_label(label: object) -> int:
    """Convert mixed label values into binary class labels."""
    label_text = str(label).strip().lower()
    return 1 if label_text in MALICIOUS_LABELS else int(label_text == "1")


def detect_column(columns: Iterable[str], candidates: List[str]) -> str:
    """Find matching column name using case-insensitive search."""
    lowered = {col.lower(): col for col in columns}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    raise ValueError(
        f"Column not found. Tried {candidates}. Available: {list(columns)}"
    )


def collect_csv_files(dataset_path: str) -> List[str]:
    """Collect CSV file paths from a file path or directory path."""
    path = Path(dataset_path)
    if path.is_file():
        return [str(path)]
    if path.is_dir():
        csv_files = sorted(str(item) for item in path.glob("*.csv"))
        if csv_files:
            return csv_files
    raise FileNotFoundError(f"No CSV dataset found at: {dataset_path}")
