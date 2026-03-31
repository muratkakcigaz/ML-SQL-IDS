"""Preprocessing utilities for SQL Injection detection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Tuple
from urllib.parse import unquote_plus

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

# Common SQL tokens we want to preserve during tokenization.
SQL_KEYWORDS = {
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "union",
    "where",
    "or",
    "and",
    "from",
    "into",
    "like",
    "sleep",
    "benchmark",
    "having",
    "group",
    "by",
    "order",
    "limit",
    "join",
    "information_schema",
    "xp_cmdshell",
}

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


def url_decode(value: str) -> str:
    """Decode URL encoded payload safely."""
    if not isinstance(value, str):
        value = str(value)
    return unquote_plus(value)


def normalize_text(value: str) -> str:
    """Lowercase and normalize whitespaces."""
    value = value.lower().strip()
    value = re.sub(r"\s+", " ", value)
    return value


def tokenize_payload(value: str) -> List[str]:
    """
    Tokenize payload while preserving SQL keywords and symbols.

    This tokenizer keeps:
    - SQL words (e.g., select, union, drop)
    - Numbers
    - SQL-related operators and punctuation
    """
    spaced = re.sub(r"([()=><!,'\";*+\-/])", r" \1 ", value)
    raw_tokens = re.findall(r"[a-z_][a-z0-9_]*|\d+|[=><!]+|[()=><!,'\";*+\-/]", spaced)

    tokens = []
    for token in raw_tokens:
        if token in SQL_KEYWORDS:
            tokens.append(token)
        else:
            tokens.append(token)
    return tokens


def to_binary_label(label: object) -> int:
    """Map heterogeneous labels to binary 0/1."""
    label_text = str(label).strip().lower()
    if label_text in MALICIOUS_LABELS:
        return 1
    return int(label_text == "1")


def detect_column(columns: Iterable[str], candidates: List[str]) -> str:
    """Return the first matching column in a case-insensitive way."""
    lowered = {col.lower(): col for col in columns}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    raise ValueError(
        f"Required column not found. Tried: {candidates}. "
        f"Available columns: {list(columns)}"
    )


@dataclass
class SQLIPreprocessor:
    """Handles preprocessing and TF-IDF vectorization for SQLi detection."""

    max_features: int = 5000
    ngram_range: Tuple[int, int] = (1, 2)

    def __post_init__(self) -> None:
        self.vectorizer = TfidfVectorizer(
            tokenizer=tokenize_payload,
            token_pattern=None,  # Required when custom tokenizer is used.
            max_features=self.max_features,
            ngram_range=self.ngram_range,
        )

    def clean_payload(self, payload: str) -> str:
        """Apply URL decode, lowercase, and whitespace normalization."""
        decoded = url_decode(payload)
        return normalize_text(decoded)

    def preprocess_texts(self, payloads: Iterable[str]) -> List[str]:
        """Preprocess a list/series of payloads."""
        return [self.clean_payload(payload) for payload in payloads]

    def fit_transform(self, payloads: Iterable[str]):
        """Fit TF-IDF on texts and return transformed matrix."""
        cleaned = self.preprocess_texts(payloads)
        return self.vectorizer.fit_transform(cleaned)

    def transform(self, payloads: Iterable[str]):
        """Transform texts using an already-fitted TF-IDF vectorizer."""
        cleaned = self.preprocess_texts(payloads)
        return self.vectorizer.transform(cleaned)

    def load_kaggle_dataset(self, csv_path: str):
        """
        Load SQLi dataset from CSV and return payload series and binary labels.

        The loader tries common column names used in Kaggle datasets.
        """
        dataset = pd.read_csv(csv_path)
        payload_col = detect_column(dataset.columns, PAYLOAD_COLUMN_CANDIDATES)
        label_col = detect_column(dataset.columns, LABEL_COLUMN_CANDIDATES)

        payloads = dataset[payload_col].astype(str)
        labels = dataset[label_col].apply(to_binary_label).astype(int)
        return payloads, labels
