"""Data loading module for SQL-IDS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

import pandas as pd

from utils import (
    LABEL_COLUMN_CANDIDATES,
    PAYLOAD_COLUMN_CANDIDATES,
    clean_payload,
    collect_csv_files,
    detect_column,
    to_binary_label,
)


@dataclass
class SQLIDataLoader:
    """Read and prepare Kaggle-style SQL injection datasets."""

    dataset_path: str

    def load(self) -> Tuple[pd.Series, pd.Series]:
        """Load, clean and return payloads with binary labels."""
        csv_files = collect_csv_files(self.dataset_path)
        frames = [pd.read_csv(path) for path in csv_files]
        dataset = pd.concat(frames, ignore_index=True)

        payload_col = detect_column(dataset.columns, PAYLOAD_COLUMN_CANDIDATES)
        label_col = detect_column(dataset.columns, LABEL_COLUMN_CANDIDATES)

        payloads = dataset[payload_col].astype(str).apply(clean_payload)
        labels = dataset[label_col].apply(to_binary_label).astype(int)
        return payloads, labels
