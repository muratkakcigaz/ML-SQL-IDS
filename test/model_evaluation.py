"""Model performance evaluation (binary and optional multi-class)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

import config

# ---------------------------------------------------------------------------
# Collected samples during streaming
# ---------------------------------------------------------------------------


@dataclass
class EvaluationData:
    """Ground-truth and prediction pairs accumulated row-by-row."""

    y_true_binary: list[int] = field(default_factory=list)
    y_pred_binary: list[int] = field(default_factory=list)
    y_true_multiclass: list[str] = field(default_factory=list)
    y_pred_multiclass: list[str] = field(default_factory=list)

    def binary_sample_count(self) -> int:
        return len(self.y_true_binary)

    def multiclass_sample_count(self) -> int:
        return len(self.y_true_multiclass)

    def has_binary(self) -> bool:
        return self.binary_sample_count() > 0

    def has_multiclass(self) -> bool:
        return self.multiclass_sample_count() > 0


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class BinaryMetrics:
    """Binary classification metrics."""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: list[list[int]]
    classification_report: str
    support: int


@dataclass
class MulticlassMetrics:
    """Multi-class metrics (weighted average)."""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: list[list[int]]
    classification_report: str
    support: int
    class_labels: list[str]


def _safe_binary_metrics(
    y_true: list[int],
    y_pred: list[int],
) -> BinaryMetrics:
    """Compute binary metrics with zero-division protection."""
    labels = [0, 1]
    return BinaryMetrics(
        accuracy=float(accuracy_score(y_true, y_pred)),
        precision=float(
            precision_score(y_true, y_pred, average="binary", zero_division=0)
        ),
        recall=float(recall_score(y_true, y_pred, average="binary", zero_division=0)),
        f1_score=float(f1_score(y_true, y_pred, average="binary", zero_division=0)),
        confusion_matrix=confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        classification_report=classification_report(
            y_true, y_pred, labels=labels, zero_division=0
        ),
        support=len(y_true),
    )


def _safe_multiclass_metrics(
    y_true: list[str],
    y_pred: list[str],
) -> MulticlassMetrics:
    """Compute multi-class metrics with weighted averaging."""
    labels = sorted(set(y_true) | set(y_pred))
    return MulticlassMetrics(
        accuracy=float(accuracy_score(y_true, y_pred)),
        precision=float(
            precision_score(
                y_true, y_pred, average="weighted", zero_division=0, labels=labels
            )
        ),
        recall=float(
            recall_score(
                y_true, y_pred, average="weighted", zero_division=0, labels=labels
            )
        ),
        f1_score=float(
            f1_score(
                y_true, y_pred, average="weighted", zero_division=0, labels=labels
            )
        ),
        confusion_matrix=confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        classification_report=classification_report(
            y_true, y_pred, labels=labels, zero_division=0
        ),
        support=len(y_true),
        class_labels=labels,
    )


def format_performance_report(
    binary: Optional[BinaryMetrics],
    multiclass: Optional[MulticlassMetrics],
    dataset_name: str,
    *,
    partial: bool = False,
    processed_rows: int = 0,
    total_rows: int = 0,
) -> str:
    """Build terminal-friendly performance report."""
    lines = [
        "",
        "=" * 40,
        "MODEL PERFORMANCE REPORT",
        "=" * 40,
        f"Dataset: {dataset_name}",
    ]

    if partial:
        lines.append(
            f"Note: PARTIAL evaluation (stream stopped early) — "
            f"{processed_rows:,}/{total_rows:,} rows processed"
        )

    if binary is not None:
        lines.extend(
            [
                "",
                "--- Binary classification (Label vs prediction) ---",
                f"Samples : {binary.support:,}",
                f"Accuracy : {binary.accuracy:.4f}",
                f"Precision: {binary.precision:.4f}",
                f"Recall   : {binary.recall:.4f}",
                f"F1-score : {binary.f1_score:.4f}",
                "",
                "Confusion Matrix:",
                np.array2string(
                    np.array(binary.confusion_matrix),
                    separator="  ",
                ),
                "",
                "Classification Report:",
                binary.classification_report.rstrip(),
            ]
        )

    if multiclass is not None:
        lines.extend(
            [
                "",
                "--- Multi-class (attack_type, weighted avg) ---",
                f"Samples : {multiclass.support:,}",
                f"Classes : {', '.join(multiclass.class_labels)}",
                f"Accuracy : {multiclass.accuracy:.4f}",
                f"Precision: {multiclass.precision:.4f}",
                f"Recall   : {multiclass.recall:.4f}",
                f"F1-score : {multiclass.f1_score:.4f}",
                "",
                "Confusion Matrix:",
                np.array2string(
                    np.array(multiclass.confusion_matrix),
                    separator="  ",
                ),
                "",
                "Classification Report:",
                multiclass.classification_report.rstrip(),
            ]
        )

    if binary is None and multiclass is None:
        lines.append(
            "\nNo evaluation data collected (dataset has no Label / attack_type)."
        )

    lines.append("=" * 40)
    return "\n".join(lines)


def metrics_to_json_dict(
    binary: Optional[BinaryMetrics],
    multiclass: Optional[MulticlassMetrics],
    dataset_name: str,
    *,
    partial: bool = False,
    processed_rows: int = 0,
    total_rows: int = 0,
) -> dict[str, Any]:
    """Serialize metrics for JSON export."""
    payload: dict[str, Any] = {
        "dataset": dataset_name,
        "partial": partial,
        "processed_rows": processed_rows,
        "total_rows": total_rows,
        "binary": None,
        "multiclass": None,
    }

    if binary is not None:
        payload["binary"] = {
            "accuracy": binary.accuracy,
            "precision": binary.precision,
            "recall": binary.recall,
            "f1_score": binary.f1_score,
            "support": binary.support,
            "confusion_matrix": binary.confusion_matrix,
        }
        # Top-level keys for backward compatibility (binary task)
        payload["accuracy"] = binary.accuracy
        payload["precision"] = binary.precision
        payload["recall"] = binary.recall
        payload["f1_score"] = binary.f1_score

    if multiclass is not None:
        payload["multiclass"] = {
            "accuracy": multiclass.accuracy,
            "precision": multiclass.precision,
            "recall": multiclass.recall,
            "f1_score": multiclass.f1_score,
            "support": multiclass.support,
            "class_labels": multiclass.class_labels,
            "confusion_matrix": multiclass.confusion_matrix,
        }
        if binary is None:
            payload["accuracy"] = multiclass.accuracy
            payload["precision"] = multiclass.precision
            payload["recall"] = multiclass.recall
            payload["f1_score"] = multiclass.f1_score

    return payload


def export_metrics_json(
    payload: dict[str, Any],
    path: Path,
    logger: logging.Logger,
) -> None:
    """Write metrics dict to JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    logger.info("Metrics exported to %s", path)


def evaluate_model(
    eval_data: EvaluationData,
    dataset_name: str,
    logger: logging.Logger,
    *,
    partial: bool = False,
    processed_rows: int = 0,
    total_rows: int = 0,
) -> dict[str, Any]:
    """
    Compute metrics, print report, and optionally export JSON.

    Returns the metrics dictionary (for programmatic use).
    """
    binary_metrics: Optional[BinaryMetrics] = None
    multiclass_metrics: Optional[MulticlassMetrics] = None

    if not eval_data.has_binary() and not eval_data.has_multiclass():
        logger.warning(
            "Evaluation skipped: no ground-truth labels collected during stream."
        )
        report = format_performance_report(None, None, dataset_name)
        print(report)
        return {}

    if eval_data.has_binary():
        try:
            binary_metrics = _safe_binary_metrics(
                eval_data.y_true_binary,
                eval_data.y_pred_binary,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Binary evaluation failed: %s", exc)

    if eval_data.has_multiclass():
        unique_true = set(eval_data.y_true_multiclass)
        if len(unique_true) >= 2:
            try:
                multiclass_metrics = _safe_multiclass_metrics(
                    eval_data.y_true_multiclass,
                    eval_data.y_pred_multiclass,
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Multi-class evaluation failed: %s", exc)
        else:
            logger.info(
                "Multi-class evaluation skipped: need >= 2 classes, got %s",
                unique_true,
            )

    report = format_performance_report(
        binary_metrics,
        multiclass_metrics,
        dataset_name,
        partial=partial,
        processed_rows=processed_rows,
        total_rows=total_rows,
    )
    print(report)
    logger.info("Model performance report printed.")

    payload = metrics_to_json_dict(
        binary_metrics,
        multiclass_metrics,
        dataset_name,
        partial=partial,
        processed_rows=processed_rows,
        total_rows=total_rows,
    )

    if config.EXPORT_METRICS_JSON and payload:
        try:
            export_metrics_json(payload, config.METRICS_JSON_PATH, logger)
        except OSError as exc:
            logger.error("Failed to write metrics JSON: %s", exc)

    return payload


if __name__ == "__main__":
    import sys
    from pathlib import Path

    _test_dir = Path(__file__).resolve().parent
    if str(_test_dir) not in sys.path:
        sys.path.insert(0, str(_test_dir))

    print(
        "model_evaluation.py — evaluation-only mode\n"
        "(For full pipeline: python test/run.py)\n",
        file=sys.stderr,
    )
    from run import run_eval_only, setup_logging

    sys.exit(run_eval_only(setup_logging()))
