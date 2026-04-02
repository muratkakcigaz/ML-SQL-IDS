"""Evaluation and plotting utilities for SQL-IDS models."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)


def calculate_metrics(y_true, y_pred) -> Dict[str, float]:
    """Calculate standard binary classification metrics."""
    precision, recall, f1_score, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="binary",
        zero_division=0,
    )
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
    }


def save_confusion_matrix(y_true, y_pred, model_name: str, plots_dir: str) -> None:
    """Save confusion matrix figure for a model."""
    matrix = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=matrix, display_labels=[0, 1])
    disp.plot(cmap="Blues", colorbar=False)
    plt.title(f"{model_name} Confusion Matrix")
    plt.tight_layout()
    output_path = Path(plots_dir) / f"{model_name.lower()}_confusion_matrix.png"
    plt.savefig(output_path, dpi=150)
    plt.close()


def save_results_report(metrics_by_model: Dict[str, Dict[str, float]], output: str) -> None:
    """Write model metrics into a plain text report file."""
    lines = []
    for model_name, metrics in metrics_by_model.items():
        lines.append(f"[{model_name}]")
        lines.append(f"Accuracy : {metrics['accuracy']:.4f}")
        lines.append(f"Precision: {metrics['precision']:.4f}")
        lines.append(f"Recall   : {metrics['recall']:.4f}")
        lines.append(f"F1-Score : {metrics['f1_score']:.4f}")
        lines.append("")

    Path(output).write_text("\n".join(lines), encoding="utf-8")


def save_performance_bar_chart(
    metrics_by_model: Dict[str, Dict[str, float]],
    output: str,
) -> None:
    """Create a grouped bar chart to compare model performances."""
    model_names = list(metrics_by_model.keys())
    accuracies = [metrics_by_model[name]["accuracy"] for name in model_names]
    precisions = [metrics_by_model[name]["precision"] for name in model_names]
    recalls = [metrics_by_model[name]["recall"] for name in model_names]
    f1_scores = [metrics_by_model[name]["f1_score"] for name in model_names]

    x_positions = list(range(len(model_names)))
    width = 0.2

    plt.figure(figsize=(10, 5))
    plt.bar([x - 1.5 * width for x in x_positions], accuracies, width, label="Accuracy")
    plt.bar([x - 0.5 * width for x in x_positions], precisions, width, label="Precision")
    plt.bar([x + 0.5 * width for x in x_positions], recalls, width, label="Recall")
    plt.bar([x + 1.5 * width for x in x_positions], f1_scores, width, label="F1-Score")

    plt.xticks(x_positions, model_names)
    plt.ylim(0.0, 1.0)
    plt.ylabel("Score")
    plt.title("SQL-IDS Model Performance Comparison")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()
