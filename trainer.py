"""Main training pipeline for SQL-IDS."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from xgboost import XGBClassifier

from data_loader import SQLIDataLoader
from evaluator import (
    calculate_metrics,
    save_confusion_matrix,
    save_performance_bar_chart,
    save_results_report,
)
from utils import ensure_directories, sql_tokenizer


def build_models(random_state: int) -> Dict[str, object]:
    """Create base ML models for SQL injection detection."""
    return {
        "XGBoost": XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=random_state,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300,
            random_state=random_state,
            n_jobs=-1,
        ),
        "SVM": SVC(
            kernel="rbf",
            C=2.0,
            gamma="scale",
            probability=True,
            random_state=random_state,
        ),
    }


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Train SQL-IDS models.")
    parser.add_argument(
        "--dataset",
        default="./data/SQLiV3.csv",
        help="Dataset CSV file or folder containing CSV files.",
    )
    parser.add_argument(
        "--models-dir",
        default="models",
        help="Directory to save trained models/vectorizer.",
    )
    parser.add_argument(
        "--plots-dir",
        default="plots",
        help="Directory to save confusion matrices and charts.",
    )
    parser.add_argument(
        "--results-file",
        default="results.txt",
        help="Output text file for evaluation report.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test set ratio.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed.",
    )
    parser.add_argument(
        "--max-features",
        type=int,
        default=5000,
        help="Maximum TF-IDF feature size.",
    )
    return parser.parse_args()


def train_pipeline(args: argparse.Namespace) -> None:
    """Train all models, save artifacts, and generate evaluation outputs."""
    ensure_directories([args.models_dir, args.plots_dir])

    loader = SQLIDataLoader(dataset_path=args.dataset)
    payloads, labels = loader.load()

    vectorizer = TfidfVectorizer(
        tokenizer=sql_tokenizer,
        token_pattern=None,
        max_features=args.max_features,
        ngram_range=(1, 2),
    )
    features = vectorizer.fit_transform(payloads)

    X_train, X_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=labels,
    )

    models = build_models(random_state=args.random_state)
    metrics_by_model: Dict[str, Dict[str, float]] = {}

    vectorizer_path = Path(args.models_dir) / "tfidf_vectorizer.pkl"
    joblib.dump(vectorizer, vectorizer_path)

    for model_name, model in models.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)
        metrics = calculate_metrics(y_test, predictions)
        metrics_by_model[model_name] = metrics

        model_filename = f"{model_name.lower()}_model.pkl"
        joblib.dump(model, Path(args.models_dir) / model_filename)
        save_confusion_matrix(y_test, predictions, model_name, args.plots_dir)

        print(
            f"{model_name}: "
            f"acc={metrics['accuracy']:.4f}, "
            f"prec={metrics['precision']:.4f}, "
            f"rec={metrics['recall']:.4f}, "
            f"f1={metrics['f1_score']:.4f}"
        )

    save_results_report(metrics_by_model, args.results_file)
    save_performance_bar_chart(
        metrics_by_model,
        str(Path(args.plots_dir) / "model_performance_comparison.png"),
    )

    print(f"Vectorizer saved: {vectorizer_path}")
    print(f"Results report saved: {args.results_file}")
    print(f"Plots saved in: {args.plots_dir}")


if __name__ == "__main__":
    train_pipeline(parse_args())
