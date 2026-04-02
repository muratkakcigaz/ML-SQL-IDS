"""Prediction script for SQL Injection payloads."""

from __future__ import annotations

import argparse
from typing import List

import joblib


def decode_label(value: int) -> str:
    """Human-readable output label."""
    return "SQLi Attack" if int(value) == 1 else "Benign"


def predict_payloads(model_path: str, payloads: List[str]) -> None:
    """Load model bundle and run predictions for input payloads."""
    bundle = joblib.load(model_path)
    preprocessor = bundle["preprocessor"]
    model = bundle["ensemble_model"]

    features = preprocessor.transform(payloads)
    predictions = model.predict(features)
    probabilities = model.predict_proba(features)[:, 1]

    for payload, pred, prob in zip(payloads, predictions, probabilities):
        print("-" * 80)
        print(f"Payload   : {payload}")
        print(f"Prediction: {decode_label(pred)}")
        print(f"SQLi Prob.: {prob:.4f}")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Predict SQLi payload labels.")
    parser.add_argument(
        "--model-path",
        type=str,
        default="models/sql_ids_bundle.joblib",
        help="Path to trained model bundle.",
    )
    parser.add_argument(
        "--payload",
        action="append",
        required=True,
        help="HTTP payload to classify (use multiple times for batch).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_args()
    predict_payloads(arguments.model_path, arguments.payload)
