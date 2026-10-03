"""Evaluate the email classifier against separate, labeled CSV datasets."""

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

try:
    from .ml_model import build_email_ml_pipeline
except ImportError:
    from ml_model import build_email_ml_pipeline


LABELS = {"legitimate", "suspicious", "impersonated", "phishing", "fraud"}
MAX_DATASET_BYTES = 25 * 1024 * 1024
MAX_DATASET_ROWS = 20_000


class EvaluationDataError(ValueError):
    """Raised when evaluation data cannot support an honest holdout report."""


def _load_dataset(path: Path, dataset_name: str) -> tuple[list[str], list[str], str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvaluationDataError(
            f"Could not read {dataset_name} CSV: {error}"
        ) from error
    if len(raw) > MAX_DATASET_BYTES:
        raise EvaluationDataError(
            f"{dataset_name} CSV exceeds the {MAX_DATASET_BYTES // (1024 * 1024)} MB limit."
        )

    try:
        reader = csv.DictReader(raw.decode("utf-8-sig").splitlines())
        if not reader.fieldnames or not {"text", "label"}.issubset(reader.fieldnames):
            raise EvaluationDataError(
                f"{dataset_name} CSV must contain text and label columns."
            )
        texts = []
        labels = []
        for row_number, row in enumerate(reader, start=2):
            text = str(row.get("text") or "").strip()
            label = str(row.get("label") or "").strip().lower()
            if not text or len(text) > 50_000:
                raise EvaluationDataError(
                    f"{dataset_name} CSV row {row_number} has empty text or exceeds 50,000 characters."
                )
            if label not in LABELS:
                raise EvaluationDataError(
                    f"{dataset_name} CSV row {row_number} has an unsupported label."
                )
            texts.append(text)
            labels.append(label)
            if len(texts) > MAX_DATASET_ROWS:
                raise EvaluationDataError(
                    f"{dataset_name} CSV exceeds the {MAX_DATASET_ROWS:,}-row limit."
                )
    except (UnicodeError, csv.Error) as error:
        raise EvaluationDataError(
            f"{dataset_name} CSV must be valid UTF-8 CSV: {error}"
        ) from error

    return texts, labels, hashlib.sha256(raw).hexdigest()


def _validate_dataset(texts: list[str], labels: list[str], name: str) -> dict[str, int]:
    counts = dict(Counter(labels))
    if len(texts) != len(set(text.casefold() for text in texts)):
        raise EvaluationDataError(
            f"{name} dataset contains duplicate email text; deduplicate before evaluation."
        )
    if len(counts) < 2:
        raise EvaluationDataError(f"{name} dataset must contain at least two labels.")
    return counts


def evaluate_holdout(training_csv: Path, test_csv: Path) -> dict[str, Any]:
    """Fit on training data and report metrics for a distinct test dataset."""
    training_texts, training_labels, training_hash = _load_dataset(
        training_csv, "Training"
    )
    test_texts, test_labels, test_hash = _load_dataset(test_csv, "Test")
    training_counts = _validate_dataset(
        training_texts, training_labels, "Training"
    )
    test_counts = _validate_dataset(test_texts, test_labels, "Test")

    if len(training_texts) < 15 or any(count < 3 for count in training_counts.values()):
        raise EvaluationDataError(
            "Training CSV needs at least 15 examples and three examples per label."
        )
    if not set(test_counts).issubset(training_counts):
        raise EvaluationDataError(
            "Every test label must also occur in the training dataset."
        )
    if set(test_counts) != set(training_counts):
        missing = ", ".join(sorted(set(training_counts) - set(test_counts)))
        raise EvaluationDataError(
            f"Test CSV needs at least one example for every trained label; missing: {missing}."
        )
    training_text_keys = {text.casefold() for text in training_texts}
    if training_text_keys.intersection(text.casefold() for text in test_texts):
        raise EvaluationDataError(
            "Training and test datasets overlap by exact email text; remove overlap to avoid leakage."
        )
    if "legitimate" not in test_counts or not (set(test_counts) - {"legitimate"}):
        raise EvaluationDataError(
            "Test CSV must include legitimate and at least one threat-class example."
        )

    model = build_email_ml_pipeline()
    model.fit(training_texts, training_labels)
    predictions = model.predict(test_texts).tolist()
    class_labels = sorted(training_counts)
    precision, recall, f1, supports = precision_recall_fscore_support(
        test_labels,
        predictions,
        labels=class_labels,
        zero_division=0,
    )
    matrix = confusion_matrix(test_labels, predictions, labels=class_labels)
    class_metrics = {}
    for index, label in enumerate(class_labels):
        false_positives = int(matrix[:, index].sum() - matrix[index, index])
        true_negatives = int(matrix.sum() - matrix[index, :].sum() - false_positives)
        negative_count = false_positives + true_negatives
        class_metrics[label] = {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(supports[index]),
            "false_positive_rate": (
                false_positives / negative_count if negative_count else None
            ),
        }

    legitimate_index = class_labels.index("legitimate")
    legitimate_count = int(matrix[legitimate_index, :].sum())
    threat_count = int(matrix.sum() - legitimate_count)
    false_positives = int(
        matrix[legitimate_index, :].sum() - matrix[legitimate_index, legitimate_index]
    )
    false_negatives = int(matrix[:, legitimate_index].sum() - matrix[legitimate_index, legitimate_index])

    return {
        "report_type": "separate_holdout_evaluation",
        "evidence_status": (
            "Dataset labels and provenance are user-supplied and were not independently verified."
        ),
        "model": "Word + character TF-IDF logistic regression",
        "metrics": {
            "accuracy": float(accuracy_score(test_labels, predictions)),
            "balanced_accuracy": float(
                balanced_accuracy_score(test_labels, predictions)
            ),
            "macro_f1": float(
                precision_recall_fscore_support(
                    test_labels, predictions, labels=class_labels,
                    average="macro", zero_division=0,
                )[2]
            ),
            "weighted_f1": float(
                precision_recall_fscore_support(
                    test_labels, predictions, labels=class_labels,
                    average="weighted", zero_division=0,
                )[2]
            ),
            "legitimate_false_positive_rate": (
                false_positives / legitimate_count if legitimate_count else None
            ),
            "threat_false_negative_rate": (
                false_negatives / threat_count if threat_count else None
            ),
        },
        "training": {
            "samples": len(training_texts),
            "class_counts": training_counts,
            "sha256": training_hash,
        },
        "test": {
            "samples": len(test_texts),
            "class_counts": test_counts,
            "sha256": test_hash,
        },
        "confusion_matrix": {
            "labels": class_labels,
            "rows_are_actual_columns_are_predicted": matrix.tolist(),
        },
        "per_class": class_metrics,
        "warnings": _evaluation_warnings(len(test_texts), test_counts),
        "score_note": (
            "These are metrics on the supplied holdout only. They do not establish "
            "performance on other organizations, future campaigns, or production traffic. "
            "Model confidence scores are not calibrated probabilities."
        ),
    }


def _evaluation_warnings(test_size: int, class_counts: dict[str, int]) -> list[str]:
    warnings = []
    if test_size < 1000:
        warnings.append(
            "The holdout has fewer than 1,000 examples; treat these metrics as preliminary."
        )
    low_support = sorted(label for label, count in class_counts.items() if count < 20)
    if low_support:
        warnings.append(
            "Fewer than 20 holdout examples for: "
            + ", ".join(low_support)
            + "; per-class metrics may be unstable."
        )
    return warnings


def _format_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    lines = [
        "# Email classifier holdout evaluation",
        "",
        f"- Model: {report['model']}",
        f"- Training samples: {report['training']['samples']}",
        f"- Test samples: {report['test']['samples']}",
        f"- Training SHA-256: `{report['training']['sha256']}`",
        f"- Test SHA-256: `{report['test']['sha256']}`",
        f"- Dataset review: {report['evidence_status']}",
        "",
        "## Metrics",
        "",
        "| Metric | Result |",
        "|---|---:|",
    ]
    for name, value in metrics.items():
        lines.append(f"| {name.replace('_', ' ').title()} | {value:.4f} |")
    lines.extend([
        "",
        "## Per-class results",
        "",
        "| Class | Precision | Recall | F1 | False-positive rate | Support |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    for label, values in report["per_class"].items():
        fpr = values["false_positive_rate"]
        fpr_display = "N/A" if fpr is None else f"{fpr:.4f}"
        lines.append(
            f"| {label} | {values['precision']:.4f} | {values['recall']:.4f} | "
            f"{values['f1']:.4f} | {fpr_display} | {values['support']} |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {warning}" for warning in report["warnings"])
    lines.append(f"- {report['score_note']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate Threatloom's classifier against independent labeled CSVs."
    )
    parser.add_argument("--train", required=True, type=Path, help="Reviewed training CSV")
    parser.add_argument("--test", required=True, type=Path, help="Separate labeled holdout CSV")
    parser.add_argument("--json-out", type=Path, help="Write machine-readable metrics JSON")
    parser.add_argument("--markdown-out", type=Path, help="Write a Markdown summary")
    args = parser.parse_args()

    try:
        report = evaluate_holdout(args.train, args.test)
    except EvaluationDataError as error:
        parser.error(str(error))

    rendered_json = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(rendered_json, encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.write_text(_format_markdown(report), encoding="utf-8")
    print(rendered_json, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
