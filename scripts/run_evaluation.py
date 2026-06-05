#!/usr/bin/env python3
"""
Multi-model IDS evaluation and efficiency benchmark.

The production IDS still uses Random Forest + SHAP. This script is the
research/evaluation harness: it compares classical baselines against the
production model on CICIDS2017 and UNSW-NB15 using the same split per dataset.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import tracemalloc
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.naive_bayes import ComplementNB, GaussianNB, MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
RESULTS_JSON = DOCS_DIR / "baseline_efficiency_results.json"
RESULTS_MD = DOCS_DIR / "BASELINE_EFFICIENCY_COMPARISON.md"

RANDOM_STATE = 42
CICIDS_SAMPLE_SIZE = int(os.getenv("EVAL_CICIDS_SAMPLE_SIZE", "30000"))
UNSW_SAMPLE_SIZE = int(os.getenv("EVAL_UNSW_SAMPLE_SIZE", "60000"))
TEST_SIZE = float(os.getenv("EVAL_TEST_SIZE", "0.2"))


def _optional_xgboost() -> tuple[str, BaseEstimator] | None:
    try:
        from xgboost import XGBClassifier
    except Exception:
        return None

    return (
        "XGBoost",
        XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
    )


def model_candidates() -> list[tuple[str, BaseEstimator]]:
    """Return baseline classifiers plus the production Random Forest model."""
    candidates: list[tuple[str, BaseEstimator]] = [
        (
            "Logistic Regression",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                solver="lbfgs",
                random_state=RANDOM_STATE,
            ),
        ),
        ("GaussianNB", GaussianNB()),
        ("MultinomialNB", MultinomialNB()),
        ("ComplementNB", ComplementNB()),
        (
            "Decision Tree",
            DecisionTreeClassifier(
                max_depth=20,
                class_weight="balanced",
                random_state=RANDOM_STATE,
            ),
        ),
        (
            "Random Forest",
            RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        ),
    ]

    xgb = _optional_xgboost()
    if xgb is not None:
        candidates.append(xgb)
    return candidates


def load_cicids() -> tuple[pd.DataFrame, pd.Series]:
    path = ROOT / "data" / "CICIDS2017.csv"
    print(f"  Loading CICIDS2017 from {path}...")
    df = pd.read_csv(path)
    y = (df["Label"].astype(str).str.lower() != "benign").astype(int)
    X = df.drop(columns=["Label"], errors="ignore")
    X = X.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
    return _sample_dataset(X, y, CICIDS_SAMPLE_SIZE)


def load_cicids_multiclass() -> tuple[pd.DataFrame, pd.Series]:
    path = ROOT / "data" / "CICIDS2017.csv"
    df = pd.read_csv(path)
    y = df["Label"].astype(str).str.replace("\ufffd", "-", regex=False).str.strip()
    X = df.drop(columns=["Label"], errors="ignore")
    X = X.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
    return _sample_dataset(X, y, CICIDS_SAMPLE_SIZE)


def load_unsw() -> tuple[pd.DataFrame, pd.Series]:
    train_path = ROOT / "data" / "UNSW_NB15_training-set.csv"
    test_path = ROOT / "data" / "UNSW_NB15_testing-set.csv"
    print(f"  Loading UNSW-NB15 from {train_path.name} + {test_path.name}...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    df = pd.concat([train_df, test_df], ignore_index=True)
    y = df["label"].astype(int)
    X = df.drop(
        columns=["id", "label", "attack_cat", "proto", "service", "state"],
        errors="ignore",
    )
    X = X.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
    return _sample_dataset(X, y, UNSW_SAMPLE_SIZE)


def load_unsw_multiclass() -> tuple[pd.DataFrame, pd.Series]:
    train_path = ROOT / "data" / "UNSW_NB15_training-set.csv"
    test_path = ROOT / "data" / "UNSW_NB15_testing-set.csv"
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    df = pd.concat([train_df, test_df], ignore_index=True)
    y = df.get("attack_cat", pd.Series(["Unknown"] * len(df))).astype(str).str.strip()
    y = y.where(y.ne("") & y.ne("nan"), "Normal")
    X = df.drop(
        columns=["id", "label", "attack_cat", "proto", "service", "state"],
        errors="ignore",
    )
    X = X.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
    return _sample_dataset(X, y, UNSW_SAMPLE_SIZE)


def _sample_dataset(
    X: pd.DataFrame,
    y: pd.Series,
    sample_size: int,
) -> tuple[pd.DataFrame, pd.Series]:
    if sample_size <= 0 or sample_size >= len(X):
        return X.reset_index(drop=True), y.reset_index(drop=True)

    sampled = X.sample(n=sample_size, random_state=RANDOM_STATE)
    return sampled.reset_index(drop=True), y.loc[sampled.index].reset_index(drop=True)


def make_pipeline(model: BaseEstimator, numeric_columns: list[str]) -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "numeric",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        # Keeps Naive Bayes variants non-negative and makes
                        # timing comparisons independent of raw feature scale.
                        ("scaler", MinMaxScaler()),
                    ]
                ),
                numeric_columns,
            )
        ],
        remainder="drop",
    )
    return Pipeline(steps=[("preprocess", preprocessor), ("classifier", model)])


def positive_scores(model: Pipeline, X_test: pd.DataFrame) -> np.ndarray | None:
    classifier = model.named_steps["classifier"]
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X_test)[:, 1]
    if hasattr(classifier, "decision_function"):
        scores = model.decision_function(X_test)
        return 1 / (1 + np.exp(-scores))
    return None


def serialized_model_size_mb(model: Pipeline) -> float:
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=True) as tmp:
        joblib.dump(model, tmp.name)
        return Path(tmp.name).stat().st_size / (1024 * 1024)


def benchmark_model(
    dataset_name: str,
    model_name: str,
    estimator: BaseEstimator,
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
) -> dict[str, Any]:
    pipeline = make_pipeline(estimator, list(X_train.columns))

    tracemalloc.start()
    fit_start = time.perf_counter()
    pipeline.fit(X_train, y_train)
    train_time_s = time.perf_counter() - fit_start
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    infer_start = time.perf_counter()
    y_pred = pipeline.predict(X_test)
    inference_time_s = time.perf_counter() - infer_start

    y_score = positive_scores(pipeline, X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    result = {
        "dataset": dataset_name,
        "model": model_name,
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "features": int(X_train.shape[1]),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_score)) if y_score is not None else None,
        "tpr": float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "train_time_s": float(train_time_s),
        "inference_time_ms_per_sample": float((inference_time_s / len(X_test)) * 1000),
        "peak_train_memory_mb": float(peak_bytes / (1024 * 1024)),
        "model_size_mb": float(serialized_model_size_mb(pipeline)),
    }
    return result


def benchmark_attack_classes(
    dataset_name: str,
    X: pd.DataFrame,
    y: pd.Series,
) -> dict[str, Any] | None:
    class_counts = y.value_counts()
    excluded_classes = class_counts[class_counts < 2].index.tolist()
    if excluded_classes:
        keep_mask = ~y.isin(excluded_classes)
        X = X.loc[keep_mask].reset_index(drop=True)
        y = y.loc[keep_mask].reset_index(drop=True)
        class_counts = y.value_counts()

    if len(class_counts) < 3:
        return None

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    model = make_pipeline(
        RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
        list(X_train.columns),
    )
    start = time.perf_counter()
    model.fit(X_train, y_train)
    train_time_s = time.perf_counter() - start
    y_pred = model.predict(X_test)

    report = classification_report(
        y_test,
        y_pred,
        output_dict=True,
        zero_division=0,
    )
    rows = []
    for label, values in report.items():
        if label in {"accuracy", "macro avg", "weighted avg"}:
            continue
        rows.append({
            "attack_class": label,
            "precision": float(values["precision"]),
            "recall": float(values["recall"]),
            "f1": float(values["f1-score"]),
            "support": int(values["support"]),
        })

    return {
        "dataset": dataset_name,
        "model": "Random Forest",
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "features": int(X_train.shape[1]),
        "train_time_s": float(train_time_s),
        "accuracy": float(report.get("accuracy", 0.0)),
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "excluded_rare_classes": [str(label) for label in excluded_classes],
        "classes": sorted(rows, key=lambda row: row["support"], reverse=True),
    }


def evaluate_dataset(dataset_name: str, X: pd.DataFrame, y: pd.Series) -> list[dict[str, Any]]:
    print(f"\n{dataset_name}")
    print("-" * 90)
    print(f"  Samples: {len(X):,}; numeric features: {X.shape[1]}")
    print(f"  Label distribution: {dict(y.value_counts().sort_index())}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    results = []
    for model_name, estimator in model_candidates():
        print(f"  Benchmarking {model_name}...")
        result = benchmark_model(
            dataset_name,
            model_name,
            estimator,
            X_train,
            X_test,
            y_train,
            y_test,
        )
        results.append(result)
        print(
            "    "
            f"F1={result['f1']:.4f}, "
            f"AUC={result['roc_auc']:.4f}, "
            f"train={result['train_time_s']:.2f}s, "
            f"infer={result['inference_time_ms_per_sample']:.4f}ms/sample, "
            f"size={result['model_size_mb']:.2f}MB"
        )

    return results


def print_summary(results: list[dict[str, Any]]) -> None:
    print("\n" + "=" * 90)
    print("MODEL PERFORMANCE + EFFICIENCY SUMMARY")
    print("=" * 90)

    for dataset in sorted({row["dataset"] for row in results}):
        rows = [row for row in results if row["dataset"] == dataset]
        rows = sorted(rows, key=lambda row: row["f1"], reverse=True)

        print(f"\n{dataset}")
        print(
            f"{'Model':<22} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} "
            f"{'AUC':>7} {'Train(s)':>9} {'Infer(ms)':>10} {'Mem(MB)':>9} {'Size(MB)':>9}"
        )
        print("-" * 105)
        for row in rows:
            auc = f"{row['roc_auc']:.4f}" if row["roc_auc"] is not None else "N/A"
            print(
                f"{row['model']:<22} "
                f"{row['accuracy']:>7.4f} "
                f"{row['precision']:>7.4f} "
                f"{row['recall']:>7.4f} "
                f"{row['f1']:>7.4f} "
                f"{auc:>7} "
                f"{row['train_time_s']:>9.2f} "
                f"{row['inference_time_ms_per_sample']:>10.4f} "
                f"{row['peak_train_memory_mb']:>9.2f} "
                f"{row['model_size_mb']:>9.2f}"
            )


def write_reports(results: list[dict[str, Any]], per_class_results: list[dict[str, Any]]) -> None:
    timestamp = datetime.now().isoformat()
    report = {
        "benchmark": "Baseline classifier and efficiency comparison",
        "timestamp": timestamp,
        "notes": [
            "Production inference still uses Random Forest + SHAP.",
            "XGBoost is included only when the optional xgboost package is installed.",
            "Peak memory is measured with Python tracemalloc during fit and is a relative benchmark, not total process RSS.",
        ],
        "configuration": {
            "random_state": RANDOM_STATE,
            "test_size": TEST_SIZE,
            "cicids_sample_size": CICIDS_SAMPLE_SIZE,
            "unsw_sample_size": UNSW_SAMPLE_SIZE,
        },
        "results": results,
        "per_attack_class": per_class_results,
    }

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    with RESULTS_JSON.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    with RESULTS_MD.open("w", encoding="utf-8") as fh:
        fh.write("# Baseline Classifier & Efficiency Comparison\n\n")
        fh.write(f"**Generated:** {timestamp}  \n")
        fh.write("**Purpose:** Compare the production Random Forest detector against classical IDS baselines.  \n\n")
        fh.write(
            "The production pipeline remains **Random Forest + SHAP + Agentic verification**. "
            "This benchmark adds academic baselines and efficiency metrics so the model choice can be justified empirically.\n\n"
        )

        for dataset in sorted({row["dataset"] for row in results}):
            rows = sorted(
                [row for row in results if row["dataset"] == dataset],
                key=lambda row: row["f1"],
                reverse=True,
            )
            fh.write(f"## {dataset}\n\n")
            fh.write(
                "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Train Time (s) | Inference (ms/sample) | Peak Train Memory (MB) | Model Size (MB) |\n"
            )
            fh.write("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
            for row in rows:
                auc = f"{row['roc_auc']:.4f}" if row["roc_auc"] is not None else "N/A"
                fh.write(
                    f"| {row['model']} | {row['accuracy']:.4f} | {row['precision']:.4f} | "
                    f"{row['recall']:.4f} | {row['f1']:.4f} | {auc} | "
                    f"{row['train_time_s']:.2f} | {row['inference_time_ms_per_sample']:.4f} | "
                    f"{row['peak_train_memory_mb']:.2f} | {row['model_size_mb']:.2f} |\n"
                )
            best_f1 = rows[0]
            fastest = min(rows, key=lambda row: row["inference_time_ms_per_sample"])
            smallest = min(rows, key=lambda row: row["model_size_mb"])
            fh.write(
                f"\n**Finding:** {best_f1['model']} has the strongest F1 score on this run. "
                f"{fastest['model']} is fastest at inference, and {smallest['model']} has the smallest serialized footprint.\n\n"
            )

        fh.write("## Interpretation\n\n")
        fh.write(
            "- Logistic Regression and Naive Bayes variants provide lightweight baselines for speed, memory, and model-size comparisons.\n"
        )
        fh.write(
            "- Decision Tree gives a transparent tree baseline, useful for explaining the value of the production ensemble.\n"
        )
        fh.write(
            "- Random Forest remains the production model because it balances tabular IDS accuracy with SHAP-compatible explainability.\n"
        )
        fh.write(
            "- XGBoost is treated as optional so the benchmark works in the base environment without adding a mandatory dependency.\n"
        )

        if per_class_results:
            fh.write("\n## Per-Attack-Class Metrics\n\n")
            fh.write(
                "Per-class metrics use Random Forest because it is the production detector. "
                "They show which attack families are easiest or hardest for the model.\n\n"
            )
            for dataset_report in per_class_results:
                fh.write(f"### {dataset_report['dataset']}\n\n")
                fh.write(
                    f"Accuracy: {dataset_report['accuracy']:.4f}; "
                    f"Macro F1: {dataset_report['macro_f1']:.4f}; "
                    f"Weighted F1: {dataset_report['weighted_f1']:.4f}\n\n"
                )
                if dataset_report.get("excluded_rare_classes"):
                    excluded = ", ".join(dataset_report["excluded_rare_classes"])
                    fh.write(f"Excluded rare classes with fewer than two sampled rows: {excluded}\n\n")
                fh.write("| Attack Class | Precision | Recall | F1 | Support |\n")
                fh.write("|---|---:|---:|---:|---:|\n")
                for row in dataset_report["classes"]:
                    fh.write(
                        f"| {row['attack_class']} | {row['precision']:.4f} | "
                        f"{row['recall']:.4f} | {row['f1']:.4f} | {row['support']} |\n"
                    )
                fh.write("\n")

    print(f"\nSaved JSON report: {RESULTS_JSON}")
    print(f"Saved Markdown report: {RESULTS_MD}")


def main() -> None:
    print("=" * 90)
    print("MULTI-MODEL IDS EVALUATION: BASELINES + EFFICIENCY")
    print("=" * 90)

    all_results: list[dict[str, Any]] = []
    per_class_results: list[dict[str, Any]] = []
    datasets = [
        ("CICIDS2017", load_cicids),
        ("UNSW-NB15", load_unsw),
    ]

    for dataset_name, loader in datasets:
        X, y = loader()
        all_results.extend(evaluate_dataset(dataset_name, X, y))

    print("\n" + "=" * 90)
    print("PER-ATTACK-CLASS RANDOM FOREST METRICS")
    print("=" * 90)
    multiclass_datasets = [
        ("CICIDS2017", load_cicids_multiclass),
        ("UNSW-NB15", load_unsw_multiclass),
    ]
    for dataset_name, loader in multiclass_datasets:
        X, y = loader()
        report = benchmark_attack_classes(dataset_name, X, y)
        if report is None:
            continue
        per_class_results.append(report)
        print(
            f"{dataset_name}: accuracy={report['accuracy']:.4f}, "
            f"macro_f1={report['macro_f1']:.4f}, "
            f"classes={len(report['classes'])}"
        )

    print_summary(all_results)
    write_reports(all_results, per_class_results)


if __name__ == "__main__":
    main()
