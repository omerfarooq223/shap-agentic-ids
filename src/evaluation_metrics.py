"""
Evaluation metrics module for cross-dataset analysis.
Computes TPR, FPR, Precision, Recall, F1, Accuracy and generates reports.
"""

import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
)
import json
from datetime import datetime
from src.config import logger


class EvaluationMetrics:
    """Compute and track model performance metrics."""

    def __init__(self, model_name: str = "IDS Model"):
        self.model_name = model_name
        self.results = {}
        self.timestamp = datetime.now().isoformat()

    def compute_metrics(self, y_true, y_pred, y_proba=None, dataset_name: str = "Unknown"):
        """
        Compute all evaluation metrics.

        Args:
            y_true: Ground truth labels (0 or 1)
            y_pred: Predicted labels (0 or 1)
            y_proba: Predicted probabilities (optional, for ROC-AUC)
            dataset_name: Name of the dataset being evaluated

        Returns:
            dict: Dictionary of all computed metrics
        """
        # Compute basic metrics
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # Compute TPR and FPR
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0  # Sensitivity / Recall
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
        
        # Compute ROC-AUC if probabilities provided
        roc_auc = None
        best_threshold = 0.5
        if y_proba is not None:
            try:
                roc_auc = roc_auc_score(y_true, y_proba)
                # Find optimal threshold using Youden's J statistic
                fpr_vals, tpr_vals, thresholds = roc_curve(y_true, y_proba)
                best_idx = np.argmax(tpr_vals - fpr_vals)
                best_threshold = float(thresholds[best_idx])
            except:
                pass
        
        # Store results
        metrics = {
            "dataset": dataset_name,
            "timestamp": self.timestamp,
            "samples": len(y_true),
            "positives": int(np.sum(y_true)),
            "negatives": len(y_true) - int(np.sum(y_true)),
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "tpr": float(tpr),
            "fpr": float(fpr),
            "roc_auc": float(roc_auc) if roc_auc is not None else None,
            "best_threshold": best_threshold,
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn),
        }
        
        self.results[dataset_name] = metrics
        return metrics

    def print_metrics(self, dataset_name: str = None):
        """Print metrics in a formatted table."""
        if dataset_name and dataset_name in self.results:
            metrics = self.results[dataset_name]
        elif self.results:
            metrics = list(self.results.values())[-1]  # Last computed
        else:
            print("No metrics computed yet.")
            return

        print(f"\n{'='*70}")
        print(f"EVALUATION METRICS - {metrics['dataset']}")
        print(f"{'='*70}")
        print(f"Model: {self.model_name}")
        print(f"Timestamp: {metrics['timestamp']}")
        print(f"\n{'DATASET SUMMARY':<40}")
        print(f"  Total Samples: {metrics['samples']}")
        print(f"  Normal Flows: {metrics['negatives']}")
        print(f"  Attack Flows: {metrics['positives']}")
        
        print(f"\n{'CLASSIFICATION METRICS':<40}")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1-Score:  {metrics['f1']:.4f}")
        
        print(f"\n{'DETECTION PERFORMANCE':<40}")
        print(f"  TPR (True Positive Rate):  {metrics['tpr']:.4f}")
        print(f"  FPR (False Positive Rate): {metrics['fpr']:.4f}")
        if metrics['roc_auc']:
            print(f"  ROC-AUC: {metrics['roc_auc']:.4f}")
            print(f"  Optimal Threshold: {metrics.get('best_threshold', 0.5):.4f}")
        
        print(f"\n{'CONFUSION MATRIX':<40}")
        print(f"  TP: {metrics['true_positives']:<10} FP: {metrics['false_positives']}")
        print(f"  FN: {metrics['false_negatives']:<10} TN: {metrics['true_negatives']}")
        print(f"{'='*70}\n")

    def compare_datasets(self):
        """Print comparison between datasets."""
        if len(self.results) < 2:
            print("Need at least 2 datasets for comparison.")
            return

        print(f"\n{'='*90}")
        print(f"CROSS-DATASET EVALUATION COMPARISON")
        print(f"{'='*90}")
        print(f"Model: {self.model_name}\n")

        # Create comparison table
        datasets = list(self.results.keys())
        metrics_keys = ["accuracy", "precision", "recall", "f1", "tpr", "fpr"]
        
        # Header
        header = f"{'Metric':<20}"
        for ds in datasets:
            header += f"{ds:<25}"
        print(header)
        print("-" * (20 + len(datasets) * 25))
        
        # Data rows
        for metric in metrics_keys:
            row = f"{metric.upper():<20}"
            for ds in datasets:
                value = self.results[ds].get(metric, 0)
                if value is not None:
                    row += f"{value:<25.4f}"
                else:
                    row += f"{'N/A':<25}"
            print(row)
        
        # Sample counts
        print(f"\n{'SAMPLE COUNTS':<20}")
        row = f"{'Samples':<20}"
        for ds in datasets:
            count = self.results[ds]["samples"]
            row += f"{count:<25}"
        print(row)
        
        row = f"{'Normal':<20}"
        for ds in datasets:
            count = self.results[ds]["negatives"]
            row += f"{count:<25}"
        print(row)
        
        row = f"{'Attacks':<20}"
        for ds in datasets:
            count = self.results[ds]["positives"]
            row += f"{count:<25}"
        print(row)
        
        print(f"{'='*90}\n")

    def save_report(self, output_path: Path):
        """Save evaluation report to JSON file."""
        report = {
            "model": self.model_name,
            "timestamp": self.timestamp,
            "datasets": self.results,
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ Report saved to {output_path}")

    def get_metrics_dataframe(self):
        """Return metrics as a pandas DataFrame."""
        return pd.DataFrame(list(self.results.values()))

    def calculate_generalization_gap(self, source_dataset: str, target_dataset: str):
        """
        Calculate generalization gap between two datasets.
        Lower gap indicates better generalization.

        Args:
            source_dataset: Name of training dataset
            target_dataset: Name of test dataset

        Returns:
            dict: Generalization metrics
        """
        if source_dataset not in self.results or target_dataset not in self.results:
            return None

        source = self.results[source_dataset]
        target = self.results[target_dataset]

        gap = {
            "source_dataset": source_dataset,
            "target_dataset": target_dataset,
            "accuracy_gap": abs(source["accuracy"] - target["accuracy"]),
            "f1_gap": abs(source["f1"] - target["f1"]),
            "tpr_gap": abs(source["tpr"] - target["tpr"]),
            "fpr_gap": abs(source["fpr"] - target["fpr"]),
        }

        return gap

    def print_generalization_gap(self, source_dataset: str, target_dataset: str):
        """Print generalization gap analysis."""
        gap = self.calculate_generalization_gap(source_dataset, target_dataset)
        if gap is None:
            print("Cannot compute gap - missing dataset results.")
            return

        print(f"\n{'='*70}")
        print(f"GENERALIZATION GAP ANALYSIS")
        print(f"Training: {gap['source_dataset']} → Testing: {gap['target_dataset']}")
        print(f"{'='*70}")
        print(f"Accuracy Gap: {gap['accuracy_gap']:.4f}")
        print(f"F1-Score Gap: {gap['f1_gap']:.4f}")
        print(f"TPR Gap: {gap['tpr_gap']:.4f}")
        print(f"FPR Gap: {gap['fpr_gap']:.4f}")
        print(f"{'='*70}\n")

        # Interpretation
        avg_gap = np.mean([gap['accuracy_gap'], gap['f1_gap'], gap['tpr_gap']])
        if avg_gap < 0.05:
            print("✓ EXCELLENT generalization - model performs similarly on both datasets")
        elif avg_gap < 0.10:
            print("✓ GOOD generalization - minor performance drop on new dataset")
        elif avg_gap < 0.15:
            print("⚠ MODERATE generalization - notable performance drop")
        else:
            print("✗ POOR generalization - significant overfitting detected")


def load_dataset(path: Path, max_rows: int = None):
    """
    Load dataset and return features and labels.

    Args:
        path: Path to CSV file
        max_rows: Maximum rows to load (for testing)

    Returns:
        tuple: (X, y) where X is features and y is labels
    """
    df = pd.read_csv(path, nrows=max_rows)
    
    # Handle CICIDS2017
    if 'Label' in df.columns and df['Label'].dtype != 'int':
        # Convert label column if it contains strings
        df['Label'] = (df['Label'].astype(str).str.lower() != 'benign').astype(int)
    
    # Handle UNSW-NB15
    if 'Label' in df.columns:
        y = df['Label'].values
        X = df.drop('Label', axis=1)
        # Drop non-numeric columns
        X = X.select_dtypes(include=[np.number])
        return X, y
    else:
        raise ValueError(f"No 'Label' column found in {path}")


def compare_model_performance(model, cicids_path, unsw_path):
    """
    Train on CICIDS2017, test on both CICIDS2017 and UNSW-NB15.

    Args:
        model: Scikit-learn model with fit/predict methods
        cicids_path: Path to CICIDS2017 data
        unsw_path: Path to UNSW-NB15 data

    Returns:
        EvaluationMetrics object with results
    """
    metrics = EvaluationMetrics(model_name=model.__class__.__name__)

    # Load CICIDS2017 and split
    print("Loading CICIDS2017...")
    X_cicids, y_cicids = load_dataset(cicids_path, max_rows=10000)
    
    # Split for training and testing
    split_idx = int(0.8 * len(X_cicids))
    X_train, X_test_cicids = X_cicids[:split_idx], X_cicids[split_idx:]
    y_train, y_test_cicids = y_cicids[:split_idx], y_cicids[split_idx:]

    # Train model
    print("Training model on CICIDS2017...")
    model.fit(X_train, y_train)

    # Test on CICIDS2017
    print("Testing on CICIDS2017...")
    y_pred_cicids = model.predict(X_test_cicids)
    y_proba_cicids = getattr(model, "predict_proba", lambda x: None)(X_test_cicids)
    if y_proba_cicids is not None:
        y_proba_cicids = y_proba_cicids[:, 1]
    
    metrics.compute_metrics(y_test_cicids, y_pred_cicids, y_proba_cicids, "CICIDS2017")

    # Load UNSW-NB15 and test
    print("Loading UNSW-NB15...")
    X_unsw, y_unsw = load_dataset(unsw_path, max_rows=10000)

    # Align features
    common_features = list(set(X_train.columns) & set(X_unsw.columns))
    X_train_aligned = X_train[common_features]
    X_test_cicids_aligned = X_test_cicids[common_features]
    X_unsw_aligned = X_unsw[common_features]

    # Retrain with aligned features
    print("Retraining on aligned features...")
    model.fit(X_train_aligned, y_train)

    # Test on UNSW-NB15
    print("Testing on UNSW-NB15...")
    y_pred_unsw = model.predict(X_unsw_aligned)
    y_proba_unsw = getattr(model, "predict_proba", lambda x: None)(X_unsw_aligned)
    if y_proba_unsw is not None:
        y_proba_unsw = y_proba_unsw[:, 1]
    
    metrics.compute_metrics(y_unsw, y_pred_unsw, y_proba_unsw, "UNSW-NB15")

    return metrics


if __name__ == "__main__":
    from src.services.inference import inference_service
    from src.data_loader import load_data, load_unsw_nb15, preprocess_data
    from src import config
    from sklearn.model_selection import train_test_split

    print("\n" + "="*70)
    print("CROSS-DATASET EVALUATION: CICIDS2017 vs UNSW-NB15")
    print(f"Mode: {'CROSS_DATASET' if config.CROSS_DATASET_MODE else 'LEGACY'}")
    print(f"Features: {len(config.NUMERIC_FEATURES)} core common features")
    print("="*70)

    # 1. Initialize metrics and inference
    metrics_tracker = EvaluationMetrics(model_name="RandomForest (Robust)")
    inference_service.load()

    # 2. Evaluate on CICIDS2017 (Source Domain)
    print("\n[1/2] Evaluating on CICIDS2017 (Source Domain)...")
    df_cicids = load_data()
    X_cicids, y_cicids = preprocess_data(df_cicids)
    
    # Use 20% test split
    _, X_test, _, y_test = train_test_split(X_cicids, y_cicids, test_size=0.2, stratify=y_cicids, random_state=42)
    
    y_pred = inference_service._model.predict(X_test)
    y_proba = inference_service._model.predict_proba(X_test)[:, 1]
    
    metrics_tracker.compute_metrics(y_test, y_pred, y_proba, "CICIDS2017")
    metrics_tracker.print_metrics("CICIDS2017")

    # 3. Evaluate on UNSW-NB15 (Target Domain)
    print("\n[2/2] Evaluating on UNSW-NB15 (Target Domain)...")
    df_unsw = load_unsw_nb15()
    if df_unsw is not None:
        # Note: load_unsw_nb15 now correctly maps to the 8-feature schema
        X_unsw = df_unsw[config.NUMERIC_FEATURES]
        y_unsw = df_unsw[config.TARGET_COLUMN]
        
        y_pred_unsw_default = inference_service._model.predict(X_unsw)
        y_proba_unsw = inference_service._model.predict_proba(X_unsw)[:, 1]
        
        # Calculate optimal threshold for UNSW
        from sklearn.metrics import roc_curve
        fpr_unsw, tpr_unsw, thresholds_unsw = roc_curve(y_unsw, y_proba_unsw)
        best_threshold = thresholds_unsw[np.argmax(tpr_unsw - fpr_unsw)]
        y_pred_unsw = (y_proba_unsw >= best_threshold).astype(int)
        
        logger.info(f"✓ Applied optimal threshold for UNSW-NB15: {best_threshold:.4f}")
        
        metrics_tracker.compute_metrics(y_unsw, y_pred_unsw, y_proba_unsw, "UNSW-NB15")
        metrics_tracker.print_metrics("UNSW-NB15")
        
        # 4. Final Comparison
        metrics_tracker.compare_datasets()
        metrics_tracker.print_generalization_gap("CICIDS2017", "UNSW-NB15")
        
        # 5. Save final artifact
        report_path = config.DOCS_DIR / "evaluation_results.json"
        metrics_tracker.save_report(report_path)
    else:
        print("✗ UNSW-NB15 dataset not found. Skipping cross-dataset analysis.")
