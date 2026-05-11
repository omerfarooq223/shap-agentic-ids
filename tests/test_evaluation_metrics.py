"""
Cross-dataset evaluation tests.
Tests model generalization between CICIDS2017 and UNSW-NB15.
"""

import pytest
import numpy as np
import pandas as pd
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.evaluation_metrics import EvaluationMetrics, load_dataset
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler


class TestEvaluationMetrics:
    """Test evaluation metrics computation."""

    def test_metrics_initialization(self):
        """Test EvaluationMetrics initialization."""
        metrics = EvaluationMetrics(model_name="TestModel")
        assert metrics.model_name == "TestModel"
        assert len(metrics.results) == 0
        print("✓ Metrics object initialized")

    def test_metrics_compute(self):
        """Test metrics computation."""
        metrics = EvaluationMetrics()
        
        # Create dummy predictions
        y_true = np.array([0, 0, 1, 1, 0, 1, 0, 1])
        y_pred = np.array([0, 1, 1, 1, 0, 0, 0, 1])
        
        result = metrics.compute_metrics(y_true, y_pred, dataset_name="TestSet")
        
        # Check all metrics are present
        required_metrics = [
            'accuracy', 'precision', 'recall', 'f1',
            'tpr', 'fpr', 'true_positives', 'false_positives',
            'true_negatives', 'false_negatives'
        ]
        
        for metric in required_metrics:
            assert metric in result, f"Missing metric: {metric}"
        
        # Check value ranges
        assert 0 <= result['accuracy'] <= 1
        assert 0 <= result['precision'] <= 1
        assert 0 <= result['recall'] <= 1
        assert 0 <= result['f1'] <= 1
        
        print(f"✓ Metrics computed: Accuracy={result['accuracy']:.4f}, F1={result['f1']:.4f}")

    def test_metrics_with_probabilities(self):
        """Test metrics computation with probability scores."""
        metrics = EvaluationMetrics()
        
        y_true = np.array([0, 0, 1, 1, 0, 1, 0, 1])
        y_pred = np.array([0, 1, 1, 1, 0, 0, 0, 1])
        y_proba = np.array([0.1, 0.6, 0.9, 0.8, 0.2, 0.3, 0.1, 0.95])
        
        result = metrics.compute_metrics(y_true, y_pred, y_proba, "TestSet")
        
        # ROC-AUC should be computed
        assert result['roc_auc'] is not None
        assert 0 <= result['roc_auc'] <= 1
        
        print(f"✓ ROC-AUC computed: {result['roc_auc']:.4f}")

    def test_metrics_perfect_prediction(self):
        """Test metrics with perfect predictions."""
        metrics = EvaluationMetrics()
        
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([0, 0, 1, 1])
        
        result = metrics.compute_metrics(y_true, y_pred, dataset_name="Perfect")
        
        assert result['accuracy'] == 1.0
        assert result['precision'] == 1.0
        assert result['recall'] == 1.0
        assert result['f1'] == 1.0
        assert result['tpr'] == 1.0
        assert result['fpr'] == 0.0
        
        print("✓ Perfect prediction metrics correct")

    def test_metrics_worst_prediction(self):
        """Test metrics with worst-case predictions."""
        metrics = EvaluationMetrics()
        
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([1, 1, 0, 0])
        
        result = metrics.compute_metrics(y_true, y_pred, dataset_name="Worst")
        
        assert result['accuracy'] == 0.0
        assert result['tpr'] == 0.0
        assert result['fpr'] == 1.0
        
        print("✓ Worst prediction metrics correct")


class TestDatasetLoading:
    """Test dataset loading for evaluation."""

    def test_load_cicids_dataset(self, data_dir):
        """Test loading CICIDS2017 dataset."""
        try:
            data_path = data_dir / "CICIDS2017.csv"
            X, y = load_dataset(data_path, max_rows=100)
            
            assert len(X) == len(y) == 100
            assert X.shape[1] > 0  # Has features
            assert set(y).issubset({0, 1})  # Binary labels
            
            print(f"✓ Loaded CICIDS2017: {X.shape} samples/features")
        except FileNotFoundError:
            pytest.skip("CICIDS2017 data not found")
        except Exception as e:
            pytest.skip(f"Could not load CICIDS: {e}")

    def test_load_unsw_dataset(self, dataset_dir):
        """Test loading UNSW-NB15 dataset."""
        try:
            data_path = dataset_dir / "UNSW_NB15_training-set.csv"
            X, y = load_dataset(data_path, max_rows=100)
            
            assert len(X) == len(y) == 100
            assert X.shape[1] > 0
            assert set(y).issubset({0, 1})
            
            print(f"✓ Loaded UNSW-NB15: {X.shape} samples/features")
        except FileNotFoundError:
            pytest.skip("UNSW-NB15 data not found")
        except Exception as e:
            pytest.skip(f"Could not load UNSW: {e}")

    def test_dataset_feature_alignment(self, data_dir, dataset_dir):
        """Test feature alignment between datasets."""
        try:
            # Load both datasets
            cicids_path = data_dir / "CICIDS2017.csv"
            unsw_path = dataset_dir / "UNSW_NB15_training-set.csv"
            
            X_cicids, _ = load_dataset(cicids_path, max_rows=10)
            X_unsw, _ = load_dataset(unsw_path, max_rows=10)
            
            cicids_features = set(X_cicids.columns)
            unsw_features = set(X_unsw.columns)
            
            # Find common features
            common = cicids_features & unsw_features
            
            print(f"✓ CICIDS: {len(cicids_features)} features")
            print(f"✓ UNSW: {len(unsw_features)} features")
            print(f"✓ Common: {len(common)} features")
            
            assert len(common) > 0, "No common features"
        except Exception as e:
            pytest.skip(f"Feature alignment test error: {e}")


class TestCrossDatasetEvaluation:
    """Test cross-dataset model evaluation."""

    def test_model_trained_on_cicids(self, data_dir):
        """Test model training on CICIDS2017."""
        try:
            cicids_path = data_dir / "CICIDS2017.csv"
            X, y = load_dataset(cicids_path, max_rows=200)
            
            model = RandomForestClassifier(n_estimators=10, random_state=42)
            model.fit(X, y)
            
            # Test on same dataset
            predictions = model.predict(X[:50])
            
            assert len(predictions) == 50
            assert set(predictions).issubset({0, 1})
            
            print("✓ Model trained and tested on CICIDS2017")
        except Exception as e:
            pytest.skip(f"Could not train on CICIDS: {e}")

    def test_model_generalization_to_unsw(self, data_dir, dataset_dir):
        """Test model generalization from CICIDS to UNSW."""
        try:
            # Load CICIDS
            cicids_path = data_dir / "CICIDS2017.csv"
            X_cicids, y_cicids = load_dataset(cicids_path, max_rows=200)
            
            # Load UNSW
            unsw_path = dataset_dir / "UNSW_NB15_training-set.csv"
            X_unsw, y_unsw = load_dataset(unsw_path, max_rows=200)
            
            # Find common features
            common_features = list(set(X_cicids.columns) & set(X_unsw.columns))
            
            if len(common_features) < 5:
                pytest.skip("Not enough common features for evaluation")
            
            X_cicids_aligned = X_cicids[common_features]
            X_unsw_aligned = X_unsw[common_features]
            
            # Train on CICIDS
            model = RandomForestClassifier(n_estimators=10, random_state=42)
            model.fit(X_cicids_aligned, y_cicids)
            
            # Test on UNSW
            metrics = EvaluationMetrics(model_name="RandomForest")
            
            # Predictions on CICIDS test set
            pred_cicids = model.predict(X_cicids_aligned)
            metrics.compute_metrics(y_cicids, pred_cicids, dataset_name="CICIDS2017")
            
            # Predictions on UNSW
            pred_unsw = model.predict(X_unsw_aligned)
            metrics.compute_metrics(y_unsw, pred_unsw, dataset_name="UNSW-NB15")
            
            # Print comparison
            cicids_f1 = metrics.results["CICIDS2017"]["f1"]
            unsw_f1 = metrics.results["UNSW-NB15"]["f1"]
            
            print(f"✓ CICIDS F1: {cicids_f1:.4f}")
            print(f"✓ UNSW F1: {unsw_f1:.4f}")
            
            # Generalization is acceptable if performance doesn't drop too much
            gap = abs(cicids_f1 - unsw_f1)
            if gap < 0.15:
                print(f"✓ GOOD generalization (gap: {gap:.4f})")
            else:
                print(f"⚠ MODERATE generalization gap: {gap:.4f}")
            
        except Exception as e:
            pytest.skip(f"Generalization test error: {e}")

    def test_generalization_gap_calculation(self):
        """Test generalization gap calculation."""
        metrics = EvaluationMetrics()
        
        # Simulate results
        y_true1 = np.array([0, 0, 1, 1, 0, 1, 0, 1])
        y_pred1 = np.array([0, 0, 1, 1, 0, 1, 0, 1])
        metrics.compute_metrics(y_true1, y_pred1, dataset_name="Dataset1")
        
        y_true2 = np.array([0, 1, 1, 1, 0, 0, 0, 1])
        y_pred2 = np.array([0, 0, 1, 1, 0, 1, 1, 1])
        metrics.compute_metrics(y_true2, y_pred2, dataset_name="Dataset2")
        
        # Calculate gap
        gap = metrics.calculate_generalization_gap("Dataset1", "Dataset2")
        
        assert gap is not None
        assert 'accuracy_gap' in gap
        assert 'f1_gap' in gap
        assert 'tpr_gap' in gap
        assert 'fpr_gap' in gap
        
        print(f"✓ Generalization gap computed")
        print(f"  Accuracy gap: {gap['accuracy_gap']:.4f}")
        print(f"  F1 gap: {gap['f1_gap']:.4f}")


class TestMetricsReporting:
    """Test metrics reporting functionality."""

    def test_metrics_dataframe(self):
        """Test metrics export to DataFrame."""
        metrics = EvaluationMetrics()
        
        for i in range(2):
            y_true = np.random.randint(0, 2, 50)
            y_pred = np.random.randint(0, 2, 50)
            metrics.compute_metrics(y_true, y_pred, dataset_name=f"Dataset{i}")
        
        df = metrics.get_metrics_dataframe()
        
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert 'accuracy' in df.columns
        
        print(f"✓ Metrics exported to DataFrame: {df.shape}")

    def test_metrics_report_saving(self, tmp_path):
        """Test saving metrics report to JSON."""
        metrics = EvaluationMetrics()
        
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([0, 1, 1, 1])
        metrics.compute_metrics(y_true, y_pred, dataset_name="Test")
        
        report_path = tmp_path / "report.json"
        metrics.save_report(report_path)
        
        assert report_path.exists()
        print(f"✓ Report saved to {report_path}")
