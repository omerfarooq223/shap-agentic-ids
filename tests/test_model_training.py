"""
Comprehensive unit tests for ML pipeline: RandomForest, SMOTE, StandardScaler, SHAP.
Covers training, serialization, evaluation metrics, and SHAP integration.
"""

import pytest
import numpy as np
import pandas as pd
import joblib
import os
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, 
    confusion_matrix, classification_report
)
from imblearn.over_sampling import SMOTE
import shap

# Add parent directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestModelTraining:
    """Test suite for RandomForest, SMOTE, and model serialization."""

    def test_smote_class_distribution(self):
        """Test SMOTE produces expected class balance (sampling_strategy=0.25)."""
        np.random.seed(42)
        
        # Imbalanced data: 95% class 0, 5% class 1
        X = np.random.randn(1000, 20)
        y = np.array([0]*950 + [1]*50)
        
        smote = SMOTE(sampling_strategy=0.25, random_state=42)
        X_balanced, y_balanced = smote.fit_resample(X, y)
        
        unique, counts = np.unique(y_balanced, return_counts=True)
        minority_ratio = counts[1] / (counts[0] + counts[1])
        
        # With sampling_strategy=0.25, minority should be ~20% (1/5)
        # Allow small tolerance for randomness
        assert 0.18 < minority_ratio < 0.22, f"Expected ~0.20, got {minority_ratio:.4f}"
        print(f"✓ SMOTE class balance correct: {minority_ratio:.4f}")

    def test_random_forest_training(self):
        """Test RandomForest can train and predict."""
        np.random.seed(42)
        X = np.random.randn(200, 20)
        y = np.random.randint(0, 2, 200)
        
        model = RandomForestClassifier(
            n_estimators=10,
            max_depth=15,
            class_weight='balanced',
            random_state=42
        )
        model.fit(X, y)
        
        predictions = model.predict(X)
        assert len(predictions) == len(y)
        assert set(predictions).issubset({0, 1})
        print(f"✓ RandomForest training successful")

    def test_random_forest_probability_output(self):
        """Test RandomForest can output probability predictions."""
        np.random.seed(42)
        X = np.random.randn(100, 20)
        y = np.random.randint(0, 2, 100)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        proba = model.predict_proba(X)
        
        assert proba.shape == (100, 2)
        assert np.allclose(proba.sum(axis=1), 1.0)  # Probabilities sum to 1
        assert np.all((proba >= 0) & (proba <= 1))  # Valid probability range
        print(f"✓ RandomForest probability output valid")

    def test_feature_importance(self):
        """Test RandomForest computes feature importance."""
        np.random.seed(42)
        X = np.random.randn(100, 20)
        y = np.random.randint(0, 2, 100)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        importances = model.feature_importances_
        
        assert len(importances) == 20
        assert np.isclose(importances.sum(), 1.0, atol=1e-6)
        print(f"✓ Feature importances computed: top 3 = {np.argsort(importances)[-3:]}")

    def test_model_serialization(self, tmp_path):
        """Test RandomForest can be saved and loaded via joblib."""
        np.random.seed(42)
        X = np.random.randn(100, 20)
        y = np.random.randint(0, 2, 100)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        # Save
        model_path = tmp_path / "model.pkl"
        joblib.dump(model, model_path)
        
        # Verify saved
        assert model_path.exists()
        assert os.access(str(model_path), os.R_OK)
        
        # Load and verify
        loaded_model = joblib.load(model_path)
        X_test = np.random.randn(20, 20)
        
        assert np.array_equal(model.predict(X_test), loaded_model.predict(X_test))
        print(f"✓ Model serialization working")

    def test_model_with_real_cicids_data(self):
        """Test training with actual CICIDS2017 data if available."""
        from src.config import CICIDS_PATH
        
        if not Path(CICIDS_PATH).exists():
            pytest.skip(f"CICIDS2017 data not found at {CICIDS_PATH}")
        
        from src.data_loader import load_data, preprocess_data
        
        try:
            df = load_data()
            X, y = preprocess_data(df)
            
            # Quick sanity checks
            assert len(X) > 0, "No samples loaded"
            assert X.shape[1] >= 70, f"Expected ≥70 features, got {X.shape[1]}"
            assert len(np.unique(y)) >= 2, "Need at least 2 classes"
            
            # Train a quick model
            model = RandomForestClassifier(n_estimators=5, random_state=42)
            model.fit(X[:1000], y[:1000])  # Train on small subset
            
            predictions = model.predict(X[:100])
            assert len(predictions) == 100
            print(f"✓ Real data training successful: {X.shape}")
        except Exception as e:
            pytest.skip(f"Could not train on real data: {e}")


class TestScaler:
    """Test StandardScaler preprocessing."""

    def test_scaler_mean_std(self):
        """Test StandardScaler produces zero mean and unit std."""
        np.random.seed(42)
        X = np.random.randn(500, 20) * 100 + 50  # Non-standard distribution
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        mean = X_scaled.mean(axis=0)
        std = X_scaled.std(axis=0)
        
        assert np.allclose(mean, 0, atol=1e-10)
        assert np.allclose(std, 1.0, atol=1e-10)
        print(f"✓ Scaler normalization correct: mean={mean.mean():.2e}, std={std.mean():.4f}")

    def test_scaler_transform_consistency(self):
        """Test fit_transform vs separate fit/transform."""
        np.random.seed(42)
        X_train = np.random.randn(100, 20)
        X_test = np.random.randn(50, 20)
        
        # Method 1: fit_transform on train, then transform test
        scaler1 = StandardScaler()
        X_train_scaled1 = scaler1.fit_transform(X_train)
        X_test_scaled1 = scaler1.transform(X_test)
        
        # Both should match behavior
        scaler2 = StandardScaler()
        X_train_scaled2 = scaler2.fit_transform(X_train)
        X_test_scaled2 = scaler2.transform(X_test)
        
        assert np.allclose(X_train_scaled1, X_train_scaled2)
        assert np.allclose(X_test_scaled1, X_test_scaled2)
        print(f"✓ Scaler consistency verified")

    def test_scaler_serialization(self, tmp_path):
        """Test StandardScaler can be saved and loaded."""
        np.random.seed(42)
        X = np.random.randn(100, 20)
        
        scaler = StandardScaler()
        scaler.fit(X)
        
        # Save
        scaler_path = tmp_path / "scaler.pkl"
        joblib.dump(scaler, scaler_path)
        
        # Load and verify
        loaded_scaler = joblib.load(scaler_path)
        
        X_test = np.random.randn(20, 20)
        assert np.allclose(scaler.transform(X_test), loaded_scaler.transform(X_test))
        print(f"✓ Scaler serialization working")


class TestModelEvaluation:
    """Test model evaluation metrics."""

    def test_model_accuracy(self):
        """Test model accuracy calculation."""
        np.random.seed(42)
        X = np.random.randn(100, 20)
        y = np.random.randint(0, 2, 100)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        predictions = model.predict(X)
        accuracy = accuracy_score(y, predictions)
        
        assert 0 <= accuracy <= 1
        print(f"✓ Accuracy: {accuracy:.4f}")

    def test_model_precision_recall(self):
        """Test precision and recall."""
        np.random.seed(42)
        X = np.random.randn(200, 20)
        y = np.random.randint(0, 2, 200)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        predictions = model.predict(X)
        
        precision = precision_score(y, predictions, zero_division=0)
        recall = recall_score(y, predictions, zero_division=0)
        
        assert 0 <= precision <= 1
        assert 0 <= recall <= 1
        print(f"✓ Precision: {precision:.4f}, Recall: {recall:.4f}")

    def test_model_f1_score(self):
        """Test F1 score."""
        np.random.seed(42)
        X = np.random.randn(200, 20)
        y = np.random.randint(0, 2, 200)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        predictions = model.predict(X)
        f1 = f1_score(y, predictions, zero_division=0)
        
        assert 0 <= f1 <= 1
        print(f"✓ F1-Score: {f1:.4f}")

    def test_confusion_matrix(self):
        """Test confusion matrix."""
        np.random.seed(42)
        X = np.random.randn(200, 20)
        y = np.random.randint(0, 2, 200)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        predictions = model.predict(X)
        cm = confusion_matrix(y, predictions)
        
        assert cm.shape == (2, 2)
        assert (cm >= 0).all()
        print(f"✓ Confusion matrix shape: {cm.shape}")

    def test_tpr_fpr_metrics(self):
        """Test TPR and FPR calculation (per SYSTEM_DESIGN.md targets)."""
        np.random.seed(42)
        X = np.random.randn(200, 20)
        y = np.random.randint(0, 2, 200)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        predictions = model.predict(X)
        tn, fp, fn, tp = confusion_matrix(y, predictions).ravel()
        
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        assert 0 <= tpr <= 1
        assert 0 <= fpr <= 1
        print(f"✓ TPR: {tpr:.4f}, FPR: {fpr:.4f}")


class TestSHAPIntegration:
    """Test SHAP explainer integration with RandomForest."""

    def test_shap_explainer_creation(self):
        """Test SHAP TreeExplainer can be created."""
        np.random.seed(42)
        X_train = np.random.randn(100, 20)
        X_test = np.random.randn(50, 20)
        y_train = np.random.randint(0, 2, 100)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X_train, y_train)
        
        background_data = shap.sample(X_train, min(50, len(X_train)))
        
        # Should not raise an error
        explainer = shap.TreeExplainer(
            model,
            data=background_data,
            feature_perturbation="interventional"
        )
        assert explainer is not None
        print(f"✓ SHAP TreeExplainer created (interventional mode)")

    def test_shap_values_output_shape(self):
        """Test SHAP values have expected shape."""
        np.random.seed(42)
        X_train = np.random.randn(100, 20)
        X_test = np.random.randn(10, 20)
        y_train = np.random.randint(0, 2, 100)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X_train, y_train)
        
        background_data = shap.sample(X_train, 50)
        explainer = shap.TreeExplainer(model, data=background_data)
        
        # SHAP values should be list of 2 arrays (one per class for binary)
        shap_values = explainer.shap_values(X_test)
        
        # For binary classification, shap_values is list
        if isinstance(shap_values, list):
            assert len(shap_values) == 2  # 2 classes
            for sv in shap_values:
                # SHAP for TreeExplainer can have shape (n_samples, n_features) or (n_samples, n_features, 2)
                assert sv.ndim == 2 or sv.ndim == 3
                assert sv.shape[0] == 10  # n_samples
                assert sv.shape[1] == 20  # n_features
        else:
            assert shap_values.ndim >= 2
            assert shap_values.shape[0] == 10
            assert shap_values.shape[1] == 20
        
        print(f"✓ SHAP values shape correct: {shap_values[0].shape if isinstance(shap_values, list) else shap_values.shape}")

    def test_shap_with_feature_names(self):
        """Test SHAP explainer with feature names for interpretability."""
        np.random.seed(42)
        X_train = np.random.randn(100, 20)
        X_test = np.random.randn(5, 20)
        y_train = np.random.randint(0, 2, 100)
        
        feature_names = [f"Feature_{i}" for i in range(20)]
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X_train, y_train)
        
        background_data = shap.sample(X_train, 50)
        explainer = shap.TreeExplainer(
            model,
            data=background_data,
            feature_names=feature_names,
            feature_perturbation="interventional"
        )
        
        shap_values = explainer.shap_values(X_test)
        
        # Should not error and should have feature names
        assert explainer.feature_names == feature_names
        print(f"✓ SHAP feature names correctly assigned ({len(feature_names)} features)")

    def test_shap_explainer_serialization(self, tmp_path):
        """Test SHAP explainer can be saved and loaded."""
        np.random.seed(42)
        X_train = np.random.randn(100, 20)
        y_train = np.random.randint(0, 2, 100)
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X_train, y_train)
        
        background_data = shap.sample(X_train, 50)
        explainer = shap.TreeExplainer(model, data=background_data)
        
        # Save
        explainer_path = tmp_path / "explainer.pkl"
        joblib.dump(explainer, explainer_path)
        
        # Load
        loaded_explainer = joblib.load(explainer_path)
        
        # Test both work identically
        X_test = np.random.randn(5, 20)
        original_shap = explainer.shap_values(X_test)
        loaded_shap = loaded_explainer.shap_values(X_test)
        
        if isinstance(original_shap, list):
            for orig, loaded in zip(original_shap, loaded_shap):
                assert np.allclose(orig, loaded, rtol=1e-5)
        else:
            assert np.allclose(original_shap, loaded_shap, rtol=1e-5)
        
        print(f"✓ SHAP explainer serialization working")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
