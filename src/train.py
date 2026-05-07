import pandas as pd
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import numpy as np
import joblib
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    precision_score, recall_score, f1_score, roc_auc_score
)
import shap

from src import config
from src.data_loader import load_data, preprocess_data

def train_model():
    logger.info("=" * 80)
    logger.info("TRAINING PIPELINE: Random Forest + SMOTE + SHAP")
    logger.info("=" * 80)
    
    logger.info("\n[1/6] Loading data...")
    df = load_data()
    X, y = preprocess_data(df)
    logger.info(f"✓ Loaded {len(X)} samples with {X.shape[1]} features")
    logger.info(f"  Label distribution: {pd.Series(y).value_counts().to_dict()}")
    
    logger.info("\n[2/6] Train-test split (80:20 stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    logger.info(f"✓ Train: {len(X_train)} samples | Test: {len(X_test)} samples")
    
    logger.info("\n[3/6] Feature scaling (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    logger.info(f"✓ Scaled features to mean≈0, std≈1")
    
    logger.info("\n[4/6] SMOTE class balancing (sampling_strategy=0.25)...")
    # Using conservative 0.25 strategy to avoid over-synthetic data
    smote = SMOTE(sampling_strategy=0.25, random_state=42)
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)
    logger.info(f"✓ Balanced training set: {len(X_train_balanced)} samples")
    logger.info(f"  Balanced distribution: {pd.Series(y_train_balanced).value_counts().to_dict()}")
    
    logger.info("\n[5/6] Training Random Forest Classifier...")
    # Hyperparameters from Sharafaldin et al. (2017) IDS benchmarks
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train_balanced, y_train_balanced)
    logger.info(f"✓ Trained 100-tree Random Forest")
    
    logger.info("\n[6/6] Evaluation & Metrics...")
    y_pred = rf.predict(X_test_scaled)
    y_proba = rf.predict_proba(X_test_scaled)[:, 1]
    
    # Compute all metrics
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    tpr = tp / (tp + fn)
    fpr = fp / (fp + tn)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc_roc = roc_auc_score(y_test, y_proba) if len(np.unique(y_test)) > 1 else 0.0
    
    # Log metrics in structured format
    logger.info("\n" + "="*50)
    logger.info("MODEL PERFORMANCE METRICS")
    logger.info("="*50)
    logger.info(f"TPR (Sensitivity):     {tpr:.4f}  (Target: >0.90)")
    logger.info(f"FPR:                   {fpr:.4f}  (Target: <0.05)")
    logger.info(f"Precision:             {precision:.4f}  (Target: >0.85)")
    logger.info(f"Recall:                {recall:.4f}")
    logger.info(f"F1-Score:              {f1:.4f}  (Target: >0.88)")
    logger.info(f"AUC-ROC:               {auc_roc:.4f}  (Target: >0.95)")
    logger.info("="*50)
    
    logger.info("\nDetailed Classification Report:")
    logger.info(classification_report(y_test, y_pred))
    
    logger.info("\nConfusion Matrix:")
    cm_str = f"  TN={tn}, FP={fp}\n  FN={fn}, TP={tp}"
    logger.info(cm_str)
    
    logger.info("\nSaving model and scaler...")
    # Check if model directory is writable
    if not os.access(config.MODEL_DIR, os.W_OK):
        logger.error(f"Model directory {config.MODEL_DIR} is not writable!")
        raise PermissionError(f"Cannot write to {config.MODEL_DIR}")
    
    joblib.dump(rf, config.RF_MODEL_PATH)
    joblib.dump(scaler, config.SCALER_PATH)
    logger.info(f"✓ Model saved to {config.RF_MODEL_PATH}")
    logger.info(f"✓ Scaler saved to {config.SCALER_PATH}")
    
    logger.info("\nGenerating SHAP TreeExplainer (interventional mode)...")
    # Use small background sample for efficiency
    background_data = shap.sample(X_train_scaled, min(100, len(X_train_scaled)))
    
    # Create explainer with feature names for interpretability
    explainer = shap.TreeExplainer(
        rf, 
        data=background_data, 
        feature_names=config.NUMERIC_FEATURES,
        feature_perturbation="interventional"
    )
    logger.info(f"✓ SHAP explainer created with {len(config.NUMERIC_FEATURES)} feature names")
    
    # Save explainer for later use in app.py
    explainer_path = config.MODEL_DIR / "shap_explainer.pkl"
    joblib.dump(explainer, explainer_path)
    logger.info(f"✓ SHAP explainer saved to {explainer_path}")
    
    # Test on a few anomalies
    anomaly_samples = X_test_scaled[y_pred == 1][:5]
    if len(anomaly_samples) > 0:
        shap_values = explainer.shap_values(anomaly_samples)
        logger.info(f"✓ SHAP values computed for {len(anomaly_samples)} anomaly samples")
    else:
        logger.warning("No anomalies detected in test set - SHAP not tested")
    
    logger.info("\n" + "="*80)
    logger.info("✓ TRAINING PIPELINE COMPLETE")
    logger.info("="*80)
    logger.info(f"Ready for deployment! Models saved in {config.MODEL_DIR}")

if __name__ == "__main__":
    train_model()

if __name__ == "__main__":
    train_model()
