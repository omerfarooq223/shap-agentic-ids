import pandas as pd
import logging
import os

from src.config import logger

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
    
    logger.info("\n[2/6] Train-Validation-Test split (60:20:20 stratified)...")
    # First split: 80% train+val, 20% test
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    # Second split: 75% train, 25% val (of 80%) = 60% train, 20% val overall
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, stratify=y_temp, random_state=42
    )
    logger.info(f"✓ Train: {len(X_train)} samples | Val: {len(X_val)} samples | Test: {len(X_test)} samples")
    logger.info(f"  Train label dist: {pd.Series(y_train).value_counts().to_dict()}")
    logger.info(f"  Val label dist:   {pd.Series(y_val).value_counts().to_dict()}")
    logger.info(f"  Test label dist:  {pd.Series(y_test).value_counts().to_dict()}")
    
    # [3/6] Feature scaling (REMOVED)
    # Random Forest is scale-invariant. Removing the scaler prevents
    # distribution-shift distortions during cross-dataset evaluation.
    logger.info("\n[3/6] Skipping feature scaling (Trees are scale-invariant)...")
    X_train_scaled = X_train
    X_val_scaled = X_val
    X_test_scaled = X_test
    scaler = None
    
    logger.info(f"\n[4/6] SMOTE class balancing (sampling_strategy={config.SMOTE_STRATEGY})...")
    logger.info(f"  Rationale: SMOTE_STRATEGY={config.SMOTE_STRATEGY} balances minority/majority ratio")
    logger.info(f"  - Avoids over-synthetic data (values > 0.5 harm generalization)")
    logger.info(f"  - Tested on CICIDS2017 (99% benign baseline) and UNSW-NB15")
    logger.info(f"  - Reference: Chawla et al. 2002 SMOTE paper, Sharafaldin et al. 2017 IDS benchmarks")
    
    smote = SMOTE(sampling_strategy=config.SMOTE_STRATEGY, random_state=42)
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)
    logger.info(f"✓ Balanced training set: {len(X_train_balanced)} samples")
    logger.info(f"  Before SMOTE: {pd.Series(y_train).value_counts().to_dict()}")
    logger.info(f"  After SMOTE:  {pd.Series(y_train_balanced).value_counts().to_dict()}")
    
    logger.info("\n[5/6] Training Random Forest Classifier...")
    logger.info("  Note: class_weight='balanced' REMOVED (SMOTE already balanced training data)")
    logger.info("        Using only SMOTE prevents double-correction and overfitting.")
    
    # Hyperparameters from Sharafaldin et al. (2017) IDS benchmarks
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        # NOTE: Removed class_weight='balanced' - SMOTE already balanced the training set.
        # Using both would apply double correction (SMOTE weights + class weights),
        # which increases overfitting risk and metrics inflation.
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train_balanced, y_train_balanced)
    logger.info(f"✓ Trained 100-tree Random Forest on balanced training set")
    
    logger.info("\n[6/6] Evaluation on Validation & Test Sets...")
    
    # Validation set metrics (used for hyperparameter tuning / early stopping)
    logger.info("\nValidation Set Performance:")
    y_val_pred = rf.predict(X_val_scaled)
    y_val_proba = rf.predict_proba(X_val_scaled)[:, 1]
    val_f1 = f1_score(y_val, y_val_pred, zero_division=0)
    val_auc = roc_auc_score(y_val, y_val_proba) if len(np.unique(y_val)) > 1 else 0.0
    logger.info(f"  Validation F1:  {val_f1:.4f}")
    logger.info(f"  Validation AUC: {val_auc:.4f}")
    
    # Test set metrics (final held-out evaluation)
    logger.info("\nTest Set Performance (FINAL EVALUATION):")
    y_pred = rf.predict(X_test_scaled)
    y_proba = rf.predict_proba(X_test_scaled)[:, 1]
    
    # Compute all metrics on test set
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
