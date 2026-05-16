"""
src/train.py

Random Forest training pipeline with class balancing (SMOTE) and 
SHAP explainability serialization.
"""

from __future__ import annotations

import os
import logging
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    precision_score, recall_score, f1_score, roc_auc_score
)
from sklearn.preprocessing import MinMaxScaler
import shap

from src import config
from src.data_loader import load_data, preprocess_data

logger = logging.getLogger(__name__)


def train_model() -> None:
    """
    Executes the full model training lifecycle:
    1. Data ingestion & preprocessing
    2. Stratified train/val/test splitting
    3. SMOTE-based class balancing
    4. Random Forest training
    5. Evaluation & SHAP serialization
    """
    logger.info("Starting IDS Training Pipeline...")
    
    # 1. Data Ingestion
    df = load_data()
    X, y = preprocess_data(df)
    
    # 2. Stratified Splitting (60/20/20)
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, stratify=y_temp, random_state=42
    )
    
    logger.info(f"Split completed: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")
    
    # 3. Scaling
    logger.info("Initializing MinMaxScaler...")
    scaler = MinMaxScaler()
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns)
    X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=X_val.columns)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)
    
    # 4. SMOTE Balancing (On Scaled Data)
    logger.info(f"Applying SMOTE (strategy={config.SMOTE_STRATEGY})...")
    smote = SMOTE(sampling_strategy=config.SMOTE_STRATEGY, random_state=42)
    X_train_bal, y_train_bal = smote.fit_resample(X_train_scaled, y_train)
    
    # 5. Training
    logger.info("Fitting Random Forest (n_estimators=100)...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train_bal, y_train_bal)
    
    # 6. Evaluation
    _evaluate_model(rf, X_test_scaled, y_test)
    
    # 7. Serialization
    _save_artifacts(rf, scaler)


def _evaluate_model(model: RandomForestClassifier, X_test: pd.DataFrame, y_test: pd.Series) -> None:
    """Computes and logs comprehensive performance metrics."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_proba)
    
    logger.info("=== Final Model Performance ===")
    logger.info(f"F1-Score: {f1:.4f}")
    logger.info(f"AUC-ROC:  {auc:.4f}")
    logger.info("\nClassification Report:\n" + classification_report(y_test, y_pred))


def _save_artifacts(model: RandomForestClassifier, scaler: MinMaxScaler) -> None:
    """Saves the trained model and initializes/saves the SHAP explainer."""
    # Ensure model directory exists
    os.makedirs(config.MODEL_DIR, exist_ok=True)
    
    # Save Model
    joblib.dump(model, config.RF_MODEL_PATH)
    logger.info(f"Model serialized to {config.RF_MODEL_PATH}")
    
    # Save Scaler
    joblib.dump(scaler, config.SCALER_PATH)
    logger.info(f"Scaler serialized to {config.SCALER_PATH}")
    
    # Serialize SHAP Explainer
    logger.info("Initializing SHAP TreeExplainer...")
    # Use a small background sample for faster inference in production
    # but still enough for interventional consistency.
    explainer = shap.TreeExplainer(
        model, 
        feature_names=config.NUMERIC_FEATURES,
        feature_perturbation="interventional"
    )
    joblib.dump(explainer, config.SHAP_EXPL_PATH)
    logger.info(f"SHAP explainer serialized to {config.SHAP_EXPL_PATH}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_model()
