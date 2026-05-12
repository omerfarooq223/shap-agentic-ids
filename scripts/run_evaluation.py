#!/usr/bin/env python3
"""
Cross-Dataset Evaluation: Within-Dataset vs Between-Dataset Performance
Since CICIDS2017 and UNSW-NB15 have completely different features,
we evaluate model performance within each dataset separately.
"""

import pandas as pd
import numpy as np
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

print("="*90)
print("MULTI-DATASET EVALUATION: CICIDS2017 vs UNSW-NB15")
print("="*90)

# ============================================================================
# CICIDS2017 EVALUATION
# ============================================================================

print("\n[1/4] CICIDS2017 DATASET EVALUATION")
print("-" * 90)

print("  Loading CICIDS2017...")
cicids = pd.read_csv("data/CICIDS2017.csv")
print(f"  ✓ Loaded: {cicids.shape[0]:,} samples, {cicids.shape[1]} features")

# Prepare CICIDS2017
cicids_label = (cicids['Label'].astype(str).str.lower() != 'benign').astype(int)
print(f"  ✓ Label distribution: {dict(cicids_label.value_counts())}")

X_cicids = cicids.drop(['Label'], axis=1)
numeric_cols_cicids = X_cicids.select_dtypes(include=[np.number]).columns
X_cicids = X_cicids[numeric_cols_cicids]

# Sample for speed
sample_size = min(30000, len(X_cicids))
X_cicids_sample = X_cicids.sample(n=sample_size, random_state=42)
y_cicids_sample = cicids_label[X_cicids_sample.index]

print(f"  ✓ Using {sample_size:,} samples for training")
print(f"  ✓ Features (numeric): {X_cicids_sample.shape[1]}")

# Split data
X_cicids_train, X_cicids_test, y_cicids_train, y_cicids_test = train_test_split(
    X_cicids_sample, y_cicids_sample, test_size=0.2, random_state=42, stratify=y_cicids_sample
)

print(f"  ✓ Train set: {X_cicids_train.shape[0]:,} samples")
print(f"  ✓ Test set:  {X_cicids_test.shape[0]:,} samples")

# Train model
print("  Training Random Forest (n_estimators=100)...")
model_cicids = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, verbose=0)
model_cicids.fit(X_cicids_train, y_cicids_train)
print("  ✓ Model trained")

# Test on CICIDS2017
y_cicids_pred = model_cicids.predict(X_cicids_test)
y_cicids_proba = model_cicids.predict_proba(X_cicids_test)[:, 1]

cicids_acc = accuracy_score(y_cicids_test, y_cicids_pred)
cicids_prec = precision_score(y_cicids_test, y_cicids_pred, zero_division=0)
cicids_rec = recall_score(y_cicids_test, y_cicids_pred, zero_division=0)
cicids_f1 = f1_score(y_cicids_test, y_cicids_pred, zero_division=0)
cicids_auc = roc_auc_score(y_cicids_test, y_cicids_proba)

tn_c, fp_c, fn_c, tp_c = confusion_matrix(y_cicids_test, y_cicids_pred).ravel()
cicids_tpr = tp_c / (tp_c + fn_c) if (tp_c + fn_c) > 0 else 0
cicids_fpr = fp_c / (fp_c + tn_c) if (fp_c + tn_c) > 0 else 0

print("\n  ✓ CICIDS2017 Test Results:")
print(f"    • Accuracy:   {cicids_acc:.4f} ({cicids_acc*100:.2f}%)")
print(f"    • Precision:  {cicids_prec:.4f}")
print(f"    • Recall:     {cicids_rec:.4f}")
print(f"    • F1-Score:   {cicids_f1:.4f}")
print(f"    • ROC-AUC:    {cicids_auc:.4f}")
print(f"    • TPR:        {cicids_tpr:.4f} (Detects {cicids_tpr*100:.1f}% of attacks)")
print(f"    • FPR:        {cicids_fpr:.4f} (False alarms: {cicids_fpr*100:.1f}%)")

# ============================================================================
# UNSW-NB15 EVALUATION
# ============================================================================

print("\n[2/4] UNSW-NB15 DATASET EVALUATION")
print("-" * 90)

print("  Loading UNSW-NB15 training set...")
unsw_train_path = "data/UNSW_NB15_training-set.csv"
if not os.path.exists(unsw_train_path):
    print(f"  ❌ Error: {unsw_train_path} not found.")
    print("     Please ensure the UNSW-NB15 CSV files are in the data/ directory.")
    exit(1)
unsw_train = pd.read_csv(unsw_train_path)
print(f"  ✓ Loaded: {unsw_train.shape[0]:,} samples")
print(f"  ✓ Label distribution: {dict(unsw_train['label'].value_counts())}")

print("  Loading UNSW-NB15 testing set...")
unsw_test_path = "data/UNSW_NB15_testing-set.csv"
unsw_test = pd.read_csv(unsw_test_path)
print(f"  ✓ Loaded: {unsw_test.shape[0]:,} samples")
print(f"  ✓ Label distribution: {dict(unsw_test['label'].value_counts())}")

# Combine for training
unsw_all = pd.concat([unsw_train, unsw_test], ignore_index=True)

# Prepare UNSW
X_unsw = unsw_all.drop(['id', 'label', 'attack_cat', 'proto', 'service', 'state'], axis=1, errors='ignore')
y_unsw = unsw_all['label']

numeric_cols_unsw = X_unsw.select_dtypes(include=[np.number]).columns
X_unsw = X_unsw[numeric_cols_unsw]

print(f"  ✓ Features (numeric): {X_unsw.shape[1]}")
print(f"  ✓ Total samples available: {X_unsw.shape[0]:,}")

# Split data
X_unsw_train, X_unsw_test, y_unsw_train, y_unsw_test = train_test_split(
    X_unsw, y_unsw, test_size=0.2, random_state=42, stratify=y_unsw
)

print(f"  ✓ Train set: {X_unsw_train.shape[0]:,} samples")
print(f"  ✓ Test set:  {X_unsw_test.shape[0]:,} samples")

# Train model
print("  Training Random Forest (n_estimators=100)...")
model_unsw = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, verbose=0)
model_unsw.fit(X_unsw_train, y_unsw_train)
print("  ✓ Model trained")

# Test on UNSW
y_unsw_pred = model_unsw.predict(X_unsw_test)
y_unsw_proba = model_unsw.predict_proba(X_unsw_test)[:, 1]

unsw_acc = accuracy_score(y_unsw_test, y_unsw_pred)
unsw_prec = precision_score(y_unsw_test, y_unsw_pred, zero_division=0)
unsw_rec = recall_score(y_unsw_test, y_unsw_pred, zero_division=0)
unsw_f1 = f1_score(y_unsw_test, y_unsw_pred, zero_division=0)
unsw_auc = roc_auc_score(y_unsw_test, y_unsw_proba)

tn_u, fp_u, fn_u, tp_u = confusion_matrix(y_unsw_test, y_unsw_pred).ravel()
unsw_tpr = tp_u / (tp_u + fn_u) if (tp_u + fn_u) > 0 else 0
unsw_fpr = fp_u / (fp_u + tn_u) if (fp_u + tn_u) > 0 else 0

print("\n  ✓ UNSW-NB15 Test Results:")
print(f"    • Accuracy:   {unsw_acc:.4f} ({unsw_acc*100:.2f}%)")
print(f"    • Precision:  {unsw_prec:.4f}")
print(f"    • Recall:     {unsw_rec:.4f}")
print(f"    • F1-Score:   {unsw_f1:.4f}")
print(f"    • ROC-AUC:    {unsw_auc:.4f}")
print(f"    • TPR:        {unsw_tpr:.4f} (Detects {unsw_tpr*100:.1f}% of attacks)")
print(f"    • FPR:        {unsw_fpr:.4f} (False alarms: {unsw_fpr*100:.1f}%)")

# ============================================================================
# COMPARISON
# ============================================================================

print("\n[3/4] COMPARISON ANALYSIS")
print("-" * 90)

print("\n  Performance Metrics Comparison:")
print(f"  {'Metric':<15} {'CICIDS2017':<20} {'UNSW-NB15':<20} {'Difference':<20}")
print("  " + "-" * 75)

metrics_comparison = [
    ('Accuracy', cicids_acc, unsw_acc),
    ('Precision', cicids_prec, unsw_prec),
    ('Recall', cicids_rec, unsw_rec),
    ('F1-Score', cicids_f1, unsw_f1),
    ('ROC-AUC', cicids_auc, unsw_auc),
    ('TPR', cicids_tpr, unsw_tpr),
    ('FPR', cicids_fpr, unsw_fpr),
]

for metric, cicids_val, unsw_val in metrics_comparison:
    diff = cicids_val - unsw_val
    diff_str = f"{diff:+.4f} ({diff*100:+.2f}%)"
    print(f"  {metric:<15} {cicids_val:<20.4f} {unsw_val:<20.4f} {diff_str:<20}")

# Feature importance
print("\n[4/4] FEATURE IMPORTANCE ANALYSIS")
print("-" * 90)

print("\n  Top 10 Features in CICIDS2017 Model:")
feature_importance_cicids = pd.DataFrame({
    'feature': X_cicids_sample.columns,
    'importance': model_cicids.feature_importances_
}).sort_values('importance', ascending=False)

for idx, (_, row) in enumerate(feature_importance_cicids.head(10).iterrows(), 1):
    print(f"    {idx:2d}. {row['feature']:<30s} {row['importance']:7.4f}")

print("\n  Top 10 Features in UNSW-NB15 Model:")
feature_importance_unsw = pd.DataFrame({
    'feature': X_unsw.columns,
    'importance': model_unsw.feature_importances_
}).sort_values('importance', ascending=False)

for idx, (_, row) in enumerate(feature_importance_unsw.head(10).iterrows(), 1):
    print(f"    {idx:2d}. {row['feature']:<30s} {row['importance']:7.4f}")

# ============================================================================
# SUMMARY & INTERPRETATION
# ============================================================================

print("\n" + "="*90)
print("SUMMARY & INTERPRETATION")
print("="*90)

print(f"""
KEY FINDINGS:

1. CICIDS2017 MODEL PERFORMANCE:
   • Achieves {cicids_acc*100:.2f}% accuracy on its test set
   • Detects {cicids_tpr*100:.1f}% of attacks (True Positive Rate)
   • {cicids_fpr*100:.1f}% false alarm rate (False Positive Rate)
   • {cicids_f1:.4f} F1-Score indicates {'EXCELLENT' if cicids_f1 > 0.8 else 'GOOD' if cicids_f1 > 0.6 else 'MODERATE'} performance

2. UNSW-NB15 MODEL PERFORMANCE:
   • Achieves {unsw_acc*100:.2f}% accuracy on its test set
   • Detects {unsw_tpr*100:.1f}% of attacks (True Positive Rate)
   • {unsw_fpr*100:.1f}% false alarm rate (False Positive Rate)
   • {unsw_f1:.4f} F1-Score indicates {'EXCELLENT' if unsw_f1 > 0.8 else 'GOOD' if unsw_f1 > 0.6 else 'MODERATE'} performance

3. RELATIVE PERFORMANCE:
   • Accuracy difference: {abs(cicids_acc - unsw_acc)*100:.2f}%
   • Both datasets show {'strong' if max(cicids_f1, unsw_f1) > 0.7 else 'moderate'} intrusion detection capability
   
4. DATASET CHARACTERISTICS:
   • CICIDS2017: {X_cicids_sample.shape[1]} numeric features (network flow metrics)
   • UNSW-NB15: {X_unsw.shape[1]} numeric features (behavioral & network metrics)
   • Different feature sets reflect different data collection methodologies

5. PRACTICAL IMPLICATIONS FOR IDS:
   • Both datasets can effectively train intrusion detection models
   • {'High detection rate indicates good model generalization' if min(cicids_tpr, unsw_tpr) > 0.8 else 'Moderate detection suggests room for improvement'}
   • Model selection should consider the target network environment
""")

print("="*90)
