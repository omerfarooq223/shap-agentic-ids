# Dataset Setup Guide

This guide covers the steps I've taken to set up the datasets for this project, focusing on the primary CICIDS2017 dataset and the cross-evaluation UNSW-NB15 dataset.

## 1. Primary Dataset: CICIDS2017

The ML model is primarily trained on the CICIDS2017 dataset.

**Automated Setup:**
1. Download the raw CSV files from the official source or Kaggle.
2. Place them in a folder (e.g., `~/Downloads/archive/`).
3. Run `src/merge_data.py`. This script will merge, clean, and stratify a 10% sample into `data/CICIDS2017.csv`.
4. The `src/data_loader.py` will automatically detect and load this file.

## 2. Cross-Evaluation Dataset: UNSW-NB15

To prove the Random Forest model has learned generalizable network anomaly features rather than just memorizing the CICIDS2017 dataset, we use the UNSW-NB15 dataset for out-of-distribution evaluation and per-attack-class reporting.

**Setup Instructions:**
1. **Download**: Obtain `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` from the official [UNSW Canberra Cyber page](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
2. **Placement**: Save both files in `data/`.
3. **Run evaluation**:
   ```bash
   python scripts/run_evaluation.py
   ```
4. **Generated outputs**:
   - `docs/BASELINE_EFFICIENCY_COMPARISON.md`
   - `docs/baseline_efficiency_results.json`

The evaluation script compares Logistic Regression, GaussianNB, MultinomialNB, ComplementNB, Decision Tree, Random Forest, and optional XGBoost. It also computes Random Forest per-attack-class precision, recall, F1, and support for CICIDS2017 labels and UNSW-NB15 `attack_cat` families.

## Troubleshooting Missing Data

If you see `Warning: CICIDS2017.csv not found` and `merge_data.py` fails:
- Ensure the path to your raw archive in `src/merge_data.py` is absolutely correct.
- If no data is available on the machine, the system will fall back to `_generate_mock_data()` so you can still test the Flask API and LangGraph Agentic pipeline logic without needing an 800MB download.
