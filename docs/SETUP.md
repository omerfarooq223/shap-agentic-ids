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

To prove the Random Forest model has learned generalizable network anomaly features rather than just memorizing the CICIDS2017 dataset, we use the UNSW-NB15 dataset for out-of-distribution evaluation.

**Setup Instructions:**
1. **Download**: Obtain the UNSW-NB15 dataset (specifically the `UNSW_NB15_testing-set.csv` or `UNSW_NB15_training-set.csv`) from the official [UNSW Canberra Cyber page](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
2. **Placement**: Save the downloaded CSV file as `UNSW_NB15.csv` in the `data/` directory of this project (`data/UNSW_NB15.csv`).
3. **Feature Mapping (Critical Step)**:
   UNSW-NB15 uses different column names and structures than CICIDS2017 (e.g., `sbytes` instead of `Total Length of Fwd Packets`).
   Before running the evaluation script, you must map the UNSW-NB15 columns to match the 78 `NUMERIC_FEATURES` defined in `src/config.py`.
   - *Note: A preprocessing script `src/hybrid_ids_comparison.py` handles this mapping before feeding it to `data_loader.load_unsw_nb15()`.*
4. **Validation**: Run the pipeline. `data_loader.py` will automatically trigger `validate_schema()` to ensure your mapped UNSW-NB15 dataset exactly matches the expected inference format.

## Troubleshooting Missing Data

If you see `Warning: CICIDS2017.csv not found` and `merge_data.py` fails:
- Ensure the path to your raw archive in `src/merge_data.py` is absolutely correct.
- If no data is available on the machine, the system will fall back to `_generate_mock_data()` so you can still test the Flask API and LangGraph Agentic pipeline logic without needing an 800MB download.
