import pandas as pd
import numpy as np
import os

from src import config
from src.config import logger


def load_data(filepath=config.CICIDS_PATH, sample_size=None):
    """
    Loads the primary CICIDS2017 dataset.
    If the file doesn't exist, generates a synthetic mockup dataset for prototyping.
    """
    if filepath.exists():
        logger.info(f"Loading real dataset from {filepath}...")
        df = pd.read_csv(filepath)
        if sample_size:
            df = df.sample(n=sample_size, random_state=42)
            
        # Independent Min-Max Normalization (Domain Adaptation)
        num_features = config.get_numeric_features()
        for col in num_features:
            if col in df.columns:
                col_min = df[col].min()
                col_max = df[col].max()
                if col_max > col_min:
                    df[col] = (df[col] - col_min) / (col_max - col_min)
                else:
                    df[col] = 0.0
        
        return df
    else:
        logger.warning(f"Warning: {filepath} not found. Attempting to run merge_data.py pipeline to generate it...")
        try:
            from src.merge_data import merge_and_sample_dataset
            merge_and_sample_dataset()
            # Try loading again after merging
            if filepath.exists():
                return load_data(filepath, sample_size)
            else:
                raise FileNotFoundError("merge_data.py completed, but the output file was not found.")
        except Exception as e:
            logger.error(f"CRITICAL ERROR: Failed to merge data automatically. ({e})")
            logger.warning("Falling back to synthetic mock data for prototyping...")
            return _generate_mock_data(n_samples=sample_size or 5000)

def load_unsw_nb15(filepath=config.DATA_DIR / "UNSW_NB15_testing-set.csv"):
    """
    Loads the UNSW-NB15 dataset for cross-dataset evaluation.
    Includes a feature mapping layer to translate UNSW features to CICIDS equivalents.
    """
    if filepath.exists():
        logger.info(f"Loading UNSW-NB15 dataset from {filepath}...")
        df = pd.read_csv(filepath)
        
        # Feature Mapping Layer (Addressing Instructor Critique #4)
        mapping = {
            'dport': 'Destination Port',
            'dur': 'Flow Duration',
            'sbytes': 'Total Length of Fwd Packets',
            'dbytes': 'Total Length of Bwd Packets',
            'spkts': 'Total Fwd Packets',
            'dpkts': 'Total Backward Packets',
            'smean': 'Fwd Packet Length Mean',
            'dmean': 'Bwd Packet Length Mean',
            'label': config.TARGET_COLUMN  # Synchronize label name
        }
        
        # Compute Rate-based features for UNSW-NB15
        # (Using a small epsilon to avoid division by zero)
        dur_raw = df['dur'].replace(0, 0.000001) 
        df['Flow Packets/s'] = df['rate']
        df['Flow Bytes/s'] = (df['sbytes'] + df['dbytes']) / dur_raw
        df['Fwd Packets/s'] = df['spkts'] / dur_raw
        df['Bwd Packets/s'] = df['dpkts'] / dur_raw

        # Rename available columns
        df = df.rename(columns=mapping)

        # Independent Min-Max Normalization (Domain Adaptation)
        # This aligns the features by mapping the range of each dataset to [0, 1].
        # Trees handle [0, 1] input extremely well and it eliminates the 20x speed gap.
        for col in config.NUMERIC_FEATURES:
            if col in df.columns:
                col_min = df[col].min()
                col_max = df[col].max()
                if col_max > col_min:
                    df[col] = (df[col] - col_min) / (col_max - col_min)
                else:
                    df[col] = 0.0
        
        # Cross-dataset adaptation: Synchronize with Common Denominator set
        missing_cols = [col for col in config.NUMERIC_FEATURES if col not in df.columns]
        if missing_cols:
            # If still missing even after mapping, we fallback to 0 but only for these 8
            logger.warning(f"UNSW-NB15 adaptation: {len(missing_cols)} features still missing, using 0.0")
            for col in missing_cols:
                df[col] = 0.0
        
        # Ensure ONLY the common features are returned (and in the correct order)
        df = df[config.NUMERIC_FEATURES + [config.TARGET_COLUMN]]
        
        logger.info(f"✓ UNSW-NB15 successfully adapted to robust {len(config.NUMERIC_FEATURES)} feature model")
        generate_dataset_statistics(df, "UNSW-NB15 (Mapped)")
        return df
    else:
        logger.warning(f"Warning: {filepath} not found. Evaluation will be skipped.")
        return None

def validate_schema(df):
    """
    Validates that the dataset conforms to the expected CSV format.
    Ensures all NUMERIC_FEATURES and the TARGET_COLUMN are present.
    """
    missing_cols = [col for col in config.NUMERIC_FEATURES if col not in df.columns]
    
    if config.TARGET_COLUMN not in df.columns:
        raise ValueError(f"CRITICAL SCHEMA ERROR: Target column '{config.TARGET_COLUMN}' is missing.")
        
    if missing_cols:
        logger.warning(f"SCHEMA WARNING: Missing {len(missing_cols)} expected features (e.g., {missing_cols[:3]}).")
        logger.warning("Model performance may be degraded if features don't match training data exactly.")
        return False
        
    logger.info("Schema Validation: PASSED ✅")
    return True

def generate_dataset_statistics(df, dataset_name="Dataset"):
    """
    Generates and prints key statistics about the dataset, 
    useful for identifying severe class imbalances before training.
    """
    attack_count = len(df[df[config.TARGET_COLUMN] != config.BENIGN_LABEL])
    benign_count = len(df[df[config.TARGET_COLUMN] == config.BENIGN_LABEL])
    total = len(df)
    
    stats = {
        "Total Rows": total,
        "Total Columns": len(df.columns),
        "Missing Values (NaN)": df.isnull().sum().sum(),
        "Attack Flows": f"{attack_count} ({attack_count/total*100:.2f}%)",
        "Benign Flows": f"{benign_count} ({benign_count/total*100:.2f}%)"
    }
    
    logger.info(f"\n=== {dataset_name} Statistics ===")
    for key, val in stats.items():
        logger.info(f"{key}: {val}")
    logger.info("=================================\n")
    return stats

def _generate_mock_data(n_samples=5000):
    """
    Generates synthetic data matching the structure of CICIDS2017 for early prototyping.
    """
    np.random.seed(42)
    df = pd.DataFrame()
    
    for col in config.NUMERIC_FEATURES:
        df[col] = np.random.normal(loc=100, scale=50, size=n_samples)
    
    labels = [config.BENIGN_LABEL] * int(n_samples * 0.99) + ['Attack'] * int(n_samples * 0.01)
    np.random.shuffle(labels)
    df[config.TARGET_COLUMN] = labels
    
    attack_indices = df[df[config.TARGET_COLUMN] == 'Attack'].index
    df.loc[attack_indices, "Destination Port"] = 22 # SSH
    df.loc[attack_indices, "Flow Duration"] = np.random.uniform(0, 10, size=len(attack_indices))
    
    return df

def preprocess_data(df):
    """
    Preprocesses the data: handling missing values, encoding labels.
    """
    # Drop rows with NaN or infinite values
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    
    X = df[config.NUMERIC_FEATURES]
    y = (df[config.TARGET_COLUMN] != config.BENIGN_LABEL).astype(int)
    
    return X, y

if __name__ == "__main__":
    df = load_data()
