"""
src/data_loader.py

Standardized data loading and preprocessing layer for the IDS project.
Handles dataset loading, synthetic data generation, and feature normalization.
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import pandas as pd
import numpy as np

from src import config

logger = logging.getLogger(__name__)


def load_data(filepath: Path = config.CICIDS_PATH, sample_size: Optional[int] = None, normalize: bool = False) -> pd.DataFrame:
    """
    Loads the primary CICIDS2017 dataset with optional stratified sampling.
    If the file doesn't exist, it attempts to trigger the merge pipeline.
    
    Args:
        filepath: Path to the CSV dataset.
        sample_size: Number of samples to load (useful for rapid testing).
        
    Returns:
        pd.DataFrame: The loaded and normalized dataset.
    """
    if filepath.exists():
        logger.info(f"Loading dataset from {filepath}...")
        df = pd.read_csv(filepath)
        if sample_size:
            df = df.sample(n=sample_size, random_state=42)
            
        # Independent Min-Max Normalization (Domain Adaptation) - Now Optional
        if normalize:
            num_features = config.get_numeric_features()
            for col in num_features:
                if col in df.columns:
                    col_min = df[col].min()
                    col_max = df[col].max()
                    if col_max > col_min:
                        df.loc[:, col] = (df[col] - col_min) / (col_max - col_min)
                    else:
                        df.loc[:, col] = 0.0
        
        return df
    else:
        logger.warning(f"Dataset {filepath} not found. Triggering merge pipeline...")
        try:
            from src.merge_data import merge_and_sample_dataset
            merge_and_sample_dataset()
            if filepath.exists():
                return load_data(filepath, sample_size)
            else:
                raise FileNotFoundError("Merge pipeline completed but output missing.")
        except Exception as e:
            logger.error(f"Failed to merge data: {e}")
            logger.warning("Falling back to synthetic mock data.")
            return _generate_mock_data(n_samples=sample_size or 5000)


def load_unsw_nb15(filepath: Path = config.DATA_DIR / "UNSW_NB15_testing-set.csv", normalize: bool = False) -> Optional[pd.DataFrame]:
    """
    Loads the UNSW-NB15 dataset and adapts it to the CICIDS feature schema.
    
    Args:
        filepath: Path to the UNSW-NB15 test CSV.
        
    Returns:
        Optional[pd.DataFrame]: Adapted dataset or None if file missing.
    """
    if not filepath.exists():
        logger.warning(f"UNSW-NB15 dataset not found at {filepath}.")
        return None

    logger.info(f"Loading and adapting UNSW-NB15 from {filepath}...")
    df = pd.read_csv(filepath)
    
    # Feature Mapping Layer
    mapping = {
        'dport': 'Destination Port',
        'dur': 'Flow Duration',
        'sbytes': 'Total Length of Fwd Packets',
        'dbytes': 'Total Length of Bwd Packets',
        'spkts': 'Total Fwd Packets',
        'dpkts': 'Total Backward Packets',
        'smean': 'Fwd Packet Length Mean',
        'dmean': 'Bwd Packet Length Mean',
        'label': config.TARGET_COLUMN
    }
    
    # Feature Engineering for Synchronization
    dur_raw = df['dur'].replace(0, 0.000001) 
    df['Flow Packets/s'] = df['rate']
    df['Flow Bytes/s'] = (df['sbytes'] + df['dbytes']) / dur_raw
    df['Fwd Packets/s'] = df['spkts'] / dur_raw
    df['Bwd Packets/s'] = df['dpkts'] / dur_raw

    df = df.rename(columns=mapping)

    # Independent Normalization - Now Optional
    if normalize:
        for col in config.NUMERIC_FEATURES:
            if col in df.columns:
                col_min = df[col].min()
                col_max = df[col].max()
                if col_max > col_min:
                    df.loc[:, col] = (df[col] - col_min) / (col_max - col_min)
                else:
                    df.loc[:, col] = 0.0
    
    # Harmonize Schema
    missing_cols = [col for col in config.NUMERIC_FEATURES if col not in df.columns]
    if missing_cols:
        logger.warning(f"Mapping gap: {len(missing_cols)} features missing in UNSW, filling with 0.0")
        for col in missing_cols:
            df[col] = 0.0
    
    df = df[config.NUMERIC_FEATURES + [config.TARGET_COLUMN]]
    return df


def validate_schema(df: pd.DataFrame) -> bool:
    """
    Validates that the dataframe contains all required features for the model.
    """
    missing_cols = [col for col in config.NUMERIC_FEATURES if col not in df.columns]
    
    if config.TARGET_COLUMN not in df.columns:
        logger.error(f"Missing target column: {config.TARGET_COLUMN}")
        return False
        
    if missing_cols:
        logger.warning(f"Schema mismatch: {len(missing_cols)} features missing.")
        return False
        
    return True


def generate_dataset_statistics(df: pd.DataFrame, name: str = "Dataset") -> Dict[str, Any]:
    """
    Computes class balance and health metrics for the dataset.
    """
    total = len(df)
    attack_count = len(df[df[config.TARGET_COLUMN] != config.BENIGN_LABEL])
    benign_count = total - attack_count
    
    stats = {
        "Total Rows": total,
        "Attack Count": attack_count,
        "Benign Count": benign_count,
        "Attack Ratio": f"{attack_count/total*100:.2f}%" if total > 0 else "0%"
    }
    
    logger.info(f"Stats for {name}: {stats}")
    return stats


def preprocess_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Prepares data for ML training by handling NaNs and splitting X/y.
    """
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    X = df[config.NUMERIC_FEATURES]
    y = (df[config.TARGET_COLUMN] != config.BENIGN_LABEL).astype(int)
    return X, y


def _generate_mock_data(n_samples: int = 5000) -> pd.DataFrame:
    """Internal helper to generate synthetic data for prototyping."""
    np.random.seed(42)
    df = pd.DataFrame()
    for col in config.NUMERIC_FEATURES:
        df[col] = np.random.normal(loc=100, scale=50, size=n_samples)
    labels = [config.BENIGN_LABEL] * int(n_samples * 0.9) + ['Attack'] * int(n_samples * 0.1)
    np.random.shuffle(labels)
    df[config.TARGET_COLUMN] = labels
    return df


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_df = load_data(sample_size=100)
    print(f"Loaded sample of size: {len(test_df)}")
