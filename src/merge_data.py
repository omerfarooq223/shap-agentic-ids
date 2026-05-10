import os
import glob
import pandas as pd
import numpy as np

from src.config import logger

def merge_and_sample_dataset():
    # Use relative paths for portability (Addressing Instructor Critique #1)
    from src import config
    archive_dir = config.DATA_DIR / "archive"
    output_path = config.CICIDS_PATH
    
    if not archive_dir.exists():
        logger.error(f"Archive directory {archive_dir} not found. Please place raw CSVs in data/archive/")
        return

    csv_files = glob.glob(os.path.join(str(archive_dir), "*.csv"))
    if not csv_files:
        logger.error("No CSV files found in the archive directory.")
        return

    logger.info(f"Found {len(csv_files)} CSV files. Merging and processing...")
    
    df_list = []
    for file in csv_files:
        logger.info(f"Reading {os.path.basename(file)}...")
        try:
            # low_memory=False to prevent dtype warnings
            df = pd.read_csv(file, low_memory=False)
            
            # Strip whitespace from column names
            df.columns = df.columns.str.strip()
            
            # Check if Label column exists (required for sampling)
            if 'Label' not in df.columns:
                logger.error(f"File {os.path.basename(file)} missing 'Label' column. Skipping.")
                continue
            
            # Drop rows with NaN or infinite values
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            initial_rows = len(df)
            df.dropna(inplace=True)
            dropped = initial_rows - len(df)
            if dropped > 0:
                logger.info(f"  Dropped {dropped} rows with NaN/inf values")
            
            df_list.append(df)
        except Exception as e:
            logger.error(f"Error reading {file}: {e}")
            
    if not df_list:
        logger.error("No data was successfully read.")
        return
        
    logger.info("Concatenating all data...")
    full_df = pd.concat(df_list, ignore_index=True)
    
    logger.info(f"Total rows before sampling: {len(full_df)}")
    
    # Do a 10% stratified sample to keep training fast
    # Stratify by Label to ensure we keep minority classes
    from sklearn.model_selection import train_test_split
    
    # Try stratified sampling; fallback to random if classes too rare
    try:
        _, sample_df = train_test_split(
            full_df, 
            test_size=0.10, 
            stratify=full_df['Label'], 
            random_state=42
        )
        logger.info("✓ Stratified sampling applied (preserved label distribution)")
    except ValueError as e:
        logger.warning(f"Stratified sampling failed: {e}")
        logger.warning("Falling back to random sampling...")
        sample_df = full_df.sample(frac=0.10, random_state=42)
        
    logger.info(f"Total rows after sampling: {len(sample_df)} (10% of original)")
    logger.info(f"Label distribution in sampled data:")
    label_counts = sample_df['Label'].value_counts()
    for label, count in label_counts.items():
        pct = (count / len(sample_df)) * 100
        logger.info(f"  {label}: {count} ({pct:.2f}%)")
    
    logger.info(f"Saving sampled dataset to {output_path}...")
    sample_df.to_csv(output_path, index=False)
    logger.info("✓ Merge and sample complete!")

if __name__ == "__main__":
    merge_and_sample_dataset()
