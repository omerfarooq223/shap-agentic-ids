import os
import sys
import logging
import pandas as pd
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Project Roots
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Central Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / "system.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# API Key Validation
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not GROQ_API_KEY or GROQ_API_KEY == "your_groq_api_key_here":
    logger.warning("GROQ_API_KEY is not set or invalid in .env file. Agentic reasoning will fail.")
    
if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_abuseipdb_api_key_here":
    logger.warning("ABUSEIPDB_API_KEY is not set or invalid in .env file. IP Verification will fail.")

# Dataset Paths
CICIDS_PATH = DATA_DIR / "CICIDS2017.csv"

# Model Paths
RF_MODEL_PATH = MODEL_DIR / "rf_model.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"

TARGET_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"

# Dynamic Feature Detection
def get_numeric_features():
    """
    Auto-detects numerical features from the CSV header to ensure model consistency.
    Falls back to a hardcoded list if the dataset is not yet downloaded or processed.
    Validates feature count to prevent silent data corruption.
    """
    if CICIDS_PATH.exists():
        try:
            # Read only the first row to get headers (extremely fast)
            df = pd.read_csv(CICIDS_PATH, nrows=1)
            # Filter out the target column
            cols = [col for col in df.columns if col != TARGET_COLUMN]
            
            # Validate feature count - CICIDS2017 should have ~79-80 features
            expected_feature_count = 79
            if len(cols) < expected_feature_count * 0.9:  # Allow 10% variance
                logger.warning(
                    f"WARNING: Expected ~{expected_feature_count} features, "
                    f"but found only {len(cols)}. Dataset may be incomplete."
                )
            
            logger.info(f"Auto-detected {len(cols)} numeric features from CICIDS2017 CSV header")
            return cols
        except Exception as e:
            logger.error(f"Error reading features from CSV: {e}")
            
    # Fallback hardcoded features
    return [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
        "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
        "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
        "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
        "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
        "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
        "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
        "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
        "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
        "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
        "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
        "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
    ]

NUMERIC_FEATURES = get_numeric_features()
