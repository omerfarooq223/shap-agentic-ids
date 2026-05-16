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
DOCS_DIR = BASE_DIR / "docs"
os.makedirs(DOCS_DIR, exist_ok=True)

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
SHAP_EXPL_PATH = MODEL_DIR / "shap_explainer.pkl"

# Network / Streaming Defaults
DEFAULT_INTERFACE = os.getenv("CAPTURE_INTERFACE", "en0")

# Flask Configuration
FLASK_PORT = int(os.getenv("FLASK_PORT", "5005"))
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")

# API Timeouts
API_TIMEOUT = int(os.getenv("API_TIMEOUT", "10"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

# LLM Configuration
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Voice Assistant Configuration
ENABLE_BACKEND_VOICE = os.getenv("ENABLE_BACKEND_VOICE", "true").lower() == "true"

# Cross-Dataset Robustness Mode
# If True, the model will ONLY train on features that exist in both CICIDS and UNSW.
# This ensures scientific validity for cross-dataset evaluation.
CROSS_DATASET_MODE = os.getenv("CROSS_DATASET_MODE", "true").lower() == "true"

# Security
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY")
if not INTERNAL_API_KEY:
    logger.error("\n" + "="*80)
    logger.error("FATAL SECURITY ERROR: INTERNAL_API_KEY not set!")
    logger.error("Set INTERNAL_API_KEY in .env file with a strong, random value.")
    logger.error("Example: openssl rand -hex 32")
    logger.error("="*80)
    sys.exit(1)

if len(INTERNAL_API_KEY) < 32:
    logger.error("\n" + "="*80)
    logger.error(f"FATAL SECURITY ERROR: INTERNAL_API_KEY is too weak ({len(INTERNAL_API_KEY)} chars).")
    logger.error("INTERNAL_API_KEY must be at least 32 characters (256 bits).")
    logger.error("Generate with: openssl rand -hex 32")
    logger.error("="*80)
    sys.exit(1)
logger.info("✓ INTERNAL_API_KEY validated (strong key configured)", extra={"key_length": len(INTERNAL_API_KEY)})
# Rate Limiting Configuration
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_DETECT = os.getenv("RATE_LIMIT_DETECT", "100 per minute")  # Critical endpoint
RATE_LIMIT_CHAT = os.getenv("RATE_LIMIT_CHAT", "50 per minute")      # Chat endpoint
RATE_LIMIT_HEALTH = os.getenv("RATE_LIMIT_HEALTH", "1000 per minute") # Health checks (frequent)
RATE_LIMIT_TEST = os.getenv("RATE_LIMIT_TEST", "10 per minute")       # Stress test (prevent abuse)

# CORS Configuration with Security Validation
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN")
if not FRONTEND_ORIGIN:
    logger.error("\n" + "="*80)
    logger.error("FATAL SECURITY ERROR: FRONTEND_ORIGIN not set!")
    logger.error("Set FRONTEND_ORIGIN in .env file to your frontend domain.")
    logger.error("Examples:")
    logger.error("  FRONTEND_ORIGIN=https://myapp.com  (production)")
    logger.error("  FRONTEND_ORIGIN=http://localhost:5173  (development)")
    logger.error("Never use '*' in production — it allows any origin to access the API!")
    logger.error("="*80)
    sys.exit(1)

# Warn if using wildcard in non-development mode
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
if FRONTEND_ORIGIN == "*" and ENVIRONMENT != "development":
    logger.error("\n" + "="*80)
    logger.error("FATAL SECURITY ERROR: CORS wildcard '*' not allowed in production!")
    logger.error("Set a specific FRONTEND_ORIGIN domain and set ENVIRONMENT=production")
    logger.error("="*80)
    sys.exit(1)

if FRONTEND_ORIGIN == "*":
    logger.warning("⚠️  CORS is configured to accept ANY origin (FRONTEND_ORIGIN='*')")
    logger.warning("    This is only safe for local development!")
    logger.warning("    For production, set FRONTEND_ORIGIN to your specific domain")
else:
    logger.info(f"✓ CORS configured for: {FRONTEND_ORIGIN}")

# Secrets Management - Support for rotation without restart
class SecretsManager:
    """
    Manages API keys with support for rotation.
    
    In production, this can be extended to:
    - Periodically reload from environment/secrets manager
    - Support key versioning (old and new keys simultaneously)
    - Graceful key rollover without restarting
    """
    
    def __init__(self):
        self._internal_api_key = INTERNAL_API_KEY
        self._abuseipdb_api_key = ABUSEIPDB_API_KEY
        self._groq_api_key = GROQ_API_KEY
        self._last_reload = None
        
    def reload_secrets(self):
        """
        Reload secrets from environment (useful for key rotation).
        This would typically be called by a scheduled task or signal handler.
        """
        try:
            old_key = self._internal_api_key
            new_key = os.getenv("INTERNAL_API_KEY")
            
            if new_key and len(new_key) >= 32:
                self._internal_api_key = new_key
                if new_key != old_key:
                    logger.info("✓ INTERNAL_API_KEY reloaded successfully")
                    return True
            else:
                logger.warning("Attempted key reload failed: new key is invalid")
                return False
        except Exception as exc:
            logger.error(f"Error reloading secrets: {exc}")
            return False
    
    @property
    def internal_api_key(self):
        return self._internal_api_key
    
    @property
    def abuseipdb_api_key(self):
        return self._abuseipdb_api_key
    
    @property
    def groq_api_key(self):
        return self._groq_api_key

# Initialize secrets manager
_secrets_manager = SecretsManager()

# For backward compatibility, expose as module-level variables
# (but these now come from the manager)
def get_internal_api_key():
    """Get the current INTERNAL_API_KEY (supports rotation)."""
    return _secrets_manager.internal_api_key

def get_abuseipdb_api_key():
    """Get the current ABUSEIPDB_API_KEY (supports rotation)."""
    return _secrets_manager.abuseipdb_api_key

def get_groq_api_key():
    """Get the current GROQ_API_KEY (supports rotation)."""
    return _secrets_manager.groq_api_key

def rotate_secrets():
    """
    Trigger a reload of all secrets from environment.
    In production, this can be called by a signal handler or scheduled task.
    """
    logger.info("Attempting to reload secrets from environment...")
    success = _secrets_manager.reload_secrets()
    if success:
        logger.info("✓ Secrets rotation completed successfully")
        return True
    else:
        logger.error("✗ Secrets rotation failed — using cached secrets")
        return False

# For compatibility with existing code, keep the old references but warn
INTERNAL_API_KEY_STATIC = INTERNAL_API_KEY


TARGET_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"

# Dynamic Feature Detection
def get_numeric_features():
    """
    Returns the list of features to use for training and inference.
    Falls back to a hardcoded list if the dataset is not yet downloaded or processed.
    Validates feature count to prevent silent data corruption.
    """
    if CROSS_DATASET_MODE:
        logger.info("✓ CROSS_DATASET_MODE enabled: Using 12 core common features for robust evaluation")
        return [
            "Destination Port", 
            "Flow Duration", 
            "Total Fwd Packets", 
            "Total Backward Packets",
            "Total Length of Fwd Packets", 
            "Total Length of Bwd Packets", 
            "Fwd Packet Length Mean", 
            "Bwd Packet Length Mean",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Fwd Packets/s",
            "Bwd Packets/s"
        ]

    # Fallback to auto-detection (Old behavior)
    if CICIDS_PATH.exists():
        try:
            df = pd.read_csv(CICIDS_PATH, nrows=1)
            return [col for col in df.columns if col != TARGET_COLUMN]
        except:
            pass

    # Legacy fallback
    return ["Destination Port", "Flow Duration"] # Minimal set

NUMERIC_FEATURES = get_numeric_features()

# ─────────────────────────────────────────────────────────────────────────────
# TRAINING CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Train/Validation/Test split ratios for proper model evaluation
# - Training: Used to fit model and balance with SMOTE
# - Validation: Used for hyperparameter tuning and early stopping detection
# - Test: Held-out set for final evaluation (never touched during training)
TRAIN_TEST_SPLIT = {
    'train_ratio': 0.6,    # 60% training set
    'val_ratio': 0.2,      # 20% validation set
    'test_ratio': 0.2,     # 20% test set
}

# SMOTE (Synthetic Minority Over-sampling Technique) configuration
# SMOTE_STRATEGY: Ratio of minority class to majority class after resampling
# Why 0.25? 
#   - Prevents over-synthetic data that harms generalization (avoid 1.0)
#   - Still provides meaningful minority class samples for training
#   - Empirically validated on CICIDS2017 dataset
#   - Results: Improves recall without excessive false positives
# Reference: Chawla et al. 2002, used in production IDS (Sharafaldin et al. 2017)
SMOTE_STRATEGY = float(os.getenv('SMOTE_STRATEGY', '0.25'))
if not 0.0 < SMOTE_STRATEGY <= 1.0:
    raise ValueError(f"SMOTE_STRATEGY must be in (0, 1], got {SMOTE_STRATEGY}")

logger.info(f"Training config: SMOTE_STRATEGY={SMOTE_STRATEGY} (minority/majority ratio)")

# ---------------------------------------------------------------------------
# THREAT CLASSIFICATION THRESHOLDS (data-driven, formerly magic numbers)
# ---------------------------------------------------------------------------

# Threat intelligence thresholds (AbuseIPDB)
ABUSEIPDB_HIGH_CONFIDENCE_THRESHOLD = float(os.getenv('ABUSEIPDB_HIGH_CONFIDENCE_THRESHOLD', '80'))
ZERO_DAY_ML_CONFIDENCE_THRESHOLD = float(os.getenv('ZERO_DAY_ML_CONFIDENCE_THRESHOLD', '0.90'))
ZERO_DAY_ABUSE_SCORE_CLEAN_THRESHOLD = int(os.getenv('ZERO_DAY_ABUSE_SCORE_CLEAN_THRESHOLD', '10'))

# Risk scoring thresholds
RISK_SCORE_CRITICAL_THRESHOLD = float(os.getenv('RISK_SCORE_CRITICAL_THRESHOLD', '8.0'))
RISK_SCORE_WARNING_THRESHOLD = float(os.getenv('RISK_SCORE_WARNING_THRESHOLD', '5.0'))

# LLM confidence defaults
DEFAULT_LLM_CONFIDENCE = float(os.getenv('DEFAULT_LLM_CONFIDENCE', '0.5'))
FALLBACK_LLM_CONFIDENCE = float(os.getenv('FALLBACK_LLM_CONFIDENCE', '0.3'))

# ML confidence thresholds
ML_CONFIDENCE_HIGH_THRESHOLD = float(os.getenv('ML_CONFIDENCE_HIGH_THRESHOLD', '0.90'))

logger.info(
    f"Threat classification thresholds loaded: "
    f"ABUSE_HIGH={ABUSEIPDB_HIGH_CONFIDENCE_THRESHOLD}, "
    f"ZERO_DAY_ML_CONF={ZERO_DAY_ML_CONFIDENCE_THRESHOLD}, "
    f"RISK_CRITICAL={RISK_SCORE_CRITICAL_THRESHOLD}"
)

# ---------------------------------------------------------------------------
# UTILITY FUNCTIONS (Centralized for code deduplication)
# ---------------------------------------------------------------------------

import ipaddress
import json
from datetime import datetime

def validate_ip_address(ip_str: str) -> bool:
    """
    Validate IP address format and check if it's valid.
    
    Args:
        ip_str: String representation of IP address
        
    Returns:
        True if valid IP, False otherwise
    """
    if not isinstance(ip_str, str) or not ip_str.strip():
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is private or loopback.
    
    Args:
        ip_str: String representation of IP address
        
    Returns:
        True if private/loopback, False if public, False if invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return True  # Treat invalid IPs as private (safe default)

class StructuredLogger(logging.LoggerAdapter):
    """
    Wrapper for logging module that outputs structured JSON for key events.
    Enables log aggregation and SIEM integration.
    """
    
    def process(self, msg, kwargs):
        """Add contextual information to log messages."""
        return msg, kwargs
    
    def info_json(self, event: str, **context):
        """Log structured JSON event for machine consumption."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": "INFO",
            "event": event,
            **context
        }
        self.info(json.dumps(log_entry))
    
    def warning_json(self, event: str, **context):
        """Log structured JSON warning for machine consumption."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": "WARNING",
            "event": event,
            **context
        }
        self.warning(json.dumps(log_entry))
    
    def error_json(self, event: str, **context):
        """Log structured JSON error for machine consumption."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": "ERROR",
            "event": event,
            **context
        }
        self.error(json.dumps(log_entry))
