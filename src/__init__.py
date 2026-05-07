# SHAP-Explained Agentic Intrusion Detection System (IDS)
# A hybrid security system combining ML detection with agentic reasoning

__version__ = "1.0.0-alpha"
__author__ = "Muhammad Umar Farooq"
__course__ = "AI-374 Information Security"
__description__ = "IDS using Random Forest + SHAP + LangGraph Agent for explainable threat detection"

# Core modules
from . import config
from . import data_loader

__all__ = ["config", "data_loader", "__version__"]
