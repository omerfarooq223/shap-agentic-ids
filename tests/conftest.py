"""
Pytest configuration and fixtures for testing suite.
Provides shared test data and mock objects.
"""

import pytest
import sys
from unittest.mock import MagicMock

# --- SHIELD: Prevent broken langgraph installation from failing test collection ---
try:
    import langgraph.graph
except (ImportError, NameError):
    # Mocking langgraph modules to allow tests to run on the rest of the stack
    mock_lg = MagicMock()
    sys.modules["langgraph"] = mock_lg
    sys.modules["langgraph.graph"] = mock_lg
    sys.modules["langgraph.prebuilt"] = mock_lg

# Mock flask_limiter if missing
try:
    import flask_limiter
except ImportError:
    # Transparent decorator logic for Flask-Limiter
    class MockLimiter:
        def __init__(self, *args, **kwargs): pass
        def limit(self, *args, **kwargs):
            return lambda f: f
    
    mock_lib = MagicMock()
    mock_lib.Limiter = MockLimiter
    sys.modules["flask_limiter"] = mock_lib
    sys.modules["flask_limiter.util"] = MagicMock()
# ----------------------------------------------------------------------------------

import numpy as np
import pandas as pd
from pathlib import Path
from unittest.mock import MagicMock, patch


@pytest.fixture(scope="session")
def flask_client():
    """
    Create a fully isolated Flask test client available to all tests.
    All service singletons are mocked so no real models are needed.
    """
    from src import config
    # Ensure src.app is loaded so patching works
    import src.app
    
    with patch("src.agent.Groq") as MockGroq:
        MockGroq.return_value = MagicMock()

        # Patch the inference service singleton to avoid loading model files
        with patch("src.services.inference.inference_service") as mock_infer, \
             patch("src.services.geo_service.get_geo_location") as mock_geo, \
             patch("src.services.persistence.alert_repo") as mock_repo, \
             patch("src.app.build_agent") as mock_build_agent:

            # Configure inference service mock (v2: robust and overridable)
            mock_infer.is_ready = True
            mock_infer.predict_proba.return_value = 0.15 # Default benign
            
            def mock_explain_logic(features, top_n=5):
                return [
                    {"feature": "Destination Port", "value": str(features.get("Destination Port", 0)),
                     "contribution": 0.45, "absolute_contribution": 0.45},
                    {"feature": "Flow Duration", "value": "1234",
                     "contribution": 0.1, "absolute_contribution": 0.1}
                ]
            mock_infer.explain.side_effect = mock_explain_logic

            # Configure geo mock
            mock_geo.return_value = {
                "lat": 31.52, "lon": 74.36, "country": "Local Network", "city": "Lahore"
            }

            # Configure persistence mock
            mock_repo.get_all.return_value = []
            mock_repo.push.return_value = None
            mock_repo.load.return_value = None

            # Configure agent mock
            mock_agent = MagicMock()
            mock_agent.analyze.return_value = {
                "hypothesized_threat": "Port-Scan",
                "observation_context": "Rapid port probing detected.",
                "llm_confidence": 0.87,
                "threat_intel": {
                    "abuse_score": 45,
                    "intel_source": "AbuseIPDB (Live)",
                    "intel_status": "success",
                    "zero_day_potential": False,
                    "mitre_mapping": "T1046",
                },
                "risk_score": 8.5,
                "recommendation": "WARNING: Monitor and rate-limit flow.",
                "observation": "Observing flow",
                "_conflict_detected": False,
                "error": "",
            }
            mock_build_agent.return_value = mock_agent

            # Import app AFTER mocks are in place
            from src.app import app
            import src.app as app_module
            app_module.inference_service = mock_infer
            app_module._agent = mock_agent
            app_module.alert_repo = mock_repo

            app.config["TESTING"] = True
            with app.test_client() as client:
                yield client, mock_infer, mock_agent, mock_geo, mock_repo


@pytest.fixture(scope="session")
def project_root():
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def data_dir(project_root):
    """Return the data directory path."""
    return project_root / "data"


@pytest.fixture(scope="session")
def models_dir(project_root):
    """Return the models directory path."""
    return project_root / "models"


@pytest.fixture(scope="session")
def dataset_dir():
    """Return the UNSW-NB15 dataset directory. Skip if not present."""
    path = Path(__file__).parent.parent / "data" / "UNSW_NB15"
    if not path.exists():
        pytest.skip(f"UNSW-NB15 dataset not found at {path}. Cross-dataset tests will be skipped.")
    return path


@pytest.fixture
def sample_cicids_flow():
    """
    Return a complete sample CICIDS2017 flow with all required features.
    Dynamically generates values for all NUMERIC_FEATURES to ensure consistency.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from src import config
    
    # Create flow with all numeric features from config
    flow = {}
    for feature in config.NUMERIC_FEATURES:
        # Generate realistic values - mostly low with some variation
        flow[feature] = np.random.normal(loc=100, scale=50)
    
    # Add required string fields
    flow['src_ip'] = '192.168.1.100'
    flow['dst_ip'] = '192.168.1.50'
    flow['dst_port'] = 80
    
    return flow


@pytest.fixture
def sample_unsw_flow():
    """Return a sample UNSW-NB15 flow."""
    return {
        "srcip": "192.168.1.1",
        "sport": 1234,
        "dstip": "192.168.1.100",
        "dsport": 80,
        "proto": 6,  # TCP
        "state": "CON",
        "dur": 1.5,
        "sbytes": 500,
        "dbytes": 1000,
        "sttl": 64,
        "dttl": 64,
        "sloss": 0,
        "dloss": 0,
        "service": "http",
        "Sload": 100.0,
        "Dload": 200.0,
        "Spkts": 10,
        "Dpkts": 15,
        "swin": 65535,
        "dwin": 65535,
        "stcpb": 1000000,
        "dtcpb": 2000000,
        "smeansz": 50,
        "dmeansz": 67,
        "trans_depth": 1,
        "res_bdy_len": 5000,
        "Sjit": 0.1,
        "Djit": 0.2,
        "Sintpkt": 100.0,
        "Dintpkt": 75.0,
        "tcprtt": 10.0,
        "synack": 5.0,
        "ackdat": 5.0,
        "is_sm_ips_ports": 0,
        "ct_state_ttl": 1,
        "ct_flw_http_mthd": 1,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_srv_src": 2,
        "ct_srv_dst": 3,
        "ct_dst_ltm": 5,
        "ct_src_ltm": 4,
        "ct_src_dport_ltm": 2,
        "ct_dst_sport_ltm": 3,
        "ct_dst_src_ltm": 1,
        "attack_cat": "Normal",
        "Label": 0,
    }


@pytest.fixture
def sample_benign_flows():
    """Return multiple sample benign flows."""
    flows = []
    for i in range(10):
        flow = {
            "src_ip": f"192.168.1.{100 + i}",
            "dst_ip": f"192.168.1.{50 + i}",
            "dst_port": 80 + i,
            "Flow Duration": 1000.0 + i * 100,
            "Total Fwd Packets": 10.0 + i,
            "Total Backward Packets": 8.0 + i,
            "Total Length of Fwd Packets": 500.0 + i * 50,
            "Total Length of Bwd Packets": 400.0 + i * 50,
            "Fwd Packet Length Max": 100.0 + i * 10,
            "Fwd Packet Length Min": 20.0 + i,
            "Fwd Packet Length Mean": 50.0 + i * 5,
            "Fwd Packet Length Std": 25.0 + i * 2,
            "Bwd Packet Length Max": 90.0 + i * 10,
            "Bwd Packet Length Min": 30.0 + i,
            "Bwd Packet Length Mean": 50.0 + i * 5,
            "Bwd Packet Length Std": 20.0 + i * 2,
            "Flow Bytes/s": 900.0 + i * 100,
            "Flow Packets/s": 18.0 + i,
            "Flow IAT Mean": 50.0 + i * 5,
            "Flow IAT Std": 10.0 + i,
            "Flow IAT Max": 100.0 + i * 10,
            "Flow IAT Min": 10.0 + i,
            "Fwd IAT Total": 90.0 + i * 10,
            "Fwd IAT Mean": 10.0 + i,
            "Fwd IAT Std": 5.0 + i,
            "Fwd IAT Max": 20.0 + i * 2,
            "Fwd IAT Min": 1.0 + i * 0.1,
            "Bwd IAT Total": 70.0 + i * 10,
            "Bwd IAT Mean": 10.0 + i,
            "Bwd IAT Std": 4.0 + i,
            "Bwd IAT Max": 18.0 + i * 2,
            "Bwd IAT Min": 2.0 + i * 0.1,
            "Fwd PSH Flags": 1.0,
            "Bwd PSH Flags": 1.0,
            "Fwd URG Flags": 0.0,
            "Bwd URG Flags": 0.0,
            "Fwd Header Length": 320.0,
            "Bwd Header Length": 320.0,
            "Fwd Packets/s": 10.0 + i,
            "Bwd Packets/s": 8.0 + i,
            "Min Packet Length": 20.0 + i,
            "Max Packet Length": 100.0 + i * 10,
            "Packet Length Mean": 56.0 + i * 5,
            "Packet Length Std": 25.0 + i * 2,
            "Packet Length Variance": 625.0 + i * 50,
            "FIN Flag Count": 1.0,
            "SYN Flag Count": 1.0,
            "RST Flag Count": 0.0,
            "PSH Flag Count": 2.0,
            "ACK Flag Count": 15.0 + i,
            "URG Flag Count": 0.0,
            "CWE Flag Count": 0.0,
            "ECE Flag Count": 0.0,
            "Down/Up Ratio": 0.8 + i * 0.02,
            "Average Packet Size": 56.0 + i * 5,
            "Avg Fwd Segment Size": 50.0 + i * 5,
            "Avg Bwd Segment Size": 50.0 + i * 5,
            "Fwd Header Length.1": 320.0,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": 10.0 + i,
            "Subflow Fwd Bytes": 500.0 + i * 50,
            "Subflow Bwd Packets": 8.0 + i,
            "Subflow Bwd Bytes": 400.0 + i * 50,
            "Init_Win_bytes_forward": 65535.0,
            "Init_Win_bytes_backward": 65535.0,
            "act_data_pkt_fwd": 8.0 + i,
            "min_seg_size_forward": 20.0 + i,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }
        flows.append(flow)
    return flows


@pytest.fixture
def sample_attack_flows():
    """Return multiple sample attack flows."""
    flows = []
    attack_types = [
        {"dur": 0.001, "Flow Packets/s": 1000.0, "Total Fwd Packets": 500.0},  # DDoS
        {"dur": 5.0, "Flow Bytes/s": 50.0, "Total Fwd Packets": 3.0},  # Port Scan
        {"Flow IAT Min": 0.001, "Flow IAT Mean": 0.01},  # Brute Force
    ]
    
    for i, attack in enumerate(attack_types):
        for j in range(3):
            flow = {
                "src_ip": f"203.0.113.{100 + i * 10 + j}",
                "dst_ip": f"192.168.1.{50 + i}",
                "dst_port": 22 + i,
                "Flow Duration": attack.get("dur", 1000.0),
                "Total Fwd Packets": attack.get("Total Fwd Packets", 10.0),
                "Total Backward Packets": 1.0 + j,
                "Total Length of Fwd Packets": 50000.0 + i * 10000,
                "Total Length of Bwd Packets": 100.0,
                "Fwd Packet Length Max": 1500.0,
                "Fwd Packet Length Min": 40.0,
                "Fwd Packet Length Mean": 500.0,
                "Fwd Packet Length Std": 400.0,
                "Bwd Packet Length Max": 100.0,
                "Bwd Packet Length Min": 20.0,
                "Bwd Packet Length Mean": 50.0,
                "Bwd Packet Length Std": 30.0,
                "Flow Bytes/s": attack.get("Flow Bytes/s", 900.0),
                "Flow Packets/s": attack.get("Flow Packets/s", 18.0),
                "Flow IAT Mean": attack.get("Flow IAT Mean", 50.0),
                "Flow IAT Std": 0.001,
                "Flow IAT Max": 1.0,
                "Flow IAT Min": attack.get("Flow IAT Min", 10.0),
                "Fwd IAT Total": 1.0,
                "Fwd IAT Mean": 0.1,
                "Fwd IAT Std": 0.05,
                "Fwd IAT Max": 1.0,
                "Fwd IAT Min": 0.01,
                "Bwd IAT Total": 1.0,
                "Bwd IAT Mean": 1.0,
                "Bwd IAT Std": 0.0,
                "Bwd IAT Max": 1.0,
                "Bwd IAT Min": 1.0,
                "Fwd PSH Flags": 0.0,
                "Bwd PSH Flags": 0.0,
                "Fwd URG Flags": 0.0,
                "Bwd URG Flags": 0.0,
                "Fwd Header Length": 320.0,
                "Bwd Header Length": 60.0,
                "Fwd Packets/s": 500.0,
                "Bwd Packets/s": 0.5,
                "Min Packet Length": 40.0,
                "Max Packet Length": 1500.0,
                "Packet Length Mean": 750.0,
                "Packet Length Std": 600.0,
                "Packet Length Variance": 360000.0,
                "FIN Flag Count": 0.0,
                "SYN Flag Count": 100.0,
                "RST Flag Count": 10.0,
                "PSH Flag Count": 0.0,
                "ACK Flag Count": 1.0,
                "URG Flag Count": 0.0,
                "CWE Flag Count": 0.0,
                "ECE Flag Count": 0.0,
                "Down/Up Ratio": 0.01,
                "Average Packet Size": 750.0,
                "Avg Fwd Segment Size": 500.0,
                "Avg Bwd Segment Size": 50.0,
                "Fwd Header Length.1": 320.0,
                "Fwd Avg Bytes/Bulk": 0.0,
                "Fwd Avg Packets/Bulk": 0.0,
                "Fwd Avg Bulk Rate": 0.0,
                "Bwd Avg Bytes/Bulk": 0.0,
                "Bwd Avg Packets/Bulk": 0.0,
                "Bwd Avg Bulk Rate": 0.0,
                "Subflow Fwd Packets": attack.get("Total Fwd Packets", 10.0),
                "Subflow Fwd Bytes": 50000.0,
                "Subflow Bwd Packets": 1.0,
                "Subflow Bwd Bytes": 100.0,
                "Init_Win_bytes_forward": 65535.0,
                "Init_Win_bytes_backward": 65535.0,
                "act_data_pkt_fwd": 5.0,
                "min_seg_size_forward": 32.0,
                "Active Mean": 0.0,
                "Active Std": 0.0,
                "Active Max": 0.0,
                "Active Min": 0.0,
                "Idle Mean": 0.0,
                "Idle Std": 0.0,
                "Idle Max": 0.0,
                "Idle Min": 0.0,
            }
            flows.append(flow)
    return flows
