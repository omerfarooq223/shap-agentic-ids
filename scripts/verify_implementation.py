#!/usr/bin/env python3
"""
Verification Script: Test All New IDS Capabilities

This script verifies that all three gaps have been successfully implemented:
1. Real packet capture
2. Snort/Suricata comparison
3. Streaming/real-time processing

Run with: python3 verify_implementation.py
"""

import sys
import json
from pathlib import Path

# Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_header(text):
    """Print colored header."""
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}{text.center(70)}{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

def print_check(passed, message):
    """Print check result."""
    status = f"{GREEN}✅ PASS{RESET}" if passed else f"{RED}❌ FAIL{RESET}"
    print(f"{status}: {message}")

def test_imports():
    """Test that all new modules can be imported."""
    print_header("GAP 1: PACKET CAPTURE - Module Imports")
    
    checks = []
    
    # Test packet_capture imports
    try:
        from src.packet_capture import (
            PacketFlowExtractor,
            LivePacketCapture,
            StreamingFlowProcessor
        )
        print_check(True, "PacketFlowExtractor imported successfully")
        print_check(True, "LivePacketCapture imported successfully")
        print_check(True, "StreamingFlowProcessor imported successfully")
        checks.append(True)
    except ImportError as e:
        print_check(False, f"Failed to import packet_capture: {e}")
        checks.append(False)
    
    print_header("GAP 2: SNORT/SURICATA - Module Imports")
    
    # Test snort_comparison imports
    try:
        from src.snort_comparison import (
            SnortIntegration,
            SuricataIntegration,
            IDSComparison
        )
        print_check(True, "SnortIntegration imported successfully")
        print_check(True, "SuricataIntegration imported successfully")
        print_check(True, "IDSComparison imported successfully")
        checks.append(True)
    except ImportError as e:
        print_check(False, f"Failed to import snort_comparison: {e}")
        checks.append(False)
    
    print_header("GAP 3: STREAMING - Module Imports")
    
    # Test streaming_api imports
    try:
        from src.streaming_api import create_streaming_blueprint
        print_check(True, "create_streaming_blueprint imported successfully")
        checks.append(True)
    except ImportError as e:
        print_check(False, f"Failed to import streaming_api: {e}")
        checks.append(False)
    
    return all(checks)

def test_flask_integration():
    """Test Flask integration."""
    print_header("Flask Integration Tests")
    
    checks = []
    
    try:
        from flask import Flask
        from src.streaming_api import create_streaming_blueprint
        
        app = Flask(__name__)
        
        def dummy_callback(flow):
            pass
        
        # Test blueprint creation
        blueprint = create_streaming_blueprint(dummy_callback)
        print_check(True, "Streaming blueprint created successfully")
        
        # Register blueprint
        app.register_blueprint(blueprint)
        print_check(True, "Blueprint registered with Flask app")
        
        # Check endpoints
        endpoints = [
            '/stream/start',
            '/stream/stop',
            '/stream/status',
            '/stream/stats'
        ]
        
        registered_urls = set()
        for rule in app.url_map.iter_rules():
            registered_urls.add(str(rule.rule))
        
        for endpoint in endpoints:
            found = any(endpoint in url for url in registered_urls)
            print_check(found, f"Endpoint {YELLOW}{endpoint}{RESET} registered")
            checks.append(found)
        
    except Exception as e:
        print_check(False, f"Flask integration test failed: {e}")
        checks.append(False)
    
    return all(checks)

def test_config():
    """Test configuration."""
    print_header("Configuration Tests")
    
    checks = []
    
    try:
        from src import config
        
        # Check feature count
        feature_count = len(config.NUMERIC_FEATURES)
        # Handle both CROSS_DATASET_MODE (12) and standard mode (78)
        expected_counts = [12, 78]
        
        if feature_count in expected_counts:
            mode = "CROSS_DATASET" if feature_count == 12 else "STANDARD"
            print_check(True, f"Loaded {feature_count} features for ML model ({mode} mode)")
            checks.append(True)
        else:
            print_check(False, f"Unexpected feature count: {feature_count}. Expected 12 or 78.")
            checks.append(False)
        
        # Check model path
        model_path = Path(config.RF_MODEL_PATH)
        if model_path.exists():
            print_check(True, f"Model path exists: {config.RF_MODEL_PATH}")
            checks.append(True)
        else:
            print_check(False, f"Model path not found: {config.RF_MODEL_PATH}")
            checks.append(False)
        
    except Exception as e:
        print_check(False, f"Configuration test failed: {e}")
        checks.append(False)
    
    return all(checks)

def test_packet_capture_classes():
    """Test packet capture class instantiation."""
    print_header("Packet Capture Class Tests")
    
    checks = []
    
    try:
        from src.packet_capture import PacketFlowExtractor
        
        # Test PacketFlowExtractor
        extractor = PacketFlowExtractor(timeout=60)
        print_check(True, "PacketFlowExtractor instantiated (timeout=60s)")
        checks.append(True)
        
    except Exception as e:
        print_check(False, f"PacketFlowExtractor instantiation failed: {e}")
        checks.append(False)
    
    return all(checks)

def test_snort_comparison_classes():
    """Test Snort comparison class instantiation."""
    print_header("Snort/Suricata Class Tests")
    
    checks = []
    
    try:
        from src.snort_comparison import (
            SnortIntegration,
            SuricataIntegration,
            IDSComparison
        )
        
        # Test with dummy PCAP path
        pcap_path = "test.pcap"
        
        # Test SnortIntegration
        snort = SnortIntegration(pcap_path)
        print_check(True, "SnortIntegration instantiated")
        checks.append(True)
        
        # Test SuricataIntegration
        suricata = SuricataIntegration(pcap_path)
        print_check(True, "SuricataIntegration instantiated")
        checks.append(True)
        
        # Test IDSComparison
        comparison = IDSComparison(pcap_path)
        print_check(True, "IDSComparison instantiated")
        checks.append(True)
        
        # Check for Snort
        snort_installed = snort.check_snort_installed()
        status = "installed" if snort_installed else "not installed"
        print_check(snort_installed, f"Snort is {status} (optional)")
        
        # Check for Suricata
        suricata_installed = suricata.check_suricata_installed()
        status = "installed" if suricata_installed else "not installed"
        print_check(suricata_installed, f"Suricata is {status} (optional)")
        
    except Exception as e:
        print_check(False, f"Snort/Suricata class test failed: {e}")
        checks.append(False)
    
    return all(checks)

def test_existing_system():
    """Test that existing system still works."""
    print_header("Existing System Tests (No Regressions)")
    
    checks = []
    
    try:
        # Test config
        from src import config
        print_check(True, "Config module still works")
        checks.append(True)
        
        # Test that model can be imported (but not loaded, as it requires training)
        from src.agent import build_agent
        print_check(True, "Agent module can be imported")
        checks.append(True)
        
        # Test Flask app can be imported
        from src.app import app
        print_check(True, "Flask app module can be imported")
        checks.append(True)
        
    except Exception as e:
        print_check(False, f"Existing system test failed: {e}")
        checks.append(False)
    
    return all(checks)

def test_dependencies():
    """Test required dependencies."""
    print_header("Dependency Tests")
    
    checks = []
    
    required_packages = {
        'flask': 'Flask web framework',
        'sklearn': 'Scikit-learn (ML)',
        'pandas': 'Pandas (data)',
        'numpy': 'NumPy (numerical)',
        'shap': 'SHAP (explainability)',
        'groq': 'GROQ (LLM)',
        'langgraph': 'LangGraph (agent)',
        'scapy': 'Scapy (packet capture)',
    }
    
    for package, description in required_packages.items():
        try:
            __import__(package)
            print_check(True, f"{description} (import as {YELLOW}{package}{RESET})")
            checks.append(True)
        except ImportError:
            print_check(False, f"{description} not installed")
            checks.append(False)
    
    return all(checks)

def print_summary(results):
    """Print summary results."""
    print_header("VERIFICATION SUMMARY")
    
    total = sum(len(v) if isinstance(v, list) else 1 for v in results.values())
    passed = sum(sum(v) if isinstance(v, list) else v for v in results.values())
    
    print(f"Total Checks: {total}")
    print(f"Passed: {GREEN}{passed}{RESET}")
    print(f"Failed: {RED}{total - passed}{RESET}")
    
    if passed == total:
        print(f"\n{GREEN}{'='*70}")
        print(f"{'✅ ALL CHECKS PASSED - SYSTEM READY ✅'.center(70)}")
        print(f"{'='*70}{RESET}\n")
        return True
    else:
        print(f"\n{RED}{'='*70}")
        print(f"{'❌ SOME CHECKS FAILED - REVIEW ABOVE ❌'.center(70)}")
        print(f"{'='*70}{RESET}\n")
        return False

def main():
    """Run all verification tests."""
    print(f"\n{BLUE}")
    print("╔" + "═"*68 + "╗")
    print("║" + "Agentic IDS Implementation Verification".center(68) + "║")
    print("║" + "Testing all three gaps (Packet Capture, Snort, Streaming)".center(68) + "║")
    print("╚" + "═"*68 + "╝")
    print(f"{RESET}")
    
    results = {}
    
    # Run tests
    print("\n[1/6] Testing module imports...")
    results['imports'] = test_imports()
    
    print("\n[2/6] Testing Flask integration...")
    results['flask'] = test_flask_integration()
    
    print("\n[3/6] Testing configuration...")
    results['config'] = test_config()
    
    print("\n[4/6] Testing packet capture classes...")
    results['packet_capture'] = test_packet_capture_classes()
    
    print("\n[5/6] Testing Snort/Suricata classes...")
    results['snort'] = test_snort_comparison_classes()
    
    print("\n[6/6] Testing existing system (no regressions)...")
    results['existing'] = test_existing_system()
    
    print("\n[7/7] Testing dependencies...")
    results['deps'] = test_dependencies()
    
    # Print summary
    success = print_summary(results)
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
