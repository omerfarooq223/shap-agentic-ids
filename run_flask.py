#!/usr/bin/env python3
"""
Flask API Server Launcher
Properly handles module imports and starts the API server
"""

import os
import sys
from pathlib import Path

# Set up paths
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Now import the app
from src.app import app, initialize_system

if __name__ == '__main__':
    print("\n" + "="*80)
    print("AGENTIC IDS - FLASK API SERVER")
    print("="*80)
    
    # Check for root privileges (required for Scapy live sniffing)
    if os.getuid() != 0:
        print("⚠️  WARNING: Not running as root (sudo).")
        print("   Live packet capture will fail. For full functionality, run with: sudo python3 run_flask.py")
        print("-" * 80)
    
    # Initialize system
    if not initialize_system():
        print("\n❌ Failed to initialize system. Exiting.")
        sys.exit(1)
    
    # Start Flask server
    print("\n🚀 Starting Flask server on http://0.0.0.0:5005")
    print("📊 API Documentation available at /health")
    print("\nCtrl+C to stop server\n")
    
    app.run(host='0.0.0.0', port=5005, debug=False, use_reloader=False)
