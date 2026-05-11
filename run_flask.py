#!/usr/bin/env python3
"""
Flask API Server Launcher
Properly handles module imports and starts the API server

Security Notes:
  - Run behind a reverse proxy (nginx, Caddy) with TLS termination for production
  - Or use --cert and --key flags with SSL context
  - Never expose Flask directly to the internet without HTTPS
"""

import os
import sys
from pathlib import Path

# Set up paths
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print("\n" + "="*80)
print("AGENTIC IDS - FLASK API SERVER")
print("="*80)
print("🚀 Initializing components... (this may take a moment for SHAP/ML models)")

# Now import the app
from src.app import app, initialize_system

if __name__ == '__main__':
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
    from src import config
    
    # Check if SSL certificates are configured (for production HTTPS)
    ssl_context = None
    ssl_enabled = False
    cert_file = os.getenv("SSL_CERT_FILE")
    key_file = os.getenv("SSL_KEY_FILE")
    
    if cert_file and key_file:
        if os.path.exists(cert_file) and os.path.exists(key_file):
            ssl_context = (cert_file, key_file)
            ssl_enabled = True
            protocol = "https"
            print(f"✓ SSL/TLS enabled with certificate: {cert_file}")
        else:
            print(f"⚠️  WARNING: SSL certificates configured but files not found:")
            print(f"   Cert: {cert_file} (exists: {os.path.exists(cert_file)})")
            print(f"   Key: {key_file} (exists: {os.path.exists(key_file)})")
            protocol = "http"
    else:
        protocol = "http"
        print("⚠️  WARNING: HTTPS not configured!")
        print("   For production, either:")
        print("   1. Set SSL_CERT_FILE and SSL_KEY_FILE environment variables, OR")
        print("   2. Run behind a reverse proxy (nginx/Caddy) with TLS termination")
        print("   Example: FLASK_ENV=production SSL_CERT_FILE=/path/to/cert.pem SSL_KEY_FILE=/path/to/key.pem python3 run_flask.py")
    
    print(f"\n🚀 Starting Flask server on {protocol}://{config.FLASK_HOST}:{config.FLASK_PORT}")
    print("📊 API Documentation available at /health")
    print("🔒 IMPORTANT: This Flask app should run behind a production-grade reverse proxy (nginx, Caddy)")
    print("   with proper TLS termination, request validation, and WAF protection.\n")
    print("Ctrl+C to stop server\n")
    
    # Run Flask with optional SSL context
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=False,
        use_reloader=False,
        ssl_context=ssl_context
    )
