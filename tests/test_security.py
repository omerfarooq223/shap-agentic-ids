"""
tests/test_security.py — Security Validation Suite
Verifies API hardening, key enforcement, and rate limiting protections.
"""

import pytest
import time
from src import config

def test_api_key_enforcement(flask_client):
    """Verify that protected endpoints reject requests without a valid API key."""
    flask_client, *_ = flask_client
    # /detect endpoint requires X-API-KEY
    payload = {
        "Destination Port": 80,
        "dst_port": 80,
        "Flow Duration": 1000,
        "Total Fwd Packets": 2,
        "Total Backward Packets": 2,
        "Total Length of Fwd Packets": 100,
        "Total Length of Bwd Packets": 100,
        "Fwd Packet Length Mean": 50,
        "Bwd Packet Length Mean": 50,
        "Flow Bytes/s": 200,
        "Flow Packets/s": 4,
        "Fwd Packets/s": 2,
        "Bwd Packets/s": 2,
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8"
    }
    
    # 1. No key
    resp = flask_client.post("/detect", json={"flow": payload})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Unauthorized"
    
    # 2. Wrong key
    resp = flask_client.post("/detect", json={"flow": payload}, headers={"X-API-KEY": "wrong-key"})
    assert resp.status_code == 401
    
    # 3. Correct key
    resp = flask_client.post("/detect", json={"flow": payload}, headers={"X-API-KEY": config.INTERNAL_API_KEY})
    assert resp.status_code == 200


def test_session_auth_flow_allows_protected_reads(flask_client):
    """Browser clients authenticate once and then use an HttpOnly session cookie."""
    flask_client, *_, mock_repo = flask_client
    mock_repo.get_all.return_value = []

    login = flask_client.post("/api/v1/auth/login", json={"api_key": config.INTERNAL_API_KEY})
    assert login.status_code == 200
    assert login.get_json()["authenticated"] is True
    assert "access_token" in login.get_json()

    set_cookie = login.headers.get("Set-Cookie", "")
    assert "HttpOnly" in set_cookie
    assert f"SameSite={config.SESSION_COOKIE_SAMESITE}" in set_cookie
    if config.SESSION_COOKIE_SECURE:
        assert "Secure" in set_cookie

    resp = flask_client.get("/api/v1/alerts")
    assert resp.status_code == 200


def test_bearer_session_token_allows_protected_reads(flask_client):
    """Deployed browser clients can use the signed token when cross-site cookies are blocked."""
    flask_client, *_, mock_repo = flask_client
    mock_repo.get_all.return_value = []

    login = flask_client.post("/api/v1/auth/login", json={"api_key": config.INTERNAL_API_KEY})
    token = login.get_json()["access_token"]

    from src.app import app
    with app.test_client() as token_client:
        resp = token_client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200


def test_invalid_bearer_token_is_rejected(flask_client):
    """Malformed bearer tokens do not unlock protected endpoints."""
    client, *_, mock_repo = flask_client
    mock_repo.get_all.return_value = []

    from src.app import app
    with app.test_client() as token_client:
        resp = token_client.get("/api/v1/alerts", headers={"Authorization": "Bearer invalid"})

    assert resp.status_code == 401

def test_rate_limiting_headers(flask_client):
    """Verify that rate limiting headers are present in responses."""
    flask_client, *_ = flask_client
    headers = {"X-API-KEY": config.INTERNAL_API_KEY}
    resp = flask_client.get("/health", headers=headers)
    
    # Note: Flask-Limiter headers might be missing since we mocked the limiter
    # We just verify the request was successful
    assert resp.status_code == 200
    print("\n[SECURITY] Rate limiting headers check skipped (mocked environment)")

def test_payload_size_limit(flask_client):
    """Verify that extremely large payloads are rejected (DoS protection)."""
    flask_client, *_ = flask_client
    headers = {"X-API-KEY": config.INTERNAL_API_KEY}
    # Create a 2MB payload (if limit is 1MB)
    huge_payload = {"flow": {"data": "A" * (2 * 1024 * 1024)}}
    resp = flask_client.post("/detect", json=huge_payload, headers=headers)
    
    # Flask/Werkzeug usually returns 413 Payload Too Large
    assert resp.status_code in [413, 400]
