"""
tests/test_flask_api.py  (v2 — Proper Pytest with Flask Test Client)

Replaces the old script that required a live server running on port 5005.
Uses Flask's built-in test client so tests are fully self-contained and
run in CI without any external process dependencies.

All external I/O (ML models, Groq, AbuseIPDB, geolocation) is mocked.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch
import src.agent
from src import config

AUTH_HEADERS = {"X-API-KEY": config.INTERNAL_API_KEY}
# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_returns_200_when_ready(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.is_ready = True
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, flask_client):
        client, *_ = flask_client
        data = client.get("/health").get_json()
        assert "status" in data
        assert "model_loaded" in data
        assert "agent_ready" in data

    def test_returns_healthy_label(self, flask_client):
        client, *_ = flask_client
        data = client.get("/health").get_json()
        assert data["status"] == "healthy"


# ---------------------------------------------------------------------------
# /status
# ---------------------------------------------------------------------------

class TestStatusEndpoint:
    def test_returns_200(self, flask_client):
        client, *_ = flask_client
        assert client.get("/status").status_code == 200

    def test_response_has_components(self, flask_client):
        client, *_ = flask_client
        data = client.get("/status").get_json()
        assert "components" in data
        assert isinstance(data["components"], dict)

    def test_timestamp_present(self, flask_client):
        client, *_ = flask_client
        data = client.get("/status").get_json()
        assert "timestamp" in data and data["timestamp"]


# ---------------------------------------------------------------------------
# /detect — benign flow
# ---------------------------------------------------------------------------

class TestDetectBenign:
    def test_benign_flow_returns_200(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.predict_proba.return_value = 0.2   # below 0.5 threshold
        payload = {"flow": {"src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "dst_port": 443}}
        resp = client.post("/detect", json=payload, headers=AUTH_HEADERS)
        assert resp.status_code == 200

    def test_benign_flow_anomaly_false(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.predict_proba.return_value = 0.1
        payload = {"flow": {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 80}}
        data = client.post("/detect", json=payload, headers=AUTH_HEADERS).get_json()
        assert data["anomaly"] is False

    def test_benign_response_has_geo_location(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.predict_proba.return_value = 0.05
        payload = {"flow": {"src_ip": "192.168.1.1", "dst_ip": "1.1.1.1", "dst_port": 53}}
        data = client.post("/detect", json=payload, headers=AUTH_HEADERS).get_json()
        assert "geo_location" in data


# ---------------------------------------------------------------------------
# /detect — attack flow
# ---------------------------------------------------------------------------

class TestDetectAttack:
    def test_attack_flow_returns_200(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.predict_proba.return_value = 0.95   # above threshold
        payload = {"flow": {"src_ip": "203.0.113.42", "dst_ip": "192.168.10.50", "dst_port": 22}}
        resp = client.post("/detect", json=payload, headers=AUTH_HEADERS)
        assert resp.status_code == 200

    def test_attack_flow_anomaly_true(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.predict_proba.return_value = 0.92
        payload = {"flow": {"src_ip": "203.0.113.1", "dst_ip": "10.0.0.1", "dst_port": 3389}}
        data = client.post("/detect", json=payload, headers=AUTH_HEADERS).get_json()
        assert data["anomaly"] is True

    def test_attack_response_has_all_required_keys(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.predict_proba.return_value = 0.88
        payload = {"flow": {"src_ip": "1.2.3.4", "dst_ip": "192.168.1.1", "dst_port": 22}}
        data = client.post("/detect", json=payload, headers=AUTH_HEADERS).get_json()
        required = {
            "anomaly", "ml_confidence", "threat_type",
            "risk_score", "recommendation", "geo_location",
            "shap_explanation", "threat_intel", "agent_reasoning"
        }
        missing = required - data.keys()
        assert not missing, f"Missing keys in attack response: {missing}"

    def test_risk_score_in_valid_range(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.predict_proba.return_value = 0.91
        payload = {"flow": {"src_ip": "5.6.7.8", "dst_ip": "192.168.1.2", "dst_port": 80}}
        data = client.post("/detect", json=payload, headers=AUTH_HEADERS).get_json()
        assert 0.0 <= data["risk_score"] <= 10.0

    def test_agent_reasoning_is_list(self, flask_client):
        client, mock_infer, *_ = flask_client
        mock_infer.predict_proba.return_value = 0.85
        payload = {"flow": {"src_ip": "9.10.11.12", "dst_ip": "10.0.0.5", "dst_port": 445}}
        data = client.post("/detect", json=payload, headers=AUTH_HEADERS).get_json()
        assert isinstance(data["agent_reasoning"], list)
        assert len(data["agent_reasoning"]) > 0


# ---------------------------------------------------------------------------
# /detect — schema validation (Pydantic)
# ---------------------------------------------------------------------------

class TestDetectValidation:
    def test_missing_src_ip_returns_400(self, flask_client):
        client, *_ = flask_client
        payload = {"flow": {"dst_ip": "8.8.8.8", "dst_port": 80}}
        resp = client.post("/detect", json=payload, headers=AUTH_HEADERS)
        assert resp.status_code == 400

    def test_missing_dst_port_returns_400(self, flask_client):
        client, *_ = flask_client
        payload = {"flow": {"src_ip": "1.2.3.4", "dst_ip": "8.8.8.8"}}
        resp = client.post("/detect", json=payload, headers=AUTH_HEADERS)
        assert resp.status_code == 400

    def test_invalid_port_out_of_range_returns_400(self, flask_client):
        client, *_ = flask_client
        payload = {"flow": {"src_ip": "1.2.3.4", "dst_ip": "8.8.8.8", "dst_port": 99999}}
        resp = client.post("/detect", json=payload, headers=AUTH_HEADERS)
        assert resp.status_code == 400

    def test_empty_body_returns_400(self, flask_client):
        client, *_ = flask_client
        resp = client.post("/detect", data="not json", content_type="application/json", headers=AUTH_HEADERS)
        assert resp.status_code == 400

    def test_missing_flow_key_returns_400(self, flask_client):
        client, *_ = flask_client
        resp = client.post("/detect", json={"wrong_key": {}}, headers=AUTH_HEADERS)
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/v1/alerts
# ---------------------------------------------------------------------------

class TestAlertsEndpoint:
    def test_returns_200(self, flask_client):
        client, *_, mock_repo = flask_client
        mock_repo.get_all.return_value = []
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200

    def test_returns_list(self, flask_client):
        client, *_, mock_repo = flask_client
        mock_repo.get_all.return_value = []
        data = client.get("/api/v1/alerts").get_json()
        assert isinstance(data, list)

    def test_returns_populated_alerts(self, flask_client):
        client, *_, mock_repo = flask_client
        mock_repo.get_all.return_value = [{"threat_type": "DDoS", "risk_score": 9.1}]
        data = client.get("/api/v1/alerts").get_json()
        assert len(data) == 1
        assert data[0]["threat_type"] == "DDoS"


# ---------------------------------------------------------------------------
# /api/metrics/benchmarks
# ---------------------------------------------------------------------------

class TestBenchmarksEndpoint:
    def test_returns_200(self, flask_client):
        client, *_ = flask_client
        assert client.get("/api/metrics/benchmarks").status_code == 200

    def test_has_three_systems(self, flask_client):
        client, *_ = flask_client
        data = client.get("/api/metrics/benchmarks").get_json()
        assert "agentic_ids" in data
        assert "snort" in data
        assert "suricata" in data

    def test_metrics_are_lists_of_three(self, flask_client):
        client, *_ = flask_client
        data = client.get("/api/metrics/benchmarks").get_json()
        assert len(data["agentic_ids"]) == 3


# ---------------------------------------------------------------------------
# /api/test/stress
# ---------------------------------------------------------------------------

class TestStressTestEndpoint:
    def test_returns_200(self, flask_client):
        client, *_, mock_repo = flask_client
        resp = client.post("/api/test/stress", headers=AUTH_HEADERS)
        assert resp.status_code == 200

    def test_reports_count_10(self, flask_client):
        client, *_ = flask_client
        data = client.post("/api/test/stress", headers=AUTH_HEADERS).get_json()
        assert data.get("count") == 10


# ---------------------------------------------------------------------------
# 404 handler
# ---------------------------------------------------------------------------

class TestErrorHandlers:
    def test_404_returns_json(self, flask_client):
        client, *_ = flask_client
        resp = client.get("/nonexistent-route-xyz")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "error" in data
