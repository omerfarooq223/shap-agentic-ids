"""
tests/test_agent_steps.py  (v2 — Real Integration Tests)

These tests instantiate the ACTUAL IDSAgent and mock only the external
I/O boundaries (Groq API, AbuseIPDB HTTP calls) using pytest-mock.
This replaces the previous "theatrical" tests that re-implemented logic
inside the test body and never called any real production code.

Coverage:
  - node_observe       → correct state keys and context string
  - node_verify        → private IP skip, public IP lookup, zero-day detection
  - node_hypothesize   → LLM response parsing, whitelist guard, fallback
  - node_conflict_resolution → contradiction detection, re-route logic
  - node_conclude      → risk formula, MITRE mapping, recommendation text
  - Full pipeline      → end-to-end state transformation via agent.analyze()
  - Routing functions  → _route_after_verify, _route_after_conflict
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def agent():
    """
    Instantiate the real IDSAgent with a mocked Groq client so no actual
    network calls are made during import or construction.
    """
    with patch("src.agent.Groq") as MockGroq:
        MockGroq.return_value = MagicMock()
        from src.agent import IDSAgent
        instance = IDSAgent()
        instance.client = MockGroq.return_value
        return instance


@pytest.fixture
def base_state():
    """Minimal valid initial state as produced by node_observe."""
    return {
        "flow": {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "dst_port": 22,
            "protocol": "TCP",
        },
        "ml_confidence": 0.92,
        "shap_explanation": [
            {"feature": "Fwd Packets/s", "value": "5000.00", "contribution": 0.35, "absolute_contribution": 0.35},
            {"feature": "Flow Duration", "value": "0.01", "contribution": 0.20, "absolute_contribution": 0.20},
        ],
        "observation": "",
        "hypothesized_threat": "Unknown",
        "threat_intel": {},
        "risk_score": 0.0,
        "recommendation": "",
        "error": "",
        "latency": 0.0,
        "_conflict_detected": False,
        "_rehypothesis_attempts": 0,
    }


# ---------------------------------------------------------------------------
# 1. node_observe
# ---------------------------------------------------------------------------

class TestNodeObserve:
    def test_sets_observation_context(self, agent, base_state):
        result = agent.node_observe(base_state)
        assert "observation_context" in result
        assert "192.168.1.100" in result["observation_context"]
        assert "22" in result["observation_context"]

    def test_recognises_sensitive_port(self, agent, base_state):
        base_state["flow"]["dst_port"] = 22
        result = agent.node_observe(base_state)
        assert "SSH" in result["observation_context"]

    def test_initialises_safe_defaults(self, agent, base_state):
        result = agent.node_observe(base_state)
        assert result["hypothesized_threat"] == "Unknown"
        assert result["_conflict_detected"] is False
        assert result["_rehypothesis_attempts"] == 0
        assert "abuse_score" in result["threat_intel"]

    def test_unknown_port_labelled_general(self, agent, base_state):
        base_state["flow"]["dst_port"] = 9999
        result = agent.node_observe(base_state)
        assert "General Service" in result["observation_context"]


# ---------------------------------------------------------------------------
# 2. node_verify
# ---------------------------------------------------------------------------

class TestNodeVerify:
    def test_skips_private_ip(self, agent, base_state):
        """Private IPs must never trigger an external HTTP call."""
        with patch("src.agent.requests.get") as mock_get:
            result = agent.node_verify(base_state)
            mock_get.assert_not_called()
        assert result["threat_intel"]["intel_status"] == "skipped"
        assert result["threat_intel"]["abuse_score"] == 0

    def test_queries_public_ip(self, agent, base_state):
        base_state["flow"]["src_ip"] = "8.8.8.8"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"abuseConfidenceScore": 75}}

        with patch("src.config.ABUSEIPDB_API_KEY", "fake-key"):
            with patch("src.agent.requests.get", return_value=mock_response):
                result = agent.node_verify(base_state)

        assert result["threat_intel"]["abuse_score"] == 75
        assert result["threat_intel"]["intel_source"] == "AbuseIPDB (Live)"

    def test_zero_day_detection_triggers(self, agent, base_state):
        """High ML confidence + clean IP should flag zero-day potential."""
        base_state["flow"]["src_ip"] = "8.8.8.8"
        base_state["ml_confidence"] = 0.95   # above 0.90 threshold

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"abuseConfidenceScore": 2}}  # clean

        with patch("src.config.ABUSEIPDB_API_KEY", "fake-key"):
            with patch("src.agent.requests.get", return_value=mock_response):
                result = agent.node_verify(base_state)

        assert result["threat_intel"]["zero_day_potential"] is True
        assert result["threat_intel"]["abuse_score"] == 50  # elevated score

    def test_api_failure_handled_gracefully(self, agent, base_state):
        base_state["flow"]["src_ip"] = "8.8.8.8"
        with patch("src.config.ABUSEIPDB_API_KEY", "fake-key"):
            with patch("src.agent.requests.get", side_effect=ConnectionError("timeout")):
                result = agent.node_verify(base_state)
        assert result["threat_intel"]["intel_status"] == "error_exception"
        assert result["threat_intel"]["abuse_score"] == 0


# ---------------------------------------------------------------------------
# 3. node_hypothesize
# ---------------------------------------------------------------------------

class TestNodeHypothesise:
    def _make_llm_mock(self, agent, threat_type="DDoS", reasoning="High volume.", conf=0.9):
        payload = json.dumps({"threat_type": threat_type, "reasoning": reasoning, "llm_confidence": conf})
        mock_msg = MagicMock()
        mock_msg.content = payload
        mock_choice = MagicMock()
        mock_choice.message = mock_msg
        mock_completion = MagicMock()
        mock_completion.choices = [mock_choice]
        agent.client.chat.completions.create.return_value = mock_completion

    def test_parses_llm_response_correctly(self, agent, base_state):
        agent.node_observe(base_state)   # populate observation_context
        self._make_llm_mock(agent, "DDoS", "High Fwd Packets/s.", 0.88)

        result = agent.node_hypothesize(base_state)
        assert result["hypothesized_threat"] == "DDoS"
        assert result["llm_confidence"] == 0.88
        assert "High Fwd" in result["llm_reasoning"]

    def test_whitelist_rejects_invalid_threat(self, agent, base_state):
        """LLM returning an arbitrary string must be coerced to 'Anomaly'."""
        agent.node_observe(base_state)
        self._make_llm_mock(agent, "SQL-Injection", "Some weird answer.", 0.6)

        result = agent.node_hypothesize(base_state)
        assert result["hypothesized_threat"] == "Anomaly"

    def test_fallback_on_api_error(self, agent, base_state):
        agent.node_observe(base_state)
        agent.client.chat.completions.create.side_effect = RuntimeError("API down")

        result = agent.node_hypothesize(base_state)
        assert result["hypothesized_threat"] == "Anomaly"
        assert result["llm_confidence"] == 0.3
        agent.client.chat.completions.create.side_effect = None  # reset

    def test_includes_correction_hint_on_retry(self, agent, base_state):
        """When _conflict_detected=True the prompt must include a correction."""
        agent.node_observe(base_state)
        base_state["_conflict_detected"] = True
        base_state["hypothesized_threat"] = "DDoS"
        self._make_llm_mock(agent, "Brute-Force", "Corrected reasoning.", 0.8)

        captured_prompt = []
        original_create = agent.client.chat.completions.create

        def _capture(**kwargs):
            captured_prompt.append(kwargs["messages"][0]["content"])
            return original_create(**kwargs)

        agent.client.chat.completions.create.side_effect = _capture
        agent.node_hypothesize(base_state)
        agent.client.chat.completions.create.side_effect = None

        assert any("CORRECTION REQUIRED" in p for p in captured_prompt)


# ---------------------------------------------------------------------------
# 4. node_conflict_resolution
# ---------------------------------------------------------------------------

class TestConflictResolution:
    def test_detects_port_contradiction(self, agent, base_state):
        """LLM says DDoS but port 22 implies Brute-Force → conflict."""
        base_state["flow"]["dst_port"] = 22
        base_state["hypothesized_threat"] = "DDoS"
        base_state["_rehypothesis_attempts"] = 0

        result = agent.node_conflict_resolution(base_state)
        assert result["_conflict_detected"] is True

    def test_no_conflict_when_hypothesis_matches_port(self, agent, base_state):
        base_state["flow"]["dst_port"] = 22
        base_state["hypothesized_threat"] = "Brute-Force"
        base_state["_rehypothesis_attempts"] = 0

        result = agent.node_conflict_resolution(base_state)
        # Port 22 → Brute-Force matches → no conflict
        assert result["_conflict_detected"] is False

    def test_increments_rehypothesis_counter(self, agent, base_state):
        base_state["flow"]["dst_port"] = 22
        base_state["hypothesized_threat"] = "DDoS"
        base_state["_rehypothesis_attempts"] = 0

        result = agent.node_conflict_resolution(base_state)
        assert result["_rehypothesis_attempts"] == 1

    def test_no_conflict_on_second_pass(self, agent, base_state):
        """After one retry, conflict_resolution must not re-trigger."""
        base_state["flow"]["dst_port"] = 22
        base_state["hypothesized_threat"] = "DDoS"
        base_state["_rehypothesis_attempts"] = 1   # already retried

        result = agent.node_conflict_resolution(base_state)
        assert result["_conflict_detected"] is False


# ---------------------------------------------------------------------------
# 5. node_conclude
# ---------------------------------------------------------------------------

class TestNodeConclude:
    def test_risk_formula(self, agent, base_state):
        base_state["ml_confidence"] = 0.8
        base_state["threat_intel"] = {"abuse_score": 60, "intel_source": "AbuseIPDB (Live)"}
        base_state["hypothesized_threat"] = "Port-Scan"

        result = agent.node_conclude(base_state)
        # expected = min(10, (0.8*0.6 + 0.6*0.4) * 10) = min(10, (0.48+0.24)*10) = 7.2
        assert result["risk_score"] == pytest.approx(7.2, abs=0.1)

    def test_mitre_mapping_correctness(self, agent, base_state):
        base_state["hypothesized_threat"] = "Brute-Force"
        base_state["threat_intel"] = {"abuse_score": 0}
        result = agent.node_conclude(base_state)
        assert result["mitre"] == "T1110"

    def test_critical_recommendation_at_high_risk(self, agent, base_state):
        base_state["ml_confidence"] = 1.0
        base_state["threat_intel"] = {"abuse_score": 100}
        base_state["hypothesized_threat"] = "DDoS"
        result = agent.node_conclude(base_state)
        assert "CRITICAL" in result["recommendation"]

    def test_info_recommendation_at_low_risk(self, agent, base_state):
        base_state["ml_confidence"] = 0.55
        base_state["threat_intel"] = {"abuse_score": 0}
        base_state["hypothesized_threat"] = "Anomaly"
        result = agent.node_conclude(base_state)
        assert "INFO" in result["recommendation"]

    def test_risk_never_exceeds_10(self, agent, base_state):
        base_state["ml_confidence"] = 1.0
        base_state["threat_intel"] = {"abuse_score": 100}
        base_state["hypothesized_threat"] = "DDoS"
        result = agent.node_conclude(base_state)
        assert result["risk_score"] <= 10.0


# ---------------------------------------------------------------------------
# 6. Routing logic
# ---------------------------------------------------------------------------

class TestRoutingFunctions:
    def test_high_abuse_routes_to_conclude(self, agent, base_state):
        base_state["threat_intel"] = {"abuse_score": 95}
        assert agent._route_after_verify(base_state) == "direct_to_conclude"

    def test_low_abuse_routes_to_analyze(self, agent, base_state):
        base_state["threat_intel"] = {"abuse_score": 20}
        assert agent._route_after_verify(base_state) == "analyze"

    def test_conflict_routes_to_rehypothesis(self, agent, base_state):
        base_state["_conflict_detected"] = True
        base_state["_rehypothesis_attempts"] = 0
        assert agent._route_after_conflict(base_state) == "needs_rehypothesis"

    def test_no_conflict_routes_to_resolved(self, agent, base_state):
        base_state["_conflict_detected"] = False
        base_state["_rehypothesis_attempts"] = 0
        assert agent._route_after_conflict(base_state) == "resolved"

    def test_max_retries_routes_to_resolved(self, agent, base_state):
        """After 1 retry, even a conflict should resolve (no infinite loop)."""
        base_state["_conflict_detected"] = True
        base_state["_rehypothesis_attempts"] = 1
        assert agent._route_after_conflict(base_state) == "resolved"


# ---------------------------------------------------------------------------
# 7. End-to-end: agent.analyze()
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_analyze_returns_required_keys(self, agent):
        """Full pipeline must return all keys the Flask route expects."""
        # Mock LLM
        payload = json.dumps({
            "threat_type": "Port-Scan",
            "reasoning": "Low bytes per packet, many ports.",
            "llm_confidence": 0.85,
        })
        mock_msg = MagicMock()
        mock_msg.content = payload
        mock_choice = MagicMock()
        mock_choice.message = mock_msg
        mock_completion = MagicMock()
        mock_completion.choices = [mock_choice]
        agent.client.chat.completions.create.return_value = mock_completion

        # Private IP → skip AbuseIPDB
        result = agent.analyze(
            flow_data={"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": 80},
            ml_conf=0.75,
            shap_explanation=[
                {"feature": "Fwd Packets/s", "value": "200.00",
                 "contribution": 0.25, "absolute_contribution": 0.25}
            ],
        )

        required = {"hypothesized_threat", "risk_score", "recommendation", "threat_intel", "mitre"}
        assert required.issubset(result.keys()), f"Missing keys: {required - result.keys()}"
        assert 0.0 <= result["risk_score"] <= 10.0
        assert result["hypothesized_threat"] in {
            "DDoS", "Port-Scan", "Brute-Force", "Data-Exfiltration", "Botnet", "Anomaly", "Unknown"
        }

    def test_analyze_completes_without_exception(self, agent):
        """Pipeline must never raise even if SHAP data is empty."""
        agent.client.chat.completions.create.side_effect = RuntimeError("LLM offline")
        result = agent.analyze(
            flow_data={"src_ip": "10.0.0.1", "dst_ip": "8.8.4.4", "dst_port": 443},
            ml_conf=0.88,
            shap_explanation=[],
        )
        agent.client.chat.completions.create.side_effect = None
        assert "risk_score" in result
        assert "recommendation" in result
