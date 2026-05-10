"""
src/agent.py  (v2)

IDSAgent — LangGraph-based agentic reasoning pipeline.

Architecture (Non-Linear Graph):
  observe → verify → [route] → hypothesize → conflict_resolution → conclude
                         ↘ (high-confidence intel) ↗ conclude (skip LLM)

NEW: conflict_resolution node
  Detects contradictions between the LLM hypothesis and SHAP evidence
  (e.g., LLM says "DDoS" but top SHAP feature is SSH port 22).
  When a contradiction is found, the agent re-prompts the LLM with
  an explicit correction hint — true self-correcting agentic behaviour.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import requests
from typing import Any, Dict, List

from groq import Groq
from langgraph.graph import END, StateGraph

from src import config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping (centralised)
# ---------------------------------------------------------------------------
MITRE_MAP: dict[str, str] = {
    "DDoS": "T1498",
    "Port-Scan": "T1046",
    "Brute-Force": "T1110",
    "Data-Exfiltration": "T1041",
    "Botnet": "T1102",
    "Anomaly": "T1000",
}

# Whitelist of valid threat type strings returned by the LLM
VALID_THREATS = {"DDoS", "Port-Scan", "Brute-Force", "Data-Exfiltration", "Botnet", "Anomaly"}

# Ports whose SHAP dominance is a strong indicator of threat type
PORT_THREAT_HINTS: dict[int, str] = {
    22: "Brute-Force",
    3389: "Brute-Force",
    21: "Data-Exfiltration",
    445: "Botnet",
    53: "Botnet",
}


class IDSAgent:
    """
    Agentic reasoning pipeline for IDS alerts.

    Uses LangGraph to coordinate ML predictions, SHAP explanations,
    and external threat intelligence with self-correcting conflict
    resolution.
    """

    SENSITIVE_PORTS: dict[int, str] = {
        21: "FTP (Plaintext Credentials)",
        22: "SSH (Remote Management)",
        23: "Telnet (Legacy)",
        25: "SMTP (Mail)",
        53: "DNS (Potential Tunneling)",
        80: "HTTP (Web Service)",
        443: "HTTPS (Encrypted Web)",
        445: "SMB (File Sharing – Ransomware Vector)",
        3389: "RDP (Remote Desktop)",
        8080: "HTTP-Proxy",
    }

    def __init__(self) -> None:
        self.client = Groq(api_key=config.GROQ_API_KEY)
        self.workflow = self._create_workflow()
        self.app = self.workflow.compile()

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _create_workflow(self) -> StateGraph:
        wf = StateGraph(Dict[str, Any])

        wf.add_node("observe", self.node_observe)
        wf.add_node("verify", self.node_verify)
        wf.add_node("hypothesize", self.node_hypothesize)
        wf.add_node("conflict_resolution", self.node_conflict_resolution)
        wf.add_node("conclude", self.node_conclude)

        wf.set_entry_point("observe")
        wf.add_edge("observe", "verify")

        # If AbuseIPDB is very confident, skip LLM entirely
        wf.add_conditional_edges(
            "verify",
            self._route_after_verify,
            {"analyze": "hypothesize", "direct_to_conclude": "conclude"},
        )

        # After LLM hypothesises, check for contradictions with SHAP
        wf.add_edge("hypothesize", "conflict_resolution")

        # If contradictions found, resolve; then always conclude
        wf.add_conditional_edges(
            "conflict_resolution",
            self._route_after_conflict,
            {"resolved": "conclude", "needs_rehypothesis": "hypothesize"},
        )

        wf.add_edge("conclude", END)
        return wf

    # ------------------------------------------------------------------
    # Routing functions
    # ------------------------------------------------------------------

    def _route_after_verify(self, state: Dict[str, Any]) -> str:
        abuse_score = state.get("threat_intel", {}).get("abuse_score", 0)
        if abuse_score > 80:
            logger.info(f"[Agent] High-confidence intel ({abuse_score}). Skipping LLM.")
            return "direct_to_conclude"
        return "analyze"

    def _route_after_conflict(self, state: Dict[str, Any]) -> str:
        """Only re-hypothesise once (guard via rehypothesis_attempts counter)."""
        if state.get("_conflict_detected") and state.get("_rehypothesis_attempts", 0) < 1:
            logger.warning("[Agent] Conflict detected — triggering re-hypothesise.")
            return "needs_rehypothesis"
        return "resolved"

    # ------------------------------------------------------------------
    # Node: OBSERVE
    # ------------------------------------------------------------------

    def node_observe(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Format flow + SHAP context for downstream nodes."""
        logger.info("[Agent] OBSERVE: formatting flow context …")
        flow = state.get("flow", {})
        shap_data = state.get("shap_explanation", [])
        dst_port = int(flow.get("dst_port", 0))
        port_info = self.SENSITIVE_PORTS.get(dst_port, "General Service")

        ctx = (
            f"Flow: {flow.get('src_ip')} → {flow.get('dst_ip')}:{dst_port} ({port_info})\n"
            f"ML Confidence: {state.get('ml_confidence', 0):.2f}\n"
            "Top SHAP Features (Mathematical Evidence):\n"
        )
        for item in shap_data:
            ctx += f"  - {item['feature']}: {item['value']} (Impact {item['contribution']:.4f})\n"

        state["observation_context"] = ctx
        state["hypothesized_threat"] = "Unknown"
        state["_conflict_detected"] = False
        state["_rehypothesis_attempts"] = 0
        state["threat_intel"] = {
            "abuse_score": 0,
            "intel_source": "None",
            "intel_status": "skipped",
            "zero_day_potential": False,
            "mitre_mapping": "N/A",
        }
        state["observation"] = (
            f"Observing flow: {flow.get('src_ip')} → {dst_port} "
            f"({flow.get('protocol', 'TCP')})"
        )
        return state

    # ------------------------------------------------------------------
    # Node: VERIFY
    # ------------------------------------------------------------------

    def node_verify(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Check AbuseIPDB and detect zero-day conflict signals."""
        logger.info("[Agent] VERIFY: threat intel lookup …")
        src_ip = state.get("flow", {}).get("src_ip", "")
        ml_conf = state.get("ml_confidence", 0.0)
        abuse_score = 0
        intel_source = "None"
        intel_status = "skipped"
        is_zero_day = False

        try:
            ip_obj = ipaddress.ip_address(src_ip)
            is_private = ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            is_private = True

        if not is_private and config.ABUSEIPDB_API_KEY:
            try:
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": src_ip, "maxAgeInDays": "90"},
                    headers={"Accept": "application/json", "Key": config.ABUSEIPDB_API_KEY},
                    timeout=5,
                )
                if resp.status_code == 200:
                    abuse_score = resp.json()["data"]["abuseConfidenceScore"]
                    intel_source = "AbuseIPDB (Live)"
                    intel_status = "success"
                else:
                    intel_status = f"error_{resp.status_code}"
            except Exception as exc:
                intel_status = "error_exception"
                logger.warning(f"AbuseIPDB failed: {exc}")

        # Zero-Day Conflict Detection:
        # High ML confidence + clean external reputation = potential novel threat
        if ml_conf > 0.90 and abuse_score < 10 and intel_status == "success":
            is_zero_day = True
            abuse_score = 50  # elevate score due to ML/intel conflict
            logger.warning("⚠️  CONFLICT: High ML confidence vs clean IP — potential Zero-Day")

        state["threat_intel"] = {
            "abuse_score": abuse_score,
            "intel_source": intel_source,
            "intel_status": intel_status,
            "zero_day_potential": is_zero_day,
        }
        return state

    # ------------------------------------------------------------------
    # Node: HYPOTHESIZE
    # ------------------------------------------------------------------

    def node_hypothesize(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Call GROQ LLM to classify the threat type from SHAP context."""
        logger.info("[Agent] HYPOTHESIZE: calling LLM …")

        correction_hint = ""
        if state.get("_conflict_detected"):
            correction_hint = (
                f"\n\nCORRECTION REQUIRED: Your previous answer was "
                f"'{state.get('hypothesized_threat')}' but it contradicts "
                f"the SHAP evidence. Re-analyse carefully before responding."
            )

        prompt = f"""You are a specialised Network Security Analyst.
Based on the following features of a flagged network flow, classify the threat.

{state['observation_context']}{correction_hint}

THREAT MODELS:
- DDoS: High packet/byte volume, same destination port.
- Port-Scan: Rapid requests to unusual ports; low bytes per packet.
- Brute-Force: High duration on sensitive ports (22, 3389); high packet counts.
- Data-Exfiltration: High outbound (Bwd) bytes; unusual destination.
- Botnet: Periodic beaconing; specific C2 ports.
- Anomaly: Suspicious but doesn't cleanly fit above categories.

INSTRUCTION: Use the SHAP Mathematical Evidence to justify your classification.

Respond with EXACTLY this JSON:
{{
  "threat_type": "DDoS | Port-Scan | Brute-Force | Data-Exfiltration | Botnet | Anomaly",
  "reasoning": "Technical justification referencing SHAP features",
  "llm_confidence": 0.0
}}"""

        try:
            response = self.client.chat.completions.create(
                model=config.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                max_tokens=200,
            )
            res = json.loads(response.choices[0].message.content)
            threat = res.get("threat_type", "Anomaly")
            # Whitelist guard — never let LLM return an arbitrary string
            if threat not in VALID_THREATS:
                threat = "Anomaly"
            state["hypothesized_threat"] = threat
            state["llm_reasoning"] = res.get("reasoning", "No reasoning provided.")
            state["llm_confidence"] = float(res.get("llm_confidence", 0.5))
        except Exception as exc:
            logger.error(f"LLM hypothesize failed: {exc}")
            state["hypothesized_threat"] = "Anomaly"
            state["llm_reasoning"] = "Fallback: API error during hypothesis."
            state["llm_confidence"] = 0.3

        return state

    # ------------------------------------------------------------------
    # Node: CONFLICT RESOLUTION  ← NEW
    # ------------------------------------------------------------------

    def node_conflict_resolution(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cross-signal verification between LLM hypothesis and SHAP evidence.

        Detects contradictions such as:
          • LLM says "DDoS" but top SHAP feature is Port 22 (→ Brute-Force)
          • LLM says "Brute-Force" but flow has massive byte volume (→ DDoS)

        If a contradiction is found, sets _conflict_detected=True so the
        routing function re-triggers the hypothesize node with a correction hint.
        """
        logger.info("[Agent] CONFLICT RESOLUTION: cross-checking LLM vs SHAP …")

        hypothesis = state.get("hypothesized_threat", "Anomaly")
        shap_data = state.get("shap_explanation", [])
        flow = state.get("flow", {})
        dst_port = int(flow.get("dst_port", 0))
        attempts = state.get("_rehypothesis_attempts", 0)

        # Only run conflict check on first pass
        if attempts > 0:
            state["_conflict_detected"] = False
            return state

        conflict = False

        # Rule 1: SHAP top feature strongly implies a specific port-based threat
        if shap_data:
            top_feature = shap_data[0]["feature"].lower()
            port_implied_threat = PORT_THREAT_HINTS.get(dst_port)

            if port_implied_threat and hypothesis != port_implied_threat:
                # e.g., port 22 implies Brute-Force but LLM said DDoS
                logger.warning(
                    f"[ConflictRes] Port {dst_port} implies '{port_implied_threat}' "
                    f"but LLM said '{hypothesis}'"
                )
                conflict = True

            # Rule 2: LLM says DDoS but top SHAP feature is not volume-related
            volume_features = {"flow bytes/s", "fwd packets/s", "total fwd packets", "flow packets/s"}
            if hypothesis == "DDoS" and top_feature not in volume_features:
                logger.warning(
                    f"[ConflictRes] LLM hypothesis 'DDoS' conflicts with "
                    f"top SHAP feature '{shap_data[0]['feature']}' (not volume-related)"
                )
                conflict = True

        state["_conflict_detected"] = conflict
        if conflict:
            state["_rehypothesis_attempts"] = attempts + 1
        else:
            logger.info("[Agent] No conflicts detected — hypothesis accepted.")

        return state

    # ------------------------------------------------------------------
    # Node: CONCLUDE
    # ------------------------------------------------------------------

    def node_conclude(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesise final risk score, MITRE mapping, and recommendation."""
        logger.info("[Agent] CONCLUDE: synthesising final alert …")

        ml_conf = state.get("ml_confidence", 0.0)
        threat_intel = state.get("threat_intel", {})
        abuse_norm = threat_intel.get("abuse_score", 0) / 100.0

        base_risk = (ml_conf * 0.6) + (abuse_norm * 0.4)
        risk_score = round(min(10.0, base_risk * 10.0), 1)
        state["risk_score"] = risk_score

        threat = state.get("hypothesized_threat", "Anomaly")
        mitre = MITRE_MAP.get(threat, "T1000")
        state["mitre"] = mitre

        # Propagate MITRE into threat_intel dict for API response
        state["threat_intel"]["mitre_mapping"] = mitre

        if risk_score > 8.0:
            state["recommendation"] = "CRITICAL: Immediate block required. Alert SOC."
        elif risk_score > 5.0:
            state["recommendation"] = "WARNING: Monitor and rate-limit flow."
        else:
            state["recommendation"] = "INFO: Log for periodic review."

        return state

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze(
        self,
        flow_data: Dict[str, Any],
        ml_conf: float,
        shap_explanation: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Entry-point called by the Flask service layer."""
        initial_state: Dict[str, Any] = {
            "flow": flow_data,
            "ml_confidence": ml_conf,
            "shap_explanation": shap_explanation,
            "observation": "",
            "threat_type": "",
            "threat_intel": {},
            "risk_score": 0.0,
            "recommendation": "",
            "error": "",
            "latency": 0.0,
        }
        return self.app.invoke(initial_state)


def build_agent() -> IDSAgent:
    """Helper imported by app.py."""
    return IDSAgent()


# ---------------------------------------------------------------------------
# Quick smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    agent = build_agent()
    result = agent.analyze(
        flow_data={"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": 22},
        ml_conf=0.92,
        shap_explanation=[{"feature": "Dst_Port", "value": "22", "contribution": 0.35, "absolute_contribution": 0.35}],
    )
    print(f"\nFinal Agent Result:\n{result}")
