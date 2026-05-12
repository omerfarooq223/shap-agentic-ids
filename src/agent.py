"""
src/agent.py  (v2)

IDSAgent — LangGraph-based agentic reasoning pipeline.

Architecture (Non-Linear Graph):
  observe → verify → [route] → hypothesize → conflict_resolution → conclude
                         ↘ (high-confidence intel) ↗ conclude (skip LLM)
"""

from __future__ import annotations

import json
import logging
import requests
from typing import Any, Dict, List, TypedDict, Optional

from groq import Groq
from langgraph.graph import END, StateGraph

from src import config

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# TYPE DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

class FlowState(TypedDict, total=False):
    """Network flow information from ML detection layer."""
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    timestamp: str

class AgentState(TypedDict, total=False):
    """Complete agent state graph for threat analysis."""
    # Input data
    flow: FlowState
    ml_confidence: float
    ml_prediction: int
    shap_explanation: List[Dict[str, Any]]
    
    # Processed context
    observation_context: str
    observation: str
    
    # Intelligence & Analysis
    threat_intel: Dict[str, Any]
    hypothesized_threat: str
    llm_reasoning: str
    llm_confidence: float
    
    # Conflict Resolution & Routing
    _conflict_detected: bool
    _rehypothesis_attempts: int
    
    # Final Output
    risk_score: float
    mitre: str
    recommendation: str
    error: str

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------
MITRE_MAP: dict[str, str] = {
    "DDoS": "T1498",
    "Port-Scan": "T1046",
    "Brute-Force": "T1110",
    "Data-Exfiltration": "T1041",
    "Botnet": "T1102",
    "Ransomware": "T1486",
    "C2": "T1071",
    "Worm": "T1570",
    "Trojan": "T1195",
    "Malware": "T1204",
    "Exploit": "T1190",
    "Lateral-Movement": "T1021",
    "Privilege-Escalation": "T1548",
    "Persistence": "T1547",
    "Data-Staging": "T1074",
    "C2-Beaconing": "T1071",
    "Anomaly": "T1000",
}

VALID_THREATS = set(MITRE_MAP.keys())

PORT_THREAT_HINTS: dict[int, str] = {
    22: "Brute-Force",
    3389: "Brute-Force",
    21: "Data-Exfiltration",
    445: "Botnet",
    53: "Botnet",
}

class IDSAgent:
    """Agentic reasoning pipeline for IDS alerts."""

    SENSITIVE_PORTS: dict[int, str] = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-Proxy",
    }

    def __init__(self) -> None:
        self.client = Groq(api_key=config.GROQ_API_KEY)
        self.workflow = self._create_workflow()
        self.app = self.workflow.compile()

    def _create_workflow(self) -> StateGraph:
        wf = StateGraph(AgentState)
        wf.add_node("observe", self.node_observe)
        wf.add_node("verify", self.node_verify)
        wf.add_node("hypothesize", self.node_hypothesize)
        wf.add_node("conflict_resolution", self.node_conflict_resolution)
        wf.add_node("conclude", self.node_conclude)

        wf.set_entry_point("observe")
        wf.add_edge("observe", "verify")
        wf.add_conditional_edges("verify", self._route_after_verify, {"analyze": "hypothesize", "direct_to_conclude": "conclude"})
        wf.add_edge("hypothesize", "conflict_resolution")
        wf.add_conditional_edges("conflict_resolution", self._route_after_conflict, {"resolved": "conclude", "needs_rehypothesis": "hypothesize"})
        wf.add_edge("conclude", END)
        return wf

    def _route_after_verify(self, state: AgentState) -> str:
        abuse_score = state.get("threat_intel", {}).get("abuse_score", 0)
        if abuse_score > config.ABUSEIPDB_HIGH_CONFIDENCE_THRESHOLD:
            return "direct_to_conclude"
        return "analyze"

    def _route_after_conflict(self, state: AgentState) -> str:
        if state.get("_conflict_detected") and state.get("_rehypothesis_attempts", 0) < 3:
            return "needs_rehypothesis"
        return "resolved"

    def node_observe(self, state: AgentState) -> AgentState:
        logger.info("[Agent] OBSERVE: formatting context")
        flow = state.get("flow", {})
        shap_data = state.get("shap_explanation", [])
        dst_port = int(flow.get("dst_port", 0))
        port_info = self.SENSITIVE_PORTS.get(dst_port, "General Service")

        ctx = (f"Flow: {flow.get('src_ip')} → {flow.get('dst_ip')}:{dst_port} ({port_info})\n"
               f"ML Confidence: {state.get('ml_confidence', 0):.2f}\n"
               "Top SHAP Features:\n")
        for item in shap_data:
            ctx += f"  - {item['feature']}: {item['value']} (Impact {item['contribution']:.4f})\n"

        return {
            **state,
            "observation_context": ctx,
            "hypothesized_threat": "Unknown",
            "llm_reasoning": "Awaiting analysis...",
            "llm_confidence": 0.0,
            "_conflict_detected": False,
            "_rehypothesis_attempts": state.get("_rehypothesis_attempts", 0),
            "threat_intel": {"abuse_score": 0, "intel_source": "None", "intel_status": "skipped", "zero_day_potential": False, "mitre_mapping": "N/A"},
            "observation": f"Observing flow: {flow.get('src_ip')} → {dst_port}",
            "risk_score": 0.0, "mitre": "T1000", "recommendation": "N/A", "error": ""
        }

    def node_verify(self, state: AgentState) -> AgentState:
        logger.info("[Agent] VERIFY: threat intel")
        src_ip = state.get("flow", {}).get("src_ip", "")
        ml_conf = state.get("ml_confidence", 0.0)
        abuse_score, intel_source, intel_status, is_zero_day = 0, "None", "skipped", False

        if not config.is_private_ip(src_ip) and config.ABUSEIPDB_API_KEY:
            try:
                resp = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                    params={"ipAddress": src_ip}, 
                                    headers={"Key": config.ABUSEIPDB_API_KEY}, timeout=5)
                if resp.status_code == 200:
                    abuse_score = resp.json()["data"]["abuseConfidenceScore"]
                    intel_source, intel_status = "AbuseIPDB (Live)", "success"
                else: intel_status = f"error_{resp.status_code}"
            except Exception as e:
                intel_status = "error_exception"
                logger.warning(f"AbuseIPDB fail: {e}")

        if ml_conf > config.ZERO_DAY_ML_CONFIDENCE_THRESHOLD and abuse_score < config.ZERO_DAY_ABUSE_SCORE_CLEAN_THRESHOLD and intel_status == "success":
            is_zero_day = True

        return {
            **state,
            "threat_intel": {"abuse_score": abuse_score, "intel_source": intel_source, "intel_status": intel_status, "zero_day_potential": is_zero_day}
        }

    def node_hypothesize(self, state: AgentState) -> AgentState:
        logger.info("[Agent] HYPOTHESIZE: calling LLM")
        hint = f"\n\nCORRECTION REQUIRED: Previous '{state.get('hypothesized_threat')}' contradicted SHAP." if state.get("_conflict_detected") else ""
        prompt = f"System: Network Analyst\nContext: {state.get('observation_context')}{hint}\nInstruction: Classify threat. Return JSON: {{'threat_type': '...', 'reasoning': '...', 'llm_confidence': 0.0}}"

        try:
            resp = self.client.chat.completions.create(model=config.GROQ_MODEL, messages=[{"role": "user", "content": prompt}], response_format={"type": "json_object"}, timeout=30)
            res = json.loads(resp.choices[0].message.content)
            threat = res.get("threat_type", "Anomaly")
            if threat not in VALID_THREATS: threat = "Anomaly"
            return {**state, "hypothesized_threat": threat, "llm_reasoning": res.get("reasoning"), "llm_confidence": float(res.get("llm_confidence", 0.5))}
        except Exception as e:
            logger.error(f"LLM fail: {e}")
            return {**state, "hypothesized_threat": "Anomaly", "llm_reasoning": f"Error: {str(e)[:50]}"}

    def node_conflict_resolution(self, state: AgentState) -> AgentState:
        logger.info("[Agent] CONFLICT: checking signals")
        hypo = state.get("hypothesized_threat", "Anomaly")
        port = int(state.get("flow", {}).get("dst_port", 0))
        attempts = state.get("_rehypothesis_attempts", 0)
        if attempts > 0: return {**state, "_conflict_detected": False}
        
        conflict = False
        hinted = PORT_THREAT_HINTS.get(port)
        if hinted and hypo != hinted: conflict = True
        
        return {**state, "_conflict_detected": conflict, "_rehypothesis_attempts": attempts + 1 if conflict else attempts}

    def node_conclude(self, state: AgentState) -> AgentState:
        logger.info("[Agent] CONCLUDE: final alert")
        risk = round(min(10.0, (state.get("ml_confidence", 0) * 6 + (state.get("threat_intel", {}).get("abuse_score", 0) / 10))), 1)
        threat = state.get("hypothesized_threat", "Anomaly")
        mitre = MITRE_MAP.get(threat, "T1000")
        rec = "CRITICAL: Block" if risk > 8 else "WARNING: Monitor" if risk > 5 else "INFO: Log"
        
        final = {**state, "risk_score": risk, "mitre": mitre, "recommendation": rec}
        final["threat_intel"]["mitre_mapping"] = mitre
        return self._serialize_state(final)

    def analyze(self, flow: dict, ml_conf: float, shap: list) -> dict:
        return self.app.invoke({"flow": flow, "ml_confidence": ml_conf, "shap_explanation": shap, "_rehypothesis_attempts": 0})

    def _serialize_state(self, state: dict) -> dict:
        safe_keys = {"flow", "ml_confidence", "shap_explanation", "observation_context", "observation", "hypothesized_threat", "llm_reasoning", "llm_confidence", "threat_intel", "risk_score", "recommendation", "mitre"}
        return {k: v for k, v in state.items() if k in safe_keys}

def build_agent(): return IDSAgent()

if __name__ == "__main__":
    agent = build_agent()
    print(agent.analyze({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": 22}, 0.9, [{"feature": "port", "value": 22, "contribution": 0.5}]))
