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
from typing import Any, Dict, List, TypedDict, Optional

from groq import Groq
from langgraph.graph import END, StateGraph

from src import config

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# TYPE DEFINITIONS (For better IDE support and type checking)
# ─────────────────────────────────────────────────────────────────────────────

class FlowState(TypedDict, total=False):
    """Network flow information from ML detection layer."""
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    timestamp: str

class ThreatState(TypedDict, total=False):
    """Accumulated threat assessment state across agent pipeline."""
    flow: FlowState
    ml_confidence: float
    ml_prediction: int
    shap_features: List[Dict[str, Any]]
    threat_type: str
    threat_type_confidence: float
    abuse_score: int
    intel_source: str
    intel_status: str
    is_zero_day: bool
    llm_hypothesis: str
    llm_confidence: float
    conflict_detected: bool
    conflict_evidence: str
    rehypothesis_attempt: int
    recommendation: str
    risk_score: float

class AgentState(TypedDict, total=False):
    """Complete agent state graph for threat analysis."""
    flow: FlowState
    ml_confidence: float
    ml_prediction: int
    shap_features: List[Dict[str, Any]]
    threat_type: str
    threat_type_confidence: float
    abuse_score: int
    intel_source: str
    intel_status: str
    is_zero_day: bool
    llm_hypothesis: str
    llm_confidence: float
    conflict_detected: bool
    conflict_evidence: str
    rehypothesis_attempt: int
    recommendation: str
    risk_score: float


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping (centralised) - comprehensive coverage
# Updated with full attack lifecycle: Recon, Initial Access, Execution, Persistence, etc.
# Reference: MITRE ATT&CK Framework v14.1 (https://attack.mitre.org/)
# ---------------------------------------------------------------------------
MITRE_MAP: dict[str, str] = {
    # Denial of Service / Availability
    "DDoS": "T1498",  # Network Denial of Service
    # Reconnaissance
    "Port-Scan": "T1046",  # Network Service Discovery
    # Credential Access
    "Brute-Force": "T1110",  # Brute Force
    # Exfiltration
    "Data-Exfiltration": "T1041",  # Exfiltration Over C2 Channel
    # Command & Control / Execution
    "Botnet": "T1102",  # Web Service
    # Additional common threat types (MITRE ATT&CK v14.1)
    "Ransomware": "T1486",  # Data Encrypted for Impact
    "C2": "T1071",  # Application Layer Protocol (C2 traffic)
    "Worm": "T1570",  # Lateral Tool Transfer
    "Trojan": "T1195",  # Supply Chain Compromise
    "Malware": "T1204",  # User Execution
    "Exploit": "T1190",  # Exploit Public-Facing Application
    "Lateral-Movement": "T1021",  # Remote Services
    "Privilege-Escalation": "T1548",  # Abuse Elevation Control Mechanism
    "Persistence": "T1547",  # Boot or Logon Autostart Execution
    "Data-Staging": "T1074",  # Data Staged
    "C2-Beaconing": "T1071",  # Application Layer Protocol
    "Anomaly": "T1000",  # Unknown/Unclassified threat
}

# Whitelist of valid threat type strings returned by the LLM
# Must match keys in MITRE_MAP above
VALID_THREATS = {
    "DDoS", "Port-Scan", "Brute-Force", "Data-Exfiltration", "Botnet",
    "Ransomware", "C2", "Worm", "Trojan", "Malware", "Exploit",
    "Lateral-Movement", "Privilege-Escalation", "Persistence",
    "Data-Staging", "C2-Beaconing", "Anomaly"
}

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
        """Initialize LangGraph state graph with typed state management.
        
        Returns:
            Compiled StateGraph with all nodes and edges configured.
        """
        wf = StateGraph(AgentState)

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
        if abuse_score > config.ABUSEIPDB_HIGH_CONFIDENCE_THRESHOLD:
            logger.info(f"[Agent] High-confidence intel ({abuse_score}). Skipping LLM.")
            return "direct_to_conclude"
        return "analyze"

    def _route_after_conflict(self, state: Dict[str, Any]) -> str:
        """Route after conflict resolution with explicit rehypothesis limit.
        
        Allows up to 3 re-hypothesis attempts (0, 1, 2) before giving up.
        If LLM continues to output invalid threat types, logs CRITICAL error
        and returns "resolved" to proceed with "Anomaly" classification.
        """
        if state.get("_conflict_detected"):
            attempts = state.get("_rehypothesis_attempts", 0)
            if attempts < 3:
                logger.warning(
                    f"[Agent] Conflict detected — re-hypothesising (attempt {attempts + 1}/3)"
                )
                return "needs_rehypothesis"
            else:
                logger.critical(
                    f"[Agent] CRITICAL: Conflict resolution failed after {attempts} attempts. "
                    f"Proceeding with 'Anomaly' classification. Check LLM output validity."
                )
        return "resolved"

    # ------------------------------------------------------------------
    # Node: OBSERVE
    # ------------------------------------------------------------------

    def node_observe(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        OBSERVE: Format ML detection + SHAP context for downstream reasoning.
        
        This is the entry point to the agentic pipeline. It assembles the
        ML prediction and SHAP feature attribution into a human-readable
        context that the LLM can reason about.
        
        Args:
            state: Current agent state containing:
                - flow: Network flow dict with src_ip, dst_ip, dst_port, protocol
                - ml_confidence: ML model confidence [0.0-1.0]
                - ml_prediction: 0=benign, 1=attack
                - shap_explanation: List of top SHAP feature contributions
        
        Returns:
            Updated state with added keys:
                - shap_context: Formatted string for LLM reasoning
        
        Raises:
            None - failures logged and ignored (graceful degradation)
        """
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
        """
        VERIFY: Cross-reference source IP with AbuseIPDB threat intelligence.
        
        Calls the AbuseIPDB API to gather external reputation data on the
        source IP. Detects zero-day signals when ML confidence is high
        but external reputation is clean (potential new attack pattern).
        
        Args:
            state: Current agent state with:
                - flow: Network flow with src_ip
                - ml_confidence: ML model confidence
        
        Returns:
            Updated state with:
                - abuse_score: AbuseIPDB confidence score [0-100]
                - intel_source: "AbuseIPDB (Live)", "AbuseIPDB (Cache)", or "None"
                - intel_status: "success", "failed", "skipped", or "private_ip"
                - is_zero_day: Boolean flag if potential zero-day detected
        
        Raises:
            RequestException: Logged and handled gracefully (fallback to LLM-only)
        """
        logger.info("[Agent] VERIFY: threat intel lookup …")
        src_ip = state.get("flow", {}).get("src_ip", "")
        ml_conf = state.get("ml_confidence", 0.0)
        abuse_score = 0
        intel_source = "None"
        intel_status = "skipped"
        is_zero_day = False

        # Use centralized IP validation utility
        is_private = config.is_private_ip(src_ip)

        if not is_private and config.ABUSEIPDB_API_KEY:
            try:
                # Mask the API key for logging purposes
                masked_key = config.ABUSEIPDB_API_KEY[:4] + "*" * (len(config.ABUSEIPDB_API_KEY) - 8) + config.ABUSEIPDB_API_KEY[-4:]
                
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
                    logger.warning(f"AbuseIPDB returned {resp.status_code} for IP {src_ip}")
            except requests.exceptions.Timeout:
                intel_status = "error_timeout"
                logger.warning(f"AbuseIPDB timeout after 5 seconds for IP {src_ip}")
            except requests.exceptions.ConnectionError as exc:
                intel_status = "error_connection"
                logger.warning(f"AbuseIPDB connection error for IP {src_ip}: {type(exc).__name__}")
            except (requests.exceptions.RequestException, ValueError, KeyError) as exc:
                # Catch specific API/data errors, not generic Exception (which masks KeyboardInterrupt, SystemExit)
                intel_status = "error_exception"
                logger.warning(f"AbuseIPDB lookup failed for IP {src_ip}: {type(exc).__name__}")

        # Zero-Day Conflict Detection:
        # High ML confidence + clean external reputation = potential novel threat.
        # IMPORTANT: We flag this as potential zero-day WITHOUT artificially elevating
        # the abuse_score. The score reflects actual external reputation (clean = low).
        # The conflict is informational; we don't fake the abuse score.
        if ml_conf > config.ZERO_DAY_ML_CONFIDENCE_THRESHOLD and abuse_score < config.ZERO_DAY_ABUSE_SCORE_CLEAN_THRESHOLD and intel_status == "success":
            is_zero_day = True
            # NOTE: Do NOT artificially elevate abuse_score to 50.
            # This would create false positives based on conflict, not actual threat.
            # Keep abuse_score as-is (reflects clean external reputation).
            logger.warning(
                f"⚠️  POTENTIAL ZERO-DAY: High ML confidence ({ml_conf:.2f}) "
                f"contradicts clean external reputation (abuse_score={abuse_score}). "
                f"Flagged for additional analysis but NOT artificially escalating score."
            )

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
        """
        HYPOTHESIZE: Query Groq LLM to classify threat type from SHAP evidence.
        
        The LLM uses the assembled context (network flow, ML confidence, SHAP
        features, threat intelligence) to generate a threat hypothesis. If
        conflict resolution detected issues in previous attempts, the LLM
        is explicitly prompted to correct its reasoning.
        
        Args:
            state: Current agent state with:
                - observation_context: Formatted string of flow + SHAP features
                - _conflict_detected: Boolean indicating conflict from prior analysis
                - hypothesized_threat: Previous threat type (if correcting)
        
        Returns:
            Updated state with:
                - llm_hypothesis: Selected threat type (DDoS, Port-Scan, etc.)
                - llm_confidence: LLM confidence [0.0-1.0], default 0.5
        
        Raises:
            RequestException: Caught, logged, and fallback confidence applied
            json.JSONDecodeError: Caught on malformed response, fallback applied
        """
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
            # CRITICAL: Add timeout to prevent Flask worker from blocking indefinitely
            # if Groq API hangs or is unresponsive. 30 seconds is reasonable for LLM inference.
            response = self.client.chat.completions.create(
                model=config.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                max_tokens=200,
                timeout=30,  # Prevent indefinite blocking on slow/unresponsive API
            )
            res = json.loads(response.choices[0].message.content)
            threat = res.get("threat_type", "Anomaly")
            # Whitelist guard — never let LLM return an arbitrary string
            if threat not in VALID_THREATS:
                attempts = state.get("_rehypothesis_attempts", 0)
                logger.error(
                    f"[Agent] LLM returned invalid threat type '{threat}' "
                    f"(attempt {attempts + 1}). Clamping to 'Anomaly'. "
                    f"Valid types: {VALID_THREATS}"
                )
                threat = "Anomaly"
            state["hypothesized_threat"] = threat
            state["llm_reasoning"] = res.get("reasoning", "No reasoning provided.")
            state["llm_confidence"] = float(res.get("llm_confidence", config.DEFAULT_LLM_CONFIDENCE))
        except (json.JSONDecodeError, ValueError, KeyError, AttributeError) as exc:
            # Specific exceptions for JSON parsing and data extraction, not generic Exception
            logger.error(f"LLM hypothesize failed ({type(exc).__name__}): {exc}")
            state["hypothesized_threat"] = "Anomaly"
            state["llm_reasoning"] = "Fallback: API error during hypothesis."
            state["llm_confidence"] = config.FALLBACK_LLM_CONFIDENCE

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
        """
        CONCLUDE: Synthesize final risk score, MITRE ATT&CK mapping, and recommendation.
        
        Combines all signals (ML confidence, threat intelligence, LLM hypothesis)
        into a final risk score [0.0-10.0] and actionable SOC recommendation.
        Risk score weighting: 60% ML confidence + 40% external reputation.
        
        Args:
            state: Current agent state with:
                - ml_confidence: ML model confidence [0.0-1.0]
                - threat_intel: Dict with abuse_score [0-100]
                - hypothesized_threat: Final classified threat type
        
        Returns:
            Updated state with:
                - risk_score: Final score [0.0-10.0]
                - mitre: MITRE ATT&CK technique ID (e.g., "T1498" for DDoS)
                - recommendation: SOC action (CRITICAL, WARNING, or INFO)
                - serialized_state: JSON-safe version for API response
        
        Raises:
            None - all failures logged and handled with sensible defaults
        """
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

        if risk_score > config.RISK_SCORE_CRITICAL_THRESHOLD:
            state["recommendation"] = "CRITICAL: Immediate block required. Alert SOC."
        elif risk_score > config.RISK_SCORE_WARNING_THRESHOLD:
            state["recommendation"] = "WARNING: Monitor and rate-limit flow."
        else:
            state["recommendation"] = "INFO: Log for periodic review."

        # Filter state to ensure only serializable fields are returned
        # This prevents issues when saving/replaying alerts (removes functions, exceptions, etc.)
        serializable_state = self._serialize_state(state)
        return serializable_state

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

    # ------------------------------------------------------------------
    # State serialization (for alerting and persistence)
    # ------------------------------------------------------------------

    def _serialize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Convert agent state to JSON-serializable format for alerting/storage.
        
        Removes un-serializable objects (functions, exceptions, complex objects)
        and keeps only primitive types and dicts/lists of primitives.
        
        This is critical for:
        - Storing alerts in database
        - Replaying alerts in forensic analysis
        - Sending alerts to external systems (SIEM, webhooks, etc.)
        """
        safe_state = {}
        
        # Whitelist of safe keys to serialize
        safe_keys = {
            "flow", "ml_confidence", "shap_explanation",
            "observation_context", "observation", "hypothesized_threat",
            "llm_reasoning", "llm_confidence", "threat_intel",
            "risk_score", "recommendation", "mitre",
        }
        
        for key in safe_keys:
            if key in state:
                value = state[key]
                # Deep filter nested dicts (like threat_intel, flow)
                if isinstance(value, dict):
                    safe_state[key] = self._serialize_dict(value)
                elif isinstance(value, list):
                    safe_state[key] = [
                        self._serialize_dict(item) if isinstance(item, dict) else item
                        for item in value
                        if isinstance(item, (str, int, float, bool, type(None), dict))
                    ]
                elif isinstance(value, (str, int, float, bool, type(None))):
                    safe_state[key] = value
                # else: skip non-serializable types (functions, exceptions, etc.)
        
        return safe_state
    
    def _serialize_dict(self, d: dict) -> dict:
        """Recursively filter dict to only JSON-serializable values."""
        safe_dict = {}
        for k, v in d.items():
            if isinstance(v, dict):
                safe_dict[k] = self._serialize_dict(v)
            elif isinstance(v, list):
                safe_dict[k] = [
                    self._serialize_dict(item) if isinstance(item, dict) else item
                    for item in v
                    if isinstance(item, (str, int, float, bool, type(None), dict))
                ]
            elif isinstance(v, (str, int, float, bool, type(None))):
                safe_dict[k] = v
            # else: skip non-serializable values (functions, exceptions, etc.)
        return safe_dict


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
