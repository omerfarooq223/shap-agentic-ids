import os
import logging
from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from groq import Groq
from src import config

# Set up logging
logger = logging.getLogger(__name__)

class IDSAgent:
    """
    Agentic reasoning pipeline for IDS alerts.
    Uses LangGraph to coordinate between ML predictions, SHAP explanations, 
    and external threat intelligence.
    """
    
    def __init__(self):
        self.client = Groq(api_key=config.GROQ_API_KEY)
        self.workflow = self._create_workflow()
        self.app = self.workflow.compile()

    def _create_workflow(self) -> StateGraph:
        """
        Defines the non-linear reasoning loop (Observe -> Verify -> [Hypothesize] -> Conclude).
        Includes conditional routing to skip the LLM step if external intel is conclusive.
        """
        workflow = StateGraph(Dict[str, Any])

        # Define Nodes
        workflow.add_node("observe", self.node_observe)
        workflow.add_node("verify", self.node_verify)
        workflow.add_node("hypothesize", self.node_hypothesize)
        workflow.add_node("conclude", self.node_conclude)

        # Define Edges with Conditional Logic
        workflow.set_entry_point("observe")
        workflow.add_edge("observe", "verify")

        # Conditional Edge: If IP is known-malicious, skip the LLM analysis
        workflow.add_conditional_edges(
            "verify",
            self._should_hypothesize,
            {
                "analyze": "hypothesize",
                "direct_to_conclude": "conclude"
            }
        )
        
        workflow.add_edge("hypothesize", "conclude")
        workflow.add_edge("conclude", END)

        return workflow

    def _should_hypothesize(self, state: Dict[str, Any]) -> str:
        """Determines if LLM analysis is needed based on threat intel confidence."""
        abuse_score = state.get("threat_intel", {}).get("abuse_score", 0)
        
        if abuse_score > 80:
            logger.info(f"[Agent] High-confidence Intel (Score: {abuse_score}). Skipping LLM analysis.")
            return "direct_to_conclude"
            
        logger.info(f"[Agent] Intel inconclusive (Score: {abuse_score}). Routing to LLM for hypothesis.")
        return "analyze"

    def node_observe(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Step 1: Extract and format features for the LLM."""
        logger.info("[Agent] Observation Step: Formatting flow features...")
        flow = state.get("flow", {})
        shap_data = state.get("shap_explanation", [])
        
        # Build a clear context string for the LLM
        context = f"Flow: {flow.get('src_ip')} -> {flow.get('dst_ip')}:{flow.get('dst_port')}\n"
        context += f"ML Confidence: {state.get('ml_confidence', 0):.2f}\n"
        context += "Top SHAP Features:\n"
        for item in shap_data:
            context += f"  - {item['feature']}: Impact {item['contribution']:.4f}\n"
            
        state["observation_context"] = context
        return state

    def node_hypothesize(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Step 2: Ask the LLM to hypothesize the threat type based on features."""
        logger.info("[Agent] Hypothesis Step: Classifying threat via GROQ...")
        
        prompt = f"""You are a specialized Network Security Analyst.
Based on the following features of a flagged network flow, what is the most likely threat type?

{state['observation_context']}

Respond with EXACTLY one of these categories:
- DDoS
- Port-Scan
- Brute-Force
- Data-Exfiltration
- Botnet
- Anomaly (Unknown)

One word response only."""

        try:
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=10
            )
            state["hypothesized_threat"] = response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"LLM Hypothesis failed: {e}")
            state["hypothesized_threat"] = "Anomaly (Fallback)"
            
        return state

    def node_verify(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Step 3: Cross-reference with Real-World Threat Intelligence.
        Uses AbuseIPDB for public IPs and Heuristic Entropy-Checks for private IPs.
        """
        import requests
        logger.info("[Agent] Verification Step: Performing Threat Intel Lookup...")
        src_ip = state.get("flow", {}).get("src_ip", "")
        
        # Default results
        abuse_score = 0
        intel_source = "None"
        
        # 1. Check if it's a Public IP for AbuseIPDB
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(src_ip)
            is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast
        except ValueError:
            # Invalid IP format should not trigger external lookups
            is_private = True
        
        if not is_private and config.ABUSEIPDB_API_KEY:
            try:
                url = 'https://api.abuseipdb.com/api/v2/check'
                params = {'ipAddress': src_ip, 'maxAgeInDays': '90'}
                headers = {'Accept': 'application/json', 'Key': config.ABUSEIPDB_API_KEY}
                
                response = requests.get(url, params=params, headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    abuse_score = data['data']['abuseConfidenceScore']
                    intel_source = "AbuseIPDB (Live)"
                    logger.info(f"✓ Found IP in AbuseIPDB: Score {abuse_score}")
            except Exception as e:
                logger.warning(f"AbuseIPDB lookup failed: {e}. Falling back to heuristics.")
        
        # 2. Heuristic Fallback (Novelty Check)
        # If score is still 0 (or private IP), check feature anomalies (entropy/port)
        if abuse_score == 0:
            shap_impact = sum([abs(item['contribution']) for item in state.get('shap_explanation', [])])
            if shap_impact > 0.5: # Model is very confident in anomaly
                abuse_score = 40 # Assign "Suspicious" heuristic score
                intel_source = "Local Heuristic Analysis"
        
        state["threat_intel"] = {
            "abuse_score": abuse_score,
            "intel_source": intel_source,
            "mitre_mapping": self._get_mitre_mapping(state["hypothesized_threat"])
        }
        return state

    def node_conclude(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Step 4: Final risk scoring and recommendation synthesis."""
        logger.info("[Agent] Conclusion Step: Synthesizing final alert...")
        
        ml_conf = state.get("ml_confidence", 0)
        abuse_score = state["threat_intel"]["abuse_score"] / 100.0
        
        # Weighted Risk Score (0-10)
        base_risk = (ml_conf * 0.6) + (abuse_score * 0.4)
        risk_score = min(10.0, base_risk * 10.0)
        
        state["risk_score"] = round(risk_score, 1)
        
        if risk_score > 8.0:
            state["recommendation"] = "CRITICAL: Immediate block required."
        elif risk_score > 5.0:
            state["recommendation"] = "WARNING: Monitor and rate-limit flow."
        else:
            state["recommendation"] = "INFO: Log for periodic review."
            
        return state

    def _get_mitre_mapping(self, threat: str) -> str:
        """Maps threat types to MITRE ATT&CK techniques."""
        mapping = {
            "DDoS": "T1498",
            "Port-Scan": "T1046",
            "Brute-Force": "T1110",
            "Data-Exfiltration": "T1041",
            "Botnet": "T1102"
        }
        return mapping.get(threat, "T1000")

    def analyze(self, flow_data: Dict[str, Any], ml_conf: float, shap_explanation: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Entry point for the agent."""
        initial_state = {
            "flow": flow_data,
            "ml_confidence": ml_conf,
            "shap_explanation": shap_explanation
        }
        return self.app.invoke(initial_state)

def build_agent():
    """Helper function to initialize the IDSAgent for the Flask API."""
    return IDSAgent()

if __name__ == "__main__":
    # Test stub
    agent = build_agent()
    test_flow = {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": 22}
    test_shap = [{"feature": "Dst_Port", "value": 22, "contribution": 0.35}]
    
    result = agent.analyze(test_flow, 0.92, test_shap)
    print(f"\nFinal Agent Result:\n{result}")
