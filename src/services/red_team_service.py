"""
src/services/red_team_service.py

RedTeamService — Orchestrates the interaction between Attacker, Critic, and Defender.
Used by the Flask API to run autonomous security battles.
"""

import logging
import time
from typing import List, Dict, Any

from src.attacker import AttackerAgent
from src.critic import CriticAgent
from src.agent import build_agent
from src.services.inference import inference_service
from src import config

logger = logging.getLogger(__name__)

class RedTeamService:
    def __init__(self):
        self.attacker = AttackerAgent()
        self.critic = CriticAgent()
        self._defender = None # Initialized on demand
        
    @property
    def defender(self):
        if self._defender is None:
            self._defender = build_agent()
        return self._defender

    def run_battle(self, iterations: int = 3) -> List[Dict[str, Any]]:
        """Runs a multi-round adversarial battle, logging alerts directly to the active SOC feed."""
        if not inference_service.is_ready:
            inference_service.load()
            
        history = []
        current_feedback = ""
        
        for i in range(iterations):
            round_data = {"round": i + 1}
            
            # 1. Attack
            payload = self.attacker.generate_payload(feedback=current_feedback)
            round_data["attacker_payload"] = payload
            
            # 2. ML Layers
            ml_conf = inference_service.predict_proba(payload)
            shap_data = inference_service.explain(payload)
            
            # 3. Defense
            defense_result = self.defender.analyze(payload, ml_conf, shap_data)
            round_data["defender_result"] = defense_result
            
            # 4. Critique
            feedback = self.critic.analyze_defense(payload, defense_result)
            current_feedback = feedback
            round_data["critic_feedback"] = feedback
            
            # 5. Push directly to active SOC dashboard feed and logs!
            try:
                from src.services.persistence import alert_repo
                from src.services.geo_service import get_geo_location
                from src.services.voice_service import voice_assistant
                
                risk = defense_result.get("risk_score", 0.0)
                status_label = "CRITICAL" if risk > 8.0 else "WARNING" if risk > 5.0 else "INFO"
                
                agent_logs = [
                    f"OBSERVE: {defense_result.get('observation_context', 'Flow analyzed.')}",
                    f"HYPOTHESIZE: {defense_result.get('hypothesized_threat', 'Unknown')}",
                    f"VERIFY: {defense_result.get('threat_intel', {}).get('intel_source', 'None')} — Abuse Score: {defense_result.get('threat_intel', {}).get('abuse_score', 0)}",
                    f"CONCLUDE: {defense_result.get('recommendation', 'N/A')}"
                ]
                
                # Format SHAP explanation list to match front-end contracts
                shap_list = []
                for item in shap_data:
                    shap_list.append({
                        "feature": item.get("feature", "unknown"),
                        "value": str(item.get("value", "0.0")),
                        "contribution": float(item.get("contribution", 0.0)),
                        "absolute_contribution": abs(float(item.get("contribution", 0.0)))
                    })
                
                geo = get_geo_location(payload.get("src_ip", "1.1.1.1"))
                
                alert_dict = {
                    "id": int(time.time() * 1000) + i,
                    "timestamp": time.strftime("%I:%M:%S %p"),
                    "src_ip": payload.get("src_ip", "1.1.1.1"),
                    "dst_ip": payload.get("dst_ip", "10.0.0.1"),
                    "dst_port": int(payload.get("dst_port", 80)),
                    "anomaly": True,
                    "ml_confidence": float(ml_conf),
                    "shap_explanation": shap_list,
                    "threat_type": defense_result.get("hypothesized_threat", "Unknown"),
                    "llm_reasoning": defense_result.get("llm_reasoning", "N/A"),
                    "llm_confidence": float(defense_result.get("llm_confidence", 0.0)),
                    "threat_intel": defense_result.get("threat_intel", {}),
                    "risk_score": float(risk),
                    "status": status_label,
                    "mitre": defense_result.get("mitre", "T1000"),
                    "zero_day_potential": defense_result.get("threat_intel", {}).get("zero_day_potential", False),
                    "recommendation": defense_result.get("recommendation", "N/A"),
                    "agent_reasoning": agent_logs,
                    "geo_location": geo,
                    "_backend": {
                        "agent_latency_ms": 150.0,
                        "agent_error": ""
                    }
                }
                
                alert_repo.push(alert_dict)
                
                # Trigger premium Jarvis/Friday voice announcement
                voice_assistant.announce_threat(
                    threat_type=alert_dict["threat_type"],
                    risk_score=alert_dict["risk_score"],
                    src_ip=alert_dict["src_ip"]
                )
            except Exception as e:
                logger.error(f"Failed to push red team attack alert to repo: {e}")
            
            history.append(round_data)
            
        return history

# Singleton
red_team_service = RedTeamService()
