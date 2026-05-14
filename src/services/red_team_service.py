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
        """Runs a multi-round adversarial battle."""
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
            
            history.append(round_data)
            
        return history

# Singleton
red_team_service = RedTeamService()
