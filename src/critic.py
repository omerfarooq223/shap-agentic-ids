"""
src/critic.py

CriticAgent — Analyzes the interaction between the Attacker and Defender.
Provides feedback to the Attacker to improve future attempts.
"""

import json
import logging
from typing import Dict, Any

from groq import Groq
from src import config

logger = logging.getLogger(__name__)

class CriticAgent:
    """Agentic Critic that analyzes defense logs and gives feedback to the attacker."""

    def __init__(self):
        self.client = Groq(api_key=config.get_groq_api_key())

    def analyze_defense(self, attacker_payload: Dict, defender_output: Dict) -> str:
        """
        Analyzes why the attack succeeded or failed.
        
        Args:
            attacker_payload: The features sent by the Attacker.
            defender_output: The analysis result from the IDSAgent (Defender).
            
        Returns:
            A string containing feedback for the Attacker.
        """
        logger.info("[Critic] Analyzing defense performance...")
        
        risk_score = defender_output.get("risk_score", 0.0)
        is_caught = risk_score > config.RISK_SCORE_WARNING_THRESHOLD
        
        # Prepare context for the Critic LLM
        context = {
            "attacker_payload": {k: v for k, v in attacker_payload.items() if k in ["dst_port", "protocol", "src_ip"]},
            "defender_classification": defender_output.get("mitre", "Unknown"),
            "defender_risk_score": risk_score,
            "defender_reasoning": defender_output.get("llm_reasoning", ""),
            "shap_features": defender_output.get("shap_explanation", [])[:3] # Top 3 features that caught the attack
        }

        system_prompt = (
            "You are a sophisticated Security Critic. You are overseeing a Red Teaming exercise.\n"
            "Your job is to look at the Defender's reaction to an attack and tell the Attacker "
            "how they can improve their next attempt to bypass the defense.\n\n"
            "Rules:\n"
            "1. If the risk_score is high (>5), the attack was caught. Tell the Attacker which features (SHAP) gave them away.\n"
            "2. If the risk_score is low (<5), the attack was successful. Tell the Attacker what they did right.\n"
            "3. Be technical and specific (e.g., 'Lower your Flow Bytes/s to appear more like normal traffic').\n"
            "4. Keep feedback concise and actionable."
        )

        user_content = f"Defense Result: {json.dumps(context)}"

        try:
            response = self.client.chat.completions.create(
                model=config.GROQ_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                temperature=0.5
            )
            
            feedback = response.choices[0].message.content
            status = "FAILED (Caught)" if is_caught else "SUCCESS (Bypassed)"
            logger.info(f"[Critic] Analysis complete. Attack Status: {status}")
            return feedback
            
        except Exception as e:
            logger.error(f"[Critic] Failed to analyze defense: {e}")
            return "Try to obfuscate features that have high SHAP values."

if __name__ == "__main__":
    # Test
    critic = CriticAgent()
    print(critic.analyze_defense({"dst_port": 80}, {"risk_score": 9.0, "mitre": "T1498"}))
