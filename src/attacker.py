"""
src/attacker.py

AttackerAgent — Generates adversarial network payloads to test the IDS.
Uses LLM-based reasoning to simulate a sophisticated hacker.
"""

import json
import logging
import random
from typing import Dict, Any, List

from groq import Groq
from src import config

logger = logging.getLogger(__name__)

class AttackerAgent:
    """Agentic Attacker that generates malicious network flows."""

    def __init__(self):
        self.client = Groq(api_key=config.get_groq_api_key())
        self.features = config.NUMERIC_FEATURES
        self.history: List[Dict] = []

    def generate_payload(self, feedback: str = "") -> Dict[str, Any]:
        """
        Generates a malicious flow payload.
        
        Args:
            feedback: Optional feedback from the Critic agent.
            
        Returns:
            A dictionary containing the network flow features.
        """
        logger.info("[Attacker] Generating malicious payload...")
        
        # System prompt for the Attacker
        system_prompt = (
            "You are a sophisticated Red Team penetration tester. Your goal is to generate "
            "network flow features that simulate a specific type of attack (e.g., DDoS, Port-Scan, "
            "Brute-Force, SQL Injection) while attempting to bypass an AI-based Intrusion Detection System.\n\n"
            f"You must return a JSON object with values for these specific features: {self.features}\n"
            "Also include: 'src_ip', 'dst_ip', 'dst_port', and 'protocol'.\n\n"
            "Constraints:\n"
            "1. IPs must be realistic (avoid private IPs if possible).\n"
            "2. Values must be numeric where appropriate.\n"
            "3. Logic must be consistent with the attack type.\n"
            "4. Be creative! Use the feedback to evolve your attack strategy."
        )

        user_content = "Generate a new malicious payload."
        if feedback:
            user_content = f"Previous attack failed. Feedback from Critic: {feedback}\nGenerate a modified payload to bypass detection."

        try:
            response = self.client.chat.completions.create(
                model=config.GROQ_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            payload = json.loads(response.choices[0].message.content)
            
            # Ensure all numeric features are present (fallback to random/defaults if LLM misses some)
            for feature in self.features:
                if feature not in payload:
                    payload[feature] = random.uniform(0, 100)
            
            # Basic defaults for required networking fields if missing
            if 'src_ip' not in payload: payload['src_ip'] = f"192.168.1.{random.randint(2, 254)}"
            if 'dst_ip' not in payload: payload['dst_ip'] = "10.0.0.1"
            if 'dst_port' not in payload: payload['dst_port'] = random.choice([22, 80, 443, 3389])
            if 'protocol' not in payload: payload['protocol'] = "TCP"
            
            logger.info(f"[Attacker] Payload generated (Targeting Port {payload.get('dst_port')})")
            return payload
            
        except Exception as e:
            logger.error(f"[Attacker] Failed to generate payload: {e}")
            # Fallback to a very basic DDoS-like payload
            return {f: 100.0 for f in self.features} | {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": 80}

if __name__ == "__main__":
    # Test
    attacker = AttackerAgent()
    print(json.dumps(attacker.generate_payload(), indent=2))
