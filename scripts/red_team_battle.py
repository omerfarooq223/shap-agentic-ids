"""
scripts/red_team_battle.py

Autonomous Red Teaming Battle: Attacker vs. Defender (Agentic IDS).
This script runs a feedback loop where an Attacker agent tries to bypass
the Defender, and a Critic agent provides adversarial feedback.
"""

import sys
import os
import json
import time
from typing import List, Dict

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.agent import build_agent
from src.attacker import AttackerAgent
from src.critic import CriticAgent
from src.services.inference import inference_service
from src import config

def run_battle(iterations: int = 3):
    print("\n" + "="*80)
    print("      🚀 AUTONOMOUS RED TEAMING BATTLE: ATTACKER vs. DEFENDER 🚀      ")
    print("="*80 + "\n")

    # 1. Initialize Services
    print("[System] Loading Inference Service (ML Models)...")
    inference_service.load()
    
    print("[System] Initializing Agents...")
    attacker = AttackerAgent()
    critic = CriticAgent()
    defender = build_agent()
    
    battle_history: List[Dict] = []
    current_feedback = ""

    for i in range(iterations):
        print(f"\n--- ROUND {i+1} ---")
        
        # 2. Attacker Generates Payload
        payload = attacker.generate_payload(feedback=current_feedback)
        print(f"[{time.strftime('%H:%M:%S')}] Attacker: Dispatched payload (Target: {payload.get('dst_ip')}:{payload.get('dst_port')})")
        
        # 3. ML Processing (Prediction + SHAP)
        print(f"[{time.strftime('%H:%M:%S')}] Defender: Inspecting packet via ML Layer...")
        try:
            ml_conf = inference_service.predict_proba(payload)
            shap_data = inference_service.explain(payload)
        except Exception as e:
            print(f"Error in ML Layer: {e}")
            continue

        # 4. Defender Agentic Reasoning
        print(f"[{time.strftime('%H:%M:%S')}] Defender: Running LangGraph Reasoning Pipeline...")
        result = defender.analyze(payload, ml_conf, shap_data)
        
        risk = result.get('risk_score', 0.0)
        mitre = result.get('mitre', 'Unknown')
        
        if risk > config.RISK_SCORE_WARNING_THRESHOLD:
            status = f"🔴 CAUGHT! (Risk: {risk}, MITRE: {mitre})"
        else:
            status = f"🟢 BYPASSED! (Risk: {risk})"
            
        print(f"[{time.strftime('%H:%M:%S')}] Defender Status: {status}")
        print(f"Reasoning: {result.get('llm_reasoning', 'No reasoning provided.')[:120]}...")

        # 5. Critic Analysis & Feedback
        print(f"[{time.strftime('%H:%M:%S')}] Critic: Evaluating battle logs...")
        current_feedback = critic.analyze_defense(payload, result)
        print(f"Critic Feedback: {current_feedback}")
        
        battle_history.append({
            "round": i + 1,
            "payload": {k: payload[k] for k in ["src_ip", "dst_ip", "dst_port"]},
            "defender_result": result,
            "critic_feedback": current_feedback
        })

    print("\n" + "="*80)
    print("      🏆 BATTLE CONCLUDED 🏆      ")
    print("="*80)
    
    # Save session logs
    log_file = config.LOGS_DIR / f"red_team_battle_{int(time.time())}.json"
    with open(log_file, 'w') as f:
        json.dump(battle_history, f, indent=2)
    print(f"\n[System] Detailed battle logs saved to: {log_file}")

if __name__ == "__main__":
    try:
        # Default to 3 rounds for a quick demo
        num_rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 3
        run_battle(iterations=num_rounds)
    except KeyboardInterrupt:
        print("\n[System] Battle aborted by user.")
    except Exception as e:
        print(f"\n[System] Critical error during battle: {e}")
        import traceback
        traceback.print_exc()
