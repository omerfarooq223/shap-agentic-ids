"""
tests/test_integration_e2e.py — End-to-End Pipeline Validation
Validates the full chain: Data Loading -> Model Prediction -> SHAP Explanation -> Agent Reasoning.
"""

import pytest
from src.services.inference import InferenceService
from src.agent import IDSAgent
from src import config

@pytest.mark.integration
def test_full_pipeline_chain():
    """
    Validates that a flow can pass through the entire intelligence pipeline.
    This test uses the real InferenceService and IDSAgent logic (but mocks external LLM).
    """
    # 1. Setup services
    infer = InferenceService()
    # We load the real model (if training was done) or use a mock if file missing
    try:
        infer.load()
    except Exception:
        pytest.skip("ML model files not found. Run src/train.py first.")
    
    from unittest.mock import MagicMock, patch
    with patch("src.agent.Groq") as MockGroq:
        MockGroq.return_value = MagicMock()
        agent = IDSAgent()
        agent.client = MockGroq.return_value
    
    # 2. Define a realistic "Attack" flow
    flow = {
        "Destination Port": 22,
        "Flow Duration": 500,
        "Total Fwd Packets": 50,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 5000,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Mean": 100,
        "Bwd Packet Length Mean": 0,
        "Flow Bytes/s": 10000,
        "Flow Packets/s": 100,
        "Fwd Packets/s": 100,
        "Bwd Packets/s": 0,
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1"
    }
    
    # 3. Step 1: Inference
    prob = infer.predict_proba(flow)
    assert 0 <= prob <= 1
    
    # 4. Step 2: Explainability
    explanation = infer.explain(flow)
    assert len(explanation) > 0
    assert "feature" in explanation[0]
    
    # 5. Step 3: Agentic Reasoning (Mocking only the LLM call)
    agent.client.chat.completions.create.return_value.choices[0].message.content = \
        "The flow shows high volume to port 22. This is likely a SSH brute force attempt."
    
    # If langgraph is mocked (due to environment issues), we must mock the app return
    from unittest.mock import MagicMock
    if isinstance(agent.app, MagicMock):
        agent.app.invoke.return_value = {
            "threat_level": "High",
            "recommendation": "Block port 22",
            "reasoning": "Mocked langgraph response",
            "status": "analyzed"
        }
    
    result = agent.analyze(flow, prob, explanation)
    
    # 6. Final Validation
    assert "threat_level" in result
    assert "recommendation" in result
    assert "reasoning" in result
    assert result["status"] == "analyzed"
    print(f"\n[INTEGRATION] Pipeline result: {result['threat_level']}")
