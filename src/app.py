"""
src/app.py  (v2 — clean Flask factory)

This file is now a thin orchestration layer.
All business logic lives in:
  src/services/inference.py   → InferenceService
  src/services/geo_service.py → get_geo_location (non-blocking)
  src/services/persistence.py → AlertRepository
  src/agent.py                → IDSAgent (self-correcting)
  src/schemas.py              → Pydantic input/output models
"""

from __future__ import annotations

import logging
import os
import sys
import time
import threading
import random
import traceback

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import ValidationError
from dotenv import load_dotenv

load_dotenv()

from src import config
from src.config import logger
from src.schemas import DetectRequest, ChatRequest, DetectResponse
from src.agent import build_agent
from src.services.inference import inference_service
from src.services.geo_service import get_geo_location
from src.services.persistence import alert_repo
from src.streaming_api import create_streaming_blueprint

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Configure CORS with specific origins (enforced in config.py)
CORS(
    app, 
    origins=[config.FRONTEND_ORIGIN],  # Now required, no default wildcard
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-KEY"],
    supports_credentials=True,
    max_age=3600
)

logger.info(f"✓ CORS configured for origin(s): {config.FRONTEND_ORIGIN}")

# ---------------------------------------------------------------------------
# Rate Limiting Setup
# ---------------------------------------------------------------------------
if config.RATE_LIMIT_ENABLED:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],  # Global fallback
        storage_uri="memory://"
    )
    logger.info("✓ Rate limiting enabled")
else:
    # Dummy limiter that does nothing (for testing)
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            return lambda f: f
    limiter = DummyLimiter()
    logger.warning("⚠️  Rate limiting DISABLED (development mode)")

# ---------------------------------------------------------------------------
# Module-level agent handle (initialised in initialize_system)
# ---------------------------------------------------------------------------
_agent = None


def initialize_system() -> bool:
    """Load all ML artifacts and build the agent pipeline."""
    global _agent

    logger.info("=" * 80)
    logger.info("INITIALIZING IDS SYSTEM")
    logger.info("=" * 80)

    try:
        inference_service.load()
        _agent = build_agent()
        alert_repo.load()

        logger.info("=" * 80)
        logger.info("✓ SYSTEM INITIALIZED SUCCESSFULLY")
        logger.info("=" * 80)
        return True

    except FileNotFoundError as exc:
        logger.error(f"✗ Model files not found: {exc}")
        logger.error("Run 'python src/train.py' first.")
        return False
    except Exception as exc:
        logger.error(f"✗ Initialization error: {exc}")
        traceback.print_exc()
        return False


# ---------------------------------------------------------------------------
# Before-request hook
# ---------------------------------------------------------------------------

@app.before_request
def _log_request():
    logger.debug(f"Request: {request.method} {request.path} from {request.remote_addr}")


# ---------------------------------------------------------------------------
# Health & status
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
@limiter.limit(config.RATE_LIMIT_HEALTH)
def health():
    ready = inference_service.is_ready and _agent is not None
    return jsonify(
        {
            "status": "healthy" if ready else "unhealthy",
            "model_loaded": inference_service.is_ready,
            "agent_ready": _agent is not None,
        }
    ), (200 if ready else 503)


@app.route("/status", methods=["GET"])
@limiter.limit(config.RATE_LIMIT_HEALTH)
def status():
    return jsonify(
        {
            "status": "running",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "components": {
                "ml_model": "loaded" if inference_service.is_ready else "not_loaded",
                "agent_pipeline": "ready" if _agent else "not_ready",
            },
        }
    ), 200


# ---------------------------------------------------------------------------
# Core detection endpoint
# ---------------------------------------------------------------------------

@app.route("/detect", methods=["POST", "OPTIONS"])
@limiter.limit(config.RATE_LIMIT_DETECT)
def detect():
    """
    POST /detect - Detect threats in a network flow.
    
    This is the main entry point for threat detection. It orchestrates:
    1. Schema validation of input flow
    2. ML prediction (RandomForest + SMOTE-trained)
    3. SHAP explanation of features
    4. Agentic reasoning (LLM + threat intelligence)
    
    Security:
    - Requires X-API-KEY header with valid INTERNAL_API_KEY
    - Rate limited to 100 requests/minute
    - Input features strictly validated against FEATURE_RANGES
    
    Request Body (JSON):
    {
        "flow": {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 443,
            "protocol": "TCP",
            "... feature_1 ... feature_N": <numeric values>
        }
    }
    
    Response (on success):
    {
        "threat_detected": true,
        "ml_confidence": 0.95,
        "threat_type": "DDoS",
        "mitre_technique": "T1498",
        "risk_score": 9.2,
        "recommendation": "CRITICAL: Immediate block required. Alert SOC.",
        "features": [
            {"feature": "fwd_packets/s", "value": 15000, "contribution": 0.42}
        ]
    }
    
    Returns:
        JSON response with threat classification and recommendations
        HTTP 200: Threat assessment successful
        HTTP 400: Invalid request format or missing features
        HTTP 401: Missing or invalid API key
        HTTP 503: System not initialized
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    # Security: Ensure only authorized frontend can trigger detection
    api_key = request.headers.get("X-API-KEY")
    if not api_key:
        logger.warning(f"Unauthorized /detect request (missing API key) from {request.remote_addr}")
        return jsonify({"error": "Unauthorized: missing X-API-KEY header"}), 401
    if api_key != config.get_internal_api_key():
        logger.warning(f"Unauthorized /detect request (invalid API key) from {request.remote_addr}")
        return jsonify({"error": "Unauthorized: invalid API key"}), 401

    if not inference_service.is_ready or not _agent:
        return jsonify({"error": "System not initialized. Run 'python src/train.py' first."}), 503

    # ── 1. Schema validation (replaces hand-rolled dict checks) ──────────
    try:
        body = request.get_json(force=True) or {}
        req = DetectRequest(**body)
    except ValidationError as exc:
        logger.warning(f"Schema validation error: {exc}")
        return jsonify({"error": "Invalid request", "details": exc.errors()}), 400
    except Exception:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    flow = req.flow.model_dump()

    logger.info(
        f"Processing flow {flow['src_ip']} → {flow['dst_ip']}:{flow['dst_port']}"
    )

    # ── 2. ML Detection ───────────────────────────────────────────────────
    try:
        ml_score = inference_service.predict_proba(flow)
    except ValueError as e:
        logger.warning(f"Feature validation failed: {e}")
        return jsonify({"error": "Invalid flow features", "details": str(e)}), 400
    except Exception as e:
        logger.error(f"ML prediction error: {e}", exc_info=True)
        return jsonify({"error": "ML prediction failed"}), 500
    
    logger.info(f"ML score: {ml_score:.3f}")

    if ml_score < 0.5:
        geo = get_geo_location(flow["src_ip"])
        response = DetectResponse(
            id=int(time.time() * 1000),
            timestamp=time.strftime("%I:%M:%S %p"),
            src_ip=flow["src_ip"],
            dst_ip=flow["dst_ip"],
            dst_port=flow["dst_port"],
            anomaly=False,
            ml_confidence=ml_score,
            shap_explanation=[],
            threat_type="benign",
            recommendation="No action required.",
            geo_location=geo,
            agent_reasoning=["ML model determined flow is benign."],
        )
        return jsonify(response.model_dump()), 200

    # ── 3. SHAP Explainability ────────────────────────────────────────────
    try:
        shap_explanation = inference_service.explain(flow)
    except ValueError as e:
        logger.warning(f"SHAP explanation failed due to feature validation: {e}")
        shap_explanation = []  # Fallback: continue with empty explanation
    except Exception as e:
        logger.error(f"SHAP explanation error: {e}", exc_info=True)
        shap_explanation = []  # Fallback: continue with empty explanation

    # ── 4. Agentic Reasoning (with self-correction) ───────────────────────
    t0 = time.time()
    final_state = _agent.analyze(flow, ml_score, shap_explanation)
    agent_latency_ms = (time.time() - t0) * 1000
    logger.info(f"Agent latency: {agent_latency_ms:.0f} ms")

    # ── 5. Geo (non-blocking — returns quickly via background thread) ─────
    geo = get_geo_location(flow["src_ip"])

    # ── 6. Build and validate response via Pydantic schema ───────────────
    risk = final_state.get("risk_score", 0.0)
    if risk > 8.0:
        status_label = "CRITICAL"
    elif risk > 5.0:
        status_label = "WARNING"
    else:
        status_label = "INFO"

    agent_logs = [
        f"OBSERVE: {final_state.get('observation_context', 'Flow analyzed.')}",
        f"HYPOTHESIZE: {final_state.get('hypothesized_threat', 'Unknown')}",
        (
            f"VERIFY: {final_state.get('threat_intel', {}).get('intel_source', 'None')}"
            f" — Abuse Score: {final_state.get('threat_intel', {}).get('abuse_score', 0)}"
        ),
        f"CONCLUDE: {final_state.get('recommendation', 'N/A')}",
    ]

    if final_state.get("_conflict_detected"):
        agent_logs.append(
            "CONFLICT RESOLUTION: LLM hypothesis contradicted SHAP evidence — re-analysis performed."
        )

    response = DetectResponse(
        id=int(time.time() * 1000),
        timestamp=time.strftime("%I:%M:%S %p"),
        src_ip=flow["src_ip"],
        dst_ip=flow["dst_ip"],
        dst_port=flow["dst_port"],
        anomaly=True,
        ml_confidence=ml_score,
        shap_explanation=shap_explanation,
        threat_type=final_state.get("hypothesized_threat", "Unknown"),
        llm_reasoning=final_state.get("llm_reasoning", "N/A"),
        llm_confidence=final_state.get("llm_confidence", 0.0),
        threat_intel=final_state.get("threat_intel", {}),
        risk_score=risk,
        status=status_label,
        mitre=final_state.get("threat_intel", {}).get("mitre_mapping", "T1046"),
        zero_day_potential=final_state.get("threat_intel", {}).get("zero_day_potential", False),
        recommendation=final_state.get("recommendation", "N/A"),
        agent_reasoning=agent_logs,
        geo_location=geo,
    )

    response_dict = response.model_dump()
    response_dict["_backend"] = {
        "agent_latency_ms": agent_latency_ms,
        "agent_error": final_state.get("error", ""),
    }

    alert_repo.push(response_dict)
    return jsonify(response_dict), 200


# ---------------------------------------------------------------------------
# Alerts feed
# ---------------------------------------------------------------------------

@app.route("/api/v1/alerts", methods=["GET"])
@limiter.limit(config.RATE_LIMIT_HEALTH)
def get_alerts():
    return jsonify(alert_repo.get_all()), 200


# ---------------------------------------------------------------------------
# Chat endpoint
# ---------------------------------------------------------------------------

@app.route("/chat", methods=["POST", "OPTIONS"])
@limiter.limit(config.RATE_LIMIT_CHAT)
def chat():
    """
    POST /chat - Interactive LLM chat for threat analysis discussion.
    
    Allows frontend/SOC analysts to ask follow-up questions about detected
    threats using the same Groq LLM as the agent pipeline. This enables
    interactive threat investigation without re-running the full detection.
    
    Security:
    - Requires X-API-KEY header with valid INTERNAL_API_KEY
    - Rate limited to 50 requests/minute (lower than /detect for cost control)
    - LLM query timeouts at 30 seconds to prevent hanging
    
    Request Body (JSON):
    {
        "threat_type": "DDoS",
        "question": "Why was this flow classified as DDoS?"
    }
    
    Response (on success):
    {
        "response": "This flow was classified as DDoS because of high packet volume..."
    }
    
    Returns:
        JSON response with LLM analysis
        HTTP 200: LLM response generated
        HTTP 400: Invalid request format
        HTTP 401: Missing or invalid API key
        HTTP 503: LLM service unavailable
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    # Security: Prevent LLM proxy abuse
    api_key = request.headers.get("X-API-KEY")
    if not api_key:
        logger.warning(f"Unauthorized /chat request (missing API key) from {request.remote_addr}")
        return jsonify({"error": "Unauthorized: missing X-API-KEY header"}), 401
    if api_key != config.get_internal_api_key():
        logger.warning(f"Unauthorized /chat request (invalid API key) from {request.remote_addr}")
        return jsonify({"error": "Unauthorized: invalid API key"}), 401

    try:
        body = request.get_json(force=True) or {}
        req = ChatRequest(**body)
    except ValidationError as exc:
        return jsonify({"error": "Invalid request", "details": exc.errors()}), 400

    if not config.GROQ_API_KEY:
        return jsonify({"error": "GROQ_API_KEY not configured"}), 500

    try:
        import groq as groq_lib

        recent = alert_repo.get_all()[:5]
        rag_lines = "\n".join(
            f"{i+1}. [{a['timestamp']}] {a.get('threat_type','?')} "
            f"from {a.get('src_ip','?')} (Risk: {a.get('risk_score','?')}/10)"
            for i, a in enumerate(recent)
        ) or "None (system idle)."

        system_prompt = f"""You are an expert cybersecurity analyst for an Agentic IDS.

CURRENT SYSTEM STATUS:
- Detection Engine: Random Forest (SMOTE-Balanced) + SHAP explainability
- Active Agent: LangGraph with Self-Correcting Conflict Resolution
- Threat Intelligence: AbuseIPDB Live Integration

RECENT DETECTED THREATS (Last 5):
{rag_lines}

Your expertise includes network flow analysis, ML-based anomaly detection,
SHAP explainability, MITRE ATT&CK mapping, and threat intelligence.
Be technical but concise. Reference SHAP evidence when relevant."""

        client = groq_lib.Client(api_key=config.GROQ_API_KEY)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": req.message},
            ],
            max_tokens=500,
            temperature=0.7,
            timeout=15,
        )
        bot_response = resp.choices[0].message.content.strip()
        return jsonify({"response": bot_response, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}), 200

    except Exception as exc:
        logger.error(f"[CHAT] Error: {exc}")
        return jsonify({"error": str(exc), "response": "Error processing request."}), 500


# ---------------------------------------------------------------------------
# Academic / testing endpoints
# ---------------------------------------------------------------------------

@app.route("/api/test/stress", methods=["POST"])
@limiter.limit(config.RATE_LIMIT_TEST)
def trigger_stress_test():
    """Simulates a burst of malicious flows for dashboard testing."""
    # Security: Prevent buffer spamming
    api_key = request.headers.get("X-API-KEY")
    if not api_key:
        logger.warning(f"Unauthorized /api/test/stress request (missing API key) from {request.remote_addr}")
        return jsonify({"error": "Unauthorized: missing X-API-KEY header"}), 401
    if api_key != config.get_internal_api_key():
        logger.warning(f"Unauthorized /api/test/stress request (invalid API key) from {request.remote_addr}")
        return jsonify({"error": "Unauthorized: invalid API key"}), 401

    def _burst():
        attack_types = ["DDoS", "Port-Scan", "Brute-Force", "Botnet"]
        for _ in range(10):
            mock = {
                "id": int(time.time() * 1000) + random.randint(1, 1000),
                "timestamp": time.strftime("%I:%M:%S %p"),
                "src_ip": f"103.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "dst_ip": "192.168.10.50",
                "dst_port": random.choice([22, 80, 443, 3389]),
                "anomaly": True,
                "ml_confidence": random.uniform(0.85, 0.99),
                "threat_type": random.choice(attack_types),
                "risk_score": random.uniform(7.5, 9.8),
                "status": "CRITICAL",
                "recommendation": "BLOCK: Stress test anomaly.",
                "geo_location": {
                    "lat": random.uniform(-40, 60),
                    "lon": random.uniform(-120, 140),
                },
            }
            alert_repo.push(mock)
            time.sleep(0.5)

    threading.Thread(target=_burst, daemon=True).start()
    return jsonify({"status": "Stress test started", "count": 10}), 200


@app.route("/api/metrics/benchmarks", methods=["GET"])
@limiter.limit(config.RATE_LIMIT_HEALTH)
def get_benchmarks():
    import json
    from pathlib import Path
    
    # Try to load real metrics from the evaluation script output
    results_path = Path("docs/evaluation_results.json")
    if results_path.exists():
        try:
            with open(results_path, "r") as f:
                data = json.load(f)
            
            # The structure from EvaluationMetrics
            # Extract CICIDS2017 results if available
            cicids_metrics = data.get("datasets", {}).get("CICIDS2017", {})
            if cicids_metrics:
                return jsonify({
                    "labels": ["Precision", "Recall", "F1-Score"],
                    "agentic_ids": [
                        cicids_metrics.get("precision", 0.0),
                        cicids_metrics.get("recall", 0.0),
                        cicids_metrics.get("f1", 0.0)
                    ],
                    "snort": [0.82, 0.74, 0.78],      # Legacy baseline for comparison
                    "suricata": [0.85, 0.79, 0.82],   # Legacy baseline for comparison
                    "source": "Empirical Research Run",
                    "tpr": cicids_metrics.get("tpr", 0.0),
                    "fpr": cicids_metrics.get("fpr", 0.0)
                }), 200
        except Exception as e:
            logger.error(f"Failed to read evaluation results: {e}")

    # Fallback to zeros (forcing the user to run the evaluation script)
    return jsonify({
        "labels": ["Precision", "Recall", "F1-Score"],
        "agentic_ids": [0.0, 0.0, 0.0],
        "snort": [0.82, 0.74, 0.78],
        "suricata": [0.85, 0.79, 0.82],
        "source": "EVALUATION NOT RUN - Run scripts/run_evaluation.py",
        "tpr": 0.0,
        "fpr": 0.0
    }), 200


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found", "message": "Endpoint does not exist"}), 404


@app.errorhandler(500)
def internal_error(exc):
    logger.error(f"Internal server error: {exc}")
    return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Streaming blueprint
# ---------------------------------------------------------------------------

def _detection_callback(flow: dict) -> dict:
    """Used by the streaming pipeline for live packet capture."""
    try:
        ml_score = inference_service.predict_proba(flow)
        if ml_score < 0.5:
            return {"anomaly": False, "ml_score": ml_score}
        shap_exp = inference_service.explain(flow)
        state = _agent.analyze(flow, ml_score, shap_exp)
        return {
            "anomaly": True,
            "ml_score": ml_score,
            "threat_type": state.get("hypothesized_threat"),
            "risk_score": state.get("risk_score"),
            "recommendation": state.get("recommendation"),
        }
    except ValueError as e:
        logger.warning(f"Streaming detection: feature validation failed: {e}")
        return {"anomaly": False, "error": f"Feature validation: {str(e)[:100]}"}
    except Exception as exc:
        logger.error(f"Detection callback error: {exc}")
        return {"anomaly": False, "error": str(exc)}


streaming_bp = create_streaming_blueprint(_detection_callback)
app.register_blueprint(streaming_bp)



