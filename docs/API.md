# Agentic IDS — Backend API Specification

This document details the REST API architecture I've built to power the SHAP-Explained Agentic IDS. The backend is designed as a modular Flask application that coordinates machine learning detection, mathematical explainability, and multi-agent reasoning.

---

## 🏗️ Technical Architecture

The API operates across four distinct logic layers:
1.  **Detection Layer**: High-speed Random Forest classifier (Scikit-Learn).
2.  **Explainability Layer**: SHAP (Shapley Additive exPlanations) for mathematical feature attribution.
3.  **Reasoning Layer**: LangGraph-driven autonomous agent utilizing Llama-3.3-70B via Groq.
4.  **Adversarial Layer**: Multi-agent Red Teaming (Attacker & Critic) for continuous stress testing.

---

## 📡 Core Endpoints

### 1. Threat Detection (`POST /detect`)
This is the primary entry point for network traffic analysis. It takes a raw network flow and returns a comprehensive security assessment.

**Security Requirements:**
*   Requires `X-API-KEY` header.
*   Strict Pydantic schema validation.

**Request Body:**
```json
{
  "flow": {
    "src_ip": "185.15.59.224",
    "dst_ip": "192.168.10.50",
    "dst_port": 80,
    "Flow Duration": 1200,
    "... 77 more numeric features ...": 0
  }
}
```

**Response Highlights:**
*   `anomaly`: Boolean flag.
*   `risk_score`: Final normalized score (0-10).
*   `shap_explanation`: Mathematical proof for the alert.
*   `agent_reasoning`: Step-by-step logic from the LangGraph pipeline.

---

### 2. Forensic Chat (`POST /chat`)
An interactive RAG-enabled endpoint that allows me to query the system about specific threats or general security patterns.

**Request Body:**
```json
{
  "message": "Why was the last DDoS attack flagged as high risk?"
}
```

---

### 3. Red Team Battleground (`POST /api/v1/red-team/battle`)
Triggers an autonomous adversarial loop where AI agents attempt to bypass the IDS.

**Parameters:**
*   `iterations`: Number of rounds to simulate (Max 5).

---

### 4. Health & Status
*   `GET /health`: Basic connectivity and model status check.
*   `GET /status`: Detailed component check (ML, Agent, persistence layers).
*   `GET /api/v1/alerts`: Returns the historical log of detected incidents.

---

## 🛡️ Security Implementation

I've implemented several layers of protection to ensure the API remains resilient:
*   **Rate Limiting**: Integrated `Flask-Limiter` to protect the LLM backend from token-drain attacks.
*   **Schema Enforcement**: Used `Pydantic` for strict data validation at the edge.
*   **CORS Locking**: Only my React dashboard origin is allowed to communicate with the API.
*   **Authentication**: Internal requests are verified via a 256-bit API key.

---

## 📊 Performance Baselines

Based on my empirical testing on an M2 machine:
*   **ML Prediction**: < 50ms
*   **Full Agentic Pipeline**: ~800ms - 1500ms (dependent on LLM latency)
*   **Geo-Location Lookup**: Non-blocking (async)
*   **Concurrent Support**: Handled via Flask's threaded WSGI server.
