# Agentic IDS — Backend API Specification

This document details the REST API architecture for the SHAP-Explained Agentic IDS. The backend is a modular Flask application that coordinates machine learning detection, mathematical explainability, and multi-agent reasoning.

---

## 🏗️ Technical Architecture

The API operates across four distinct logic layers:
1.  **Detection Layer**: High-speed Random Forest classifier (Scikit-Learn).
2.  **Explainability Layer**: SHAP (Shapley Additive exPlanations) for mathematical feature attribution.
3.  **Reasoning Layer**: LangGraph-driven autonomous agent utilizing Llama-3.3-70B via Groq.
4.  **Adversarial Layer**: Multi-agent Red Teaming (Attacker & Critic) for continuous stress testing.

**Default base URL (development):** `http://localhost:5005`

---

## 🔐 Authentication

Privileged endpoints require **either**:

| Method | Use case |
|--------|----------|
| **Session cookie** | Browser dashboard after `POST /api/v1/auth/login` with `{ "api_key": "<INTERNAL_API_KEY>" }`. Use `credentials: 'include'` on `fetch`. |
| **`X-API-KEY` header** | Scripts, curl, integration tests — value must match `INTERNAL_API_KEY`. Compared with `hmac.compare_digest`. |

Public (no auth): `GET /health`, `GET /status`, `GET /api/metrics/benchmarks`.

**Development:** If `INTERNAL_API_KEY` is unset and `ENVIRONMENT` is not `production`, a development-only default key is used (see `.env.example`).

**Production:** Set `ENVIRONMENT=production`, a 32+ character `INTERNAL_API_KEY`, `FRONTEND_ORIGIN`, and optionally `SESSION_SECRET_KEY` and `SESSION_COOKIE_SECURE=true` behind HTTPS.

### Auth endpoints

#### `GET /api/v1/auth/session`
Returns whether the current request is authorized.

```json
{ "authenticated": true }
```

#### `POST /api/v1/auth/login`
```json
{ "api_key": "your-internal-api-key" }
```
**Success:** `200` with `{ "authenticated": true }` and session cookie.  
**Failure:** `401`.

#### `POST /api/v1/auth/logout`
Clears the session. Returns `{ "authenticated": false }`.

---

## 📡 Core Endpoints

### 1. Threat Detection (`POST /detect`)
Primary entry point for network traffic analysis.

**Security:** Session or `X-API-KEY`. Rate limited (`RATE_LIMIT_DETECT`). Strict Pydantic validation.

**Request body:** `flow` may use camelCase aliases (`src_ip`, `dst_port`) and/or CICIDS-style names (`Destination Port`, etc.). If `Destination Port` is omitted, `dst_port` is mapped automatically.

```json
{
  "flow": {
    "src_ip": "185.15.59.224",
    "dst_ip": "192.168.10.50",
    "dst_port": 80,
    "Destination Port": 80,
    "Flow Duration": 1200
  }
}
```

**Response highlights:** `anomaly`, `risk_score`, `shap_explanation`, `agent_reasoning`.

---

### 2. Forensic Chat (`POST /chat`)
RAG-enabled SOC assistant (Llama-3.3-70B via Groq).

**Retrieval:** TF-IDF over `data/knowledge/` plus live alerts from `AlertRepository`.

**Request:**
```json
{ "message": "Why was the last DDoS attack flagged as high risk?" }
```

**Response (success):**
```json
{
  "response": "...",
  "timestamp": "2026-05-19 14:30:00",
  "rag_sources": [
    { "source": "threat_patterns.md", "score": 0.42 },
    { "source": "alert:1716123456789", "score": 0.31 }
  ]
}
```

---

### 3. Alerts (`GET /api/v1/alerts`)
Historical incident buffer. Requires session or `X-API-KEY`.

---

### 4. Red Team Battleground (`POST /api/v1/red-team/battle`)
Autonomous adversarial loop. Body: `{ "iterations": 3 }` (max 5). Requires auth.

---

### 5. Streaming capture (`/stream/*`)
Live packet pipeline (see [PACKET_CAPTURE_GUIDE.md](PACKET_CAPTURE_GUIDE.md)).

| Route | Method | Auth |
|-------|--------|------|
| `/stream/start` | POST | Yes |
| `/stream/stop` | POST | Yes |
| `/stream/status` | GET | Yes |
| `/stream/stats` | GET | Yes |

---

### 6. Health & status
| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /health` | No | Connectivity and model readiness |
| `GET /status` | No | Component-level status |
| `GET /api/metrics/benchmarks` | No | Forensic lab comparison metrics |

---

### 7. Test & voice helpers (development)
- `POST /api/test/malicious`, `POST /api/test/stress` — dashboard simulators (auth required).
- `POST /api/v1/voice/persona`, `POST /api/v1/voice/toggle` — voice assistant settings (auth required).

---

## 🛡️ Security Implementation

- **Rate limiting:** `Flask-Limiter` per route class (detect, chat, health, test).
- **Schema enforcement:** Pydantic models in `src/schemas.py`; model feature list validated against `models/model_metadata.json` at inference load time.
- **CORS:** Locked to `FRONTEND_ORIGIN` (defaults to `http://localhost:5173` in development).
- **Sessions:** HttpOnly, `SameSite=Lax`, `Secure` when `SESSION_COOKIE_SECURE=true`.

---

## 📊 Performance Baselines

On Apple M2-class hardware (indicative):
- **ML prediction:** &lt; 50 ms
- **Full agentic pipeline:** ~800–1500 ms (Groq latency)
- **Production serving:** `gunicorn -c gunicorn.conf.py` via `wsgi:application`
