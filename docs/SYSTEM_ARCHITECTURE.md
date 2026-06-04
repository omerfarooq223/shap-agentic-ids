# System Architecture: SHAP-Explained Agentic IDS

I have designed this system as a multi-layered security platform that moves beyond traditional signature-based detection. The architecture integrates high-speed machine learning with an autonomous reasoning loop and a proactive adversarial testing framework.

---

## 🏗️ High-Level System Design

The system is organized into four core functional blocks:

### 1. The Ingestion Engine (Live Capture & Streaming)
I use **Scapy** for real-time packet sniffing on specified network interfaces.
*   **Flow Extraction**: Packets are grouped into 5-tuples (Src IP, Dst IP, Src Port, Dst Port, Protocol) and processed into 78 statistical features (reduced to 12).
*   **Streaming API**: A thread-safe queue-based pipeline that feeds processed flows into the detection engine without blocking the capture process. Features a **dynamic queue-depth load shedding** mechanism (bypassing expensive LLM calls if queue exceeds 2000 items) to prevent total system collapse under heavy DDOS.

### 2. The Detection & Explanation Core
This is the "brain" of the system where raw data becomes security intelligence.
*   **ML Detection**: A Random Forest classifier trained on the CICIDS2017 dataset. I've optimized this model to handle severe class imbalance using SMOTE.
*   **SHAP Explainer**: If a flow is flagged, the system immediately runs a SHAP TreeExplainer. This provides the mathematical proof (feature attribution) for why the model made its decision.

### 3. The LangGraph Agentic Pipeline
This is where the system "reasons" about the findings. I built this using **LangGraph** to ensure a structured, state-aware decision loop:
*   **Observe**: Parses the SHAP data into a human-readable context.
*   **Verify**: Queries **AbuseIPDB** for real-time IP reputation and maps the threat to **MITRE ATT&CK** tactics.
*   **Hypothesize**: Uses **Llama-3.3-70B** to synthesize the ML math and external intel into a threat classification.
*   **Self-Correction**: A conflict resolution node that restarts the reasoning if the LLM's guess contradicts the SHAP evidence.

### 4. RAG-Enabled Forensic Chat
The dashboard **AI Analyst** uses retrieval-augmented generation on `POST /chat`:
*   **Retrieve:** TF-IDF search over `data/knowledge/` (MITRE mappings, threat patterns, evaluation benchmarks, hybrid IDS comparison, project overview, system pipeline) and live alert records.
*   **Augment:** Top-ranked passages are injected into the Llama-3.3-70B system prompt.
*   **Generate:** The model answers analyst questions grounded in retrieved context (not free-form hallucination).

### 5. Adversarial Red Teaming (Self-Hardening)
To ensure the system isn't easily bypassed, I implemented an autonomous Red Teaming framework:
*   **Attacker Agent**: Generates adversarial flows to find "blind spots" in the IDS.
*   **Critic Agent**: Analyzes why an attack succeeded or failed and provides feedback to the Attacker.
*   **Defender Hardening**: I use these battle results to harden the Defender's prompt logic and risk scoring.

---

## 🔄 Data Flow: From Packet to Action

```mermaid
flowchart LR
    Packet[Raw Packet] --> Capture[Scapy Sniffer]
    Capture --> ML[Random Forest]
    ML -->|Anomalous| SHAP[SHAP Attribution]
    SHAP --> Agent[LangGraph Pipeline]
    Agent -->|Verifies| Intel[AbuseIPDB]
    Agent -->|Concludes| Output[Alert Dashboard]
    Output --> Voice[Voice Assistant]
```

---

## 🛠️ Tech Stack & Dependencies

*   **Backend**: Flask (Python 3.11)
*   **AI/ML**: Scikit-Learn, SHAP, LangGraph, Groq (Llama-3.3-70B)
*   **Networking**: Scapy
*   **Frontend**: React, Vite, Three.js (Threat Globe), Lucide Icons
*   **Voice**: Web Speech API & macOS `say` subprocess
*   **Production serving**: `wsgi.py` + `gunicorn -c gunicorn.conf.py` (development uses `run_flask.py`)

---

## 🔐 API Access Model

The Flask app gates privileged routes with a shared `require_auth` decorator:

1. **Browser (SOC dashboard):** Analyst enters `INTERNAL_API_KEY` once; `POST /api/v1/auth/login` sets an HttpOnly session. Subsequent `fetch` calls use `credentials: 'include'`.
2. **Automation / tests:** Send `X-API-KEY: <INTERNAL_API_KEY>`.
3. **Public probes:** `GET /health`, `GET /status`, `GET /api/metrics/benchmarks` remain open for monitoring.

At startup, `validate_runtime_config()` fails fast in production if `INTERNAL_API_KEY`, `FRONTEND_ORIGIN`, or CORS policy is invalid. Inference loads `models/model_metadata.json` to verify the feature schema matches the trained Random Forest.

See [API.md](API.md) for endpoint-level detail.

---

## 📈 Performance Characteristics & Boundaries

My goal was to balance deep reasoning with operational speed:
*   **ML Latency**: ~50ms (Ideal for high-throughput filtering)
*   **Agent Latency**: ~1.2s (Acceptable for forensic deep-dives, bypassed via Graceful Degradation under severe load)
*   **Resource Usage**: Optimized to run on consumer hardware (M2 Air) by leveraging external API inference.
*   **Out-of-Scope Payloads**: 12-feature flow statistics cannot read packet data contents. Deeply embedded payloads (RCE, SQLi, malware text) are purposefully ignored in v1 format, relying strictly on heuristic flow geometry for detection. Future enhancements will involve multimodal DPI payload injection into the LLM.
