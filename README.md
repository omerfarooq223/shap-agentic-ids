
# 🛡️ SHAP-Explained Agentic IDS

### *Transforming Network Security with Explainable AI & Agentic Reasoning*

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=flat&logo=react&logoColor=61DAFB)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)
![Agentic](https://img.shields.io/badge/Agentic-LangGraph-orange?style=flat)
![RedTeaming](https://img.shields.io/badge/Red_Teaming-Autonomous-red?style=flat)
![XAI](https://img.shields.io/badge/Explainable_AI-SHAP-blueviolet?style=flat)
![Security](https://img.shields.io/badge/Security-Hardened-success?style=flat)

## 📖 Overview
This project implements a **Hybrid Intrusion Detection System (IDS)** designed for modern Security Operations Centers (SOC). It bridges the gap between high-performance "black-box" machine learning and actionable human-readable security analysis. 

The system leverages **Random Forest** classification for high-speed detection, **SHAP** (SHapley Additive exPlanations) for transparency, and a **LangGraph-driven Agent** for intelligent verification and contextualization. Unlike traditional systems that only flag threats, this platform explains *why* a flow was flagged and provides remediation steps based on live threat intelligence.

**New in v2.5:** Integrated **Autonomous Red Teaming Framework** where AI agents (Attacker & Critic) continuously stress-test the Defender to find and fix "stealthy" bypass vulnerabilities.

---

## 🏗️ System Architecture

The core logic follows a non-linear reasoning pipeline implemented with **LangGraph**:

```mermaid
flowchart TD
    A[Network Flow] --> B[ML Detection Engine]
    B --> C{Threat?}
    C -- No --> D[Log Benign]
    C -- Yes --> E[SHAP Explainer]
    E --> F[Agentic Reasoning Pipeline]
    
    subgraph "Agentic Reasoning (LangGraph)"
        F --> G[Observe: Contextualize Features]
        G --> H[Verify: External Threat Intel]
        H --> I[Hypothesize: LLM Analysis]
        I --> J[Conflict Resolution]
        J --> K[Conclude: Actionable Alert]
    end
    
    K --> L[SOC Dashboard]
    H <--> M[(AbuseIPDB API)]
    I <--> N[MITRE ATT&CK Mapping]
```

---

## 🚀 Key Features

*   **Explainable ML (XAI):** Integrated SHAP layer provides mathematical proof for every alert, mapping raw network features (entropy, ports, durations) to contribution scores.
*   **Agentic Self-Correction:** A LangGraph reasoning engine uses **Llama 3.3 (via Groq)** to verify ML outputs against live reputation data and resolves conflicts between model predictions and network logic.
*   **Autonomous Red Teaming:** A multi-agent adversarial framework where an **Attacker** generates payloads and a **Critic** analyzes defense logs to teach the attacker how to bypass the IDS, creating a continuous hardening loop.
*   **Live Threat Intelligence:** Automated IP reputation checks via **AbuseIPDB** and automated mapping to **MITRE ATT&CK** tactics and techniques.
*   **Real Packet Capture & Streaming API:** Native Scapy-based sniffer (`packet_capture.py`) for live interface capture, coupled with a highly concurrent REST Streaming API (`streaming_api.py`) for continuous line-rate packet analysis.
*   **Real Snort/Suricata Comparison:** Integrated side-by-side behavioral forensic lab (`snort_comparison.py`) to benchmark the LLM Agent against traditional signature-based rules (addresses Tier S requirement).
*   **Real-time SOC Dashboard:** A premium React-based interface featuring a 3D threat globe, live forensic chat, and high-density telemetry.
*   **Voice-Driven Security Assistant:** Integrated audible alert system using both backend (macOS `say`) and frontend (Web Speech API) synthesis to provide hands-free threat reporting for SOC analysts.

---

## 🛠️ Installation & Setup

### 1. Requirements
- **Python 3.11+**
- **Node.js 18+** (for frontend)
- **API Keys:** Groq (for LLM) and AbuseIPDB (for threat intel)

### 2. Backend Setup
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your GROQ_API_KEY and ABUSEIPDB_API_KEY
```

### 3. Frontend Setup
```bash
cd frontend
npm install
```

---

## 🚦 Usage Guide

### 1. Data Preparation & Training
Before running the system, initialize the ML pipeline:
```bash
# Merge raw datasets (CICIDS2017)
python src/merge_data.py

# Train the Random Forest + SHAP Explainer
python src/train.py
```

### 2. Launching the System
```bash
# Start the Flask Backend (default port 5005)
python run_flask.py

# Start the React Dashboard (in a separate terminal)
cd frontend
npm run dev
```

### 3. Running Benchmarks
To generate the empirical data for the Forensic Lab:
```bash
python scripts/run_evaluation.py
```

### 4. Autonomous Red Teaming (Adversarial Battle)
To run the multi-agent battle (Attacker vs Defender):
```bash
# Run a 3-round battle to stress-test the IDS
python scripts/red_team_battle.py 3
```

---

## 📂 Project Structure

```text
IS Project/
├── src/                    # Core Backend Logic
│   ├── agent.py            # LangGraph Reasoning Engine for Threat Verification
│   ├── attacker.py         # Adversarial Agent for Red Teaming (New)
│   ├── critic.py           # Analysis Agent for Adversarial Feedback (New)
│   ├── app.py              # Flask API Application & REST Endpoints
│   ├── config.py           # Central System Settings & Environment Variables
│   ├── data_loader.py      # Feature Translation & Dataset Parsing
│   ├── evaluation_metrics.py# Model Accuracy and Testing Metrics Helper
│   ├── merge_data.py       # Utility for Merging CICIDS CSV Distributions
│   ├── packet_capture.py   # Live Scapy-based Network Sniffer & PCAP Extractor
│   ├── schemas.py          # Pydantic Schemas for Strict Data Validation
│   ├── snort_comparison.py # Real Snort/Suricata Rule Benchmarking Engine
│   ├── streaming_api.py    # Async Streaming API for Continuous Network Detection
│   ├── train.py            # Random Forest ML Training & SMOTE Pipeline
│   └── services/           # Decoupled Business Logic / Abstraction Layer
│       ├── geo_service.py  # Map IPs to Geolocation via APIs
│       ├── inference.py    # SHAP TreeExplainer & RF ML Prediction Engine
│       ├── persistence.py  # JSON Alert Logging & Data Persistence
│       └── voice_service.py # Audible Security Alert System (New)
├── frontend/               # React + Vite SOC Dashboard Website
│   ├── src/                # Frontend Application Code
│   │   ├── components/     # Reusable React UI Components
│   │   ├── utils/          # API Communication Handlers
│   │   ├── ThreatGlobe.jsx # 3D Three.js Live Attack Geolocation Map
│   │   ├── Analytics.jsx   # Reporting, Visualizations & Metrics Dashboard
│   │   └── App.jsx         # Main React App Core & Routing
│   └── package.json        # Frontend Dependencies & NPM Scripts
├── scripts/                # Research, Utilities & Report Scripts
│   ├── run_evaluation.py   # Cross-Dataset Benchmarking & Model Scorer
│   ├── red_team_battle.py  # Autonomous Adversarial Loop Engine (New)
│   └── dashboard.py        # Streamlit Backup Dashboard
├── tests/                  # Pytest Unit & Integration Testing Suite
│   ├── test_flask_api.py   # System API Endpoint Checks
│   ├── test_agent_steps.py # Tests for LangGraph Node Functionalities
│   └── test_integration_e2e.py # End-to-End full system logic tests
├── data/                   # Datasets (CICIDS2017 & UNSW-NB15)
├── models/                 # Serialized Pickle Models (`rf_model.pkl`, `scaler.pkl`)
├── docs/                   # Full Technical Reporting & Academic Documentation
│   ├── API.md              # REST API Interface Spec Details
│   ├── SYSTEM_ARCHITECTURE.md # Architecture Blueprints
│   └── FINAL_COMPREHENSIVE_REPORT.md # Academic Grading Project Report
├── logs/                   # System Threat & Error Runtime Logging Outputs
├── QUICK_START.md          # Easy Step-by-Step Setup Guide
├── run_flask.py            # Core Entry Point script to boot backend application
└── requirements.txt        # Python Backend Dependencies File
```

---

## 🛡️ Security & Hardening
- **API Security:** All endpoints are protected by a 256-bit `INTERNAL_API_KEY`.
- **Rate Limiting:** Enforced via `Flask-Limiter` to prevent DoS attacks on the LLM reasoning engine.
- **Input Validation:** Strict Pydantic schemas enforce type-safety and feature range validation.
- **CORS Protection:** Origin-locked configuration to prevent unauthorized cross-site requests.

---

**Developed by:** Muhammad Umar Farooq  
**Academic Context:** AI-374 Information Security (2026)  
**License:** MIT
