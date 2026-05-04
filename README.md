# SHAP-Explained Agentic IDS

An Agent-Based Network Intrusion Detection System (IDS) that combines Machine Learning (Random Forest), SHAP explainability, and Agentic Reasoning (LangGraph + GROQ) to detect and explain network anomalies.

## Project Structure
- `PROJECT_PROPOSAL_FINAL.md`: Detailed project proposal.
- `LITERATURE_REVIEW.md`: Review of current state-of-the-art and research gaps.
- `SYSTEM_DESIGN.md`: Technical architecture and implementation plan.

## Core Features
1. **Detection Layer**: Random Forest classifier trained on CICIDS2017 with SMOTE balancing.
2. **Explainability Layer**: SHAP analysis to identify key features contributing to alerts.
3. **Reasoning Layer**: LangGraph-powered agent that verifies threats using AbuseIPDB and generates natural language explanations via GROQ LLM.

## Setup
(Details will be added during the Prototype phase in Weeks 7-9)
