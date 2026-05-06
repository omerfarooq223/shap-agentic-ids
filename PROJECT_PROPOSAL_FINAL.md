# PROJECT PROPOSAL: SHAP-EXPLAINED AGENTIC INTRUSION DETECTION SYSTEM

**Student:** Muhammad Umar Farooq
**Roll Number:** F20233763310  
**Course:** AI-374 | Information Security  
**Date:** Week 2

---

## 1. Problem

Network intrusion detection systems (Snort, Suricata) generate thousands of alerts. The problem isn't quantity—it's quality. Analysts don't understand *why* a flow triggered an alert. Manual investigation costs 40+ hours per analyst per week.

We need a system that:
1. **Detects** network anomalies accurately
2. **Explains** which features triggered the alert (not just "92% malicious")
3. **Verifies** the alert by checking external threat intelligence

> "Flagged: High entropy (8.9) + SSH port (22) + rapid connections. Similar to 200+ attacks in training data. AbuseIPDB reports source IP as brute-force attacker. Risk: 8.5/10. Recommended action: Block source IP."

This provides actionable intelligence for security analysts.

---

## 2. What I'm Building

**Three-Layer System:**

1. **Detection Layer** (Random Forest Classifier)
   - Train on CICIDS2017 with SMOTE class balancing
   - Detect anomalies: benign vs. attack
   - Output: anomaly flag + confidence

2. **Explainability Layer** (SHAP Analysis)
   - Which 3-5 features triggered the alert?
   - Quantify each feature's contribution
   - Example: "Port=22 contributed +0.35, Entropy=8.9 contributed +0.30, Duration=3s contributed -0.05"

3. **Agentic Reasoning Layer** (LangGraph + GROQ)
   - Agent observes flagged flow
   - Calls GROQ LLM: "What attack type is this?"
   - Calls threat intelligence API: "Is source IP known malicious?"
   - Synthesizes results into risk score + recommendation

---

## 3. Why This Approach

**vs. Standard ML-IDS:** We add SHAP. Most IDS stop at predictions. SHAP provides *verified explanations* tied directly to model logic.

**vs. LLM-Only IDS:** We don't trust LLM alone. LLMs hallucinate. We use LLM only to *narrate* SHAP results and threat intel findings.

**vs. Signature-Based (Snort):** Our system learns attack patterns from data. Snort uses hand-coded rules. We focus on explaining what the machine learning model learned.

---

## 4. Technology Stack

| Component | Tool | Why |
|-----------|------|-----|
| **Language** | Python 3.11 | Standard for ML/security |
| **ML Framework** | Scikit-learn | Fast, no GPU needed, works on M2 Air |
| **Class Balancing** | SMOTE (imbalanced-learn) | Proven effective on imbalanced datasets (Ahmed et al., 2022) |
| **Explainability** | SHAP (shap library) | Industry-standard feature attribution |
| **Agent Framework** | LangGraph | Structured agent loops with state management |
| **LLM API** | GROQ | Fast inference (~50ms), free tier (100K tokens/day) |
| **Threat Intelligence** | AbuseIPDB API (free tier) | IP reputation lookups |
| **Web API** | Flask (with Server-Sent Events) | Streaming API for real-time telemetry |
| **Dashboard** | React (Vite) | Premium, highly interactive frontend SOC dashboard |
| **Database** | SQLite | Logged detections + explanations |
| **Dataset (Train)** | CICIDS2017 | 2.8M flows, 14 attack types, ground truth |
| **Dataset (Test)** | UNSW-NB15 | Cross-dataset validation (different network, different attacks) |
| **Packet Capture** | Scapy | Live network interface sniffing |
| **Hybrid Evaluation**| Snort / Hybrid Comparison | Evaluated against traditional signature-based IDS |

**All free. All work on M2 Air.**

---

## 5. Critical Design Decisions

### 5.1 Class Imbalance: SMOTE + Class Weights

CICIDS2017: 99% benign, 1% attack. Without correction, RF predicts "benign" for everything.

**Solution:**
```python
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier

# Oversample minority class
smote = SMOTE(random_state=42)
X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)

# Train with class weights as fallback
rf = RandomForestClassifier(
    class_weight='balanced',  # Penalize misclassifying attacks
    n_estimators=100,
    random_state=42
)
rf.fit(X_train_balanced, y_train_balanced)
```

**Expected improvement:** Detection rate (Recall) from ~78% → 94%+

---

### 5.2 Agent Design: Tool Use, Not Just LLM Calls

**Naive Approach:**
```
Observe flow → Ask LLM "Is this an attack?" → Return LLM response
```
LLM guesses. No verification. Hallucination risk.

**Our Approach:**
```
1. OBSERVE: Extract flow features + get SHAP explanation
   → "High entropy=8.9, Port=22, Duration=3s"

2. HYPOTHESIZE: Ask GROQ LLM (with structured prompt)
   → "Based on these features, this looks like SSH brute-force"

3. VERIFY: Agent calls external APIs
   → AbuseIPDB API: Check if source IP is known attacker
   → MITRE ATT&CK lookup: Confirm this matches T1110 (brute-force)

4. SYNTHESIZE: Combine findings
   → Risk score = (RF confidence 0.92) + (LLM classification match 0.8) + (IP reputation hit 0.9)
   → Final risk = 8.5/10
   → Recommendation: "Block source IP for 24 hours"
```

This agentic workflow follows: observe → hypothesize → **verify with tools** → conclude.

---

### 5.3 GROQ Token Budget Analysis

**Concern:** CICIDS2017 has 2.8M flows. GROQ free tier: 100K tokens/day.

**Reality Check:**
- Only flag ~1% of flows as anomalies = 28,000 flows
- SHAP explanation (cached, no tokens needed)
- LLM explanation per flow: ~400 tokens
- Total tokens needed: 28,000 × 400 = **11.2M tokens**
- Free tier: 100K tokens/day = **lasts 5.6 hours**

**Solution:** 
1. **Sampling:** Test on 10% of CICIDS2017 (280K flows) = 2,800 anomalies = 1.1M tokens/day
2. **Fallback:** Use local Ollama (Mistral 7B) for unlimited inference (no token limits)
3. **Batch mode:** Process flows in batches overnight, not real-time
4. **Caching:** Store explanations in SQLite; don't re-explain identical flows

**System Scope:** While the system utilizes streaming APIs for real-time telemetry, it is fundamentally designed as a proof-of-concept for targeted SOC deployments, not high-throughput enterprise routing.

---

### 5.4 Cross-Dataset Evaluation

**Standard ML mistake:** Train on CICIDS2017, test on CICIDS2017 → RF "memorizes" attacks from 2017.

**Our approach:**
- **Train:** CICIDS2017 (2.8M flows)
- **Test:** UNSW-NB15 (1.4M flows, different network, different attack patterns)

This proves the model generalizes to unseen attack types.

**Expected challenge:** Generalization to novel networks typically results in slight performance degradation (e.g., 95% to 85%), which will be documented.

---

## 6. What I'll Deliver

**Weeks 7-9 (Prototype Phase):**
- Packet parser (load CICIDS2017 CSV)
- ML classifier trained with SMOTE (measure baseline performance)
- SHAP analysis on 100 sample flows (show which features matter)
- GitHub commits (meaningful, documented)

**Weeks 10-13 (Implementation Phase):**
- Full agent loop with LangGraph
- GROQ LLM integration (with system prompt designed to avoid hallucinations)
- AbuseIPDB API integration (threat intel lookup)
- Real-time Packet Capture (`scapy`) and Streaming API endpoints
- React/Vite Custom SOC Dashboard (real-time alerts + SHAP explanations + agent reasoning logs)
- Testing on UNSW-NB15 (cross-dataset evaluation)
- Hybrid Evaluation Framework (Benchmarking against Snort)
- Performance metrics: TPR, FPR, Precision, Recall on both datasets

**Week 14:**
- Final report (20 pages, IEEE format)
- Video demo (10 min): Load a suspicious flow → Show SHAP explanation → Show agent reasoning → Show risk score

**Viva:**
- Live demo of system
- Walk through one attack detection from raw data to explanation
- Honest discussion of limitations (not real-time, requires tool access, LLM-dependent)

---

## 7. Project Boundaries & Operational Scope

This project is designed as a **high-fidelity investigative IDS** rather than a high-throughput network gateway. We acknowledge the following operational boundaries:

*   **Inference Throughput:** Optimized for deep analysis (~1.5 flows/sec) rather than line-rate processing.
*   **External API Resilience:** Implements "Graceful Degradation" to handle AbuseIPDB or GROQ outages.
*   **Evaluation Rigor:** Utilizes a Feature Translation Layer for cross-dataset validation (UNSW-NB15).
*   **Integrity:** Employs Cross-Signal Verification to mitigate LLM hallucinations.

> [!NOTE]
> For a comprehensive breakdown of performance metrics, PPS ingestion limits, and feature mapping tables, refer to **Section 8 (Technical Constraints & Project Boundaries)** in the `SYSTEM_DESIGN.md` document.

---

## 8. Timeline (Realistic)

| Phase | Weeks | Hours | Deliverable |
|-------|-------|-------|-------------|
| Proposal | 1-2 | 5 | Problem + objectives (DONE) |
| Lit Review | 3-4 | 10 | Papers + gap analysis (DONE) |
| Design | 5-6 | 10 | Architecture + threat model (DONE) |
| **Prototype** | **7-9** | **30** | **50% working, GitHub commits** |
| **Implementation** | **10-13** | **40** | **Full system, testing, video** |
| Report | 14 | 15 | Final 20-page document |
| Viva Prep | 15 | 10 | Q&A practice |
| **TOTAL** | | **120 hours** | |

**Feasibility:** 120 hours ÷ 6 weeks = 20 hours/week. Realistic with AI assistance (Copilot for boilerplate, GROQ for LLM calls).

---

## 9. Alignment with Evaluation Rubric

| Rubric | Our Approach | Score Potential |
|--------|--------------|-----------------|
| **Innovation** | SHAP + Agent + Tool Use = novel combination not in literature | 10/10 |
| **Security depth** | STRIDE threat model + prompt injection defense + agentic reasoning | 10/10 |
| **Evaluation rigor** | Cross-dataset testing (CICIDS + UNSW), not just held-out test set | 10/10 |
| **Explainability** | SHAP (verified), not just LLM narrative (unreliable) | 10/10 |
| **Honesty** | Acknowledge limitations (not real-time, proof-of-concept, token limits) | 9/10 |
| **Code quality** | Clean, documented, GitHub commits, reproducible | 9/10 |

---

## 10. Academic Integrity

I will:
- Use LLMs (GROQ, Copilot) for code assistance but retain intellectual understanding
- Cite all external code, datasets, papers (IEEE format)
- Not use pre-made IDS; build from first principles
- Follow UMT's academic integrity policy

---

**Signature:** ________________________  
**Date:** ________________________

---
