# Developer Guide: Extending the Agentic Pipeline

I've built the Agentic IDS using **LangGraph** to orchestrate the threat reasoning pipeline. This guide explains how you can extend the agent's capabilities by adding new reasoning nodes.

## Understanding the Current Architecture

The agent logic is defined in `src/agent.py` and consists of 5 main sequential steps:
1. `validate_step`: Validates flow structure and inputs.
2. `observe_step`: Extracts top SHAP features and summarizes the flow.
3. `hypothesize_step`: Calls the GROQ LLM (Llama-3.3-70B) to classify the threat type.
4. `verify_step`: Calls AbuseIPDB to verify IP reputation and maps to MITRE tactics.
5. `score_step`: Calculates the final Risk Score (0-10) and generates a recommendation.

## Extending the RAG Knowledge Base

Forensic chat retrieval lives in `src/services/rag_service.py`. Static playbooks are markdown files under `data/knowledge/` (chunked and indexed with TF-IDF). Live alerts from `AlertRepository` are indexed on each `/chat` request.

To add domain knowledge:
1. Add a `.md` file under `data/knowledge/` (use `##` headings for clean chunking).
2. Restart Flask (or call any endpoint that runs `initialize_system`) so the index rebuilds.
3. Tune `RAG_TOP_K` in `.env` if answers need more context.

## How to Add a New Agent Step

Suppose you want to add a new step: **`query_virustotal_step`** to check domains associated with the IP.

### 1. Update the AgentState
First, define where the new data will live in the `AgentState` `TypedDict` in `src/agent.py`:
```python
class AgentState(TypedDict):
    ...
    virustotal_intel: Dict[str, Any] # Add your new state variable
```

### 2. Create the Node Function
Create a new function that takes the `AgentState`, performs the logic, and returns the updated `AgentState`. All errors MUST be caught to prevent the pipeline from crashing.
```python
def query_virustotal_step(state: AgentState) -> AgentState:
    try:
        if state.get("error"):
            return state # Skip if previous steps failed
            
        src_ip = state.get("flow", {}).get("src_ip")
        # ... perform your API call ...
        vt_score = 50 # Example result
        
        state["virustotal_intel"] = {"score": vt_score}
        logger.info(f"[AGENT] VIRUSTOTAL: Score {vt_score}")
        
    except Exception as e:
        logger.error(f"[AGENT] VIRUSTOTAL Error: {e}")
        state["error"] = str(e)
        
    return state
```

### 3. Register the Node in the Graph
Update the `build_agent()` function to include your new node and wire the edges.
```python
def build_agent():
    graph = StateGraph(AgentState)
    
    # 1. Add the node
    graph.add_node("validate", validate_step)
    ...
    graph.add_node("verify", verify_step)
    graph.add_node("virustotal", query_virustotal_step) # ADDED
    graph.add_node("score", score_step)
    
    # 2. Update the edges
    graph.add_edge("hypothesize", "verify")
    graph.add_edge("verify", "virustotal") # MODIFIED
    graph.add_edge("virustotal", "score")  # MODIFIED
    
    ...
```

## Calling authenticated APIs locally

Privileged Flask routes require a session or `X-API-KEY`:

```bash
# Header-based (pytest, curl, scripts)
curl -X POST http://localhost:5005/detect \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: $INTERNAL_API_KEY" \
  -d '{"flow": {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 443}}'

# Session-based (browser flow)
curl -c cookies.txt -X POST http://localhost:5005/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"api_key\": \"$INTERNAL_API_KEY\"}"
curl -b cookies.txt http://localhost:5005/api/v1/alerts
```

Frontend tests mock `/api/v1/auth/session` in `frontend/src/tests/App.test.jsx`; run with `cd frontend && npm run test`.

---

## Troubleshooting Common Agent Issues

### 1. LLM Timeouts or API Errors
**Symptom**: `[AGENT] HYPOTHESIZE: API error... Retrying...`
**Fix**: The agent uses exponential backoff (`RETRY_BACKOFF`). If it fails completely after `MAX_RETRIES`, it defaults to `_fallback_threat_classification()`. Ensure your `GROQ_API_KEY` is valid and you haven't hit rate limits.

### 2. State Propagation Errors
**Symptom**: `KeyError` inside a step.
**Fix**: Always use `.get()` on the `state` dictionary (e.g., `state.get("threat_type", "anomaly")`) because earlier steps might have failed and thus didn't initialize the key.

### 3. Agent Execution Hangs
**Symptom**: The `/detect` API takes >15 seconds.
**Fix**: Ensure `API_TIMEOUT` in `src/agent.py` is respected in all your `requests.get()` and LLM calls. The current strict timeout is set to 10 seconds.
