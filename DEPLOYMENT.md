# Deploying the Agentic IDS (Render + Vercel)

This repository targets **Render** (backend) and **Vercel** (frontend). Local development uses `python run_flask.py`; production uses **Gunicorn** and `wsgi.py`.

---

## Quick Render (Backend)

1. Sign in to [Render](https://render.com) and create a **Web Service** from this repo.
2. **Build command:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Start command:**
   ```bash
   gunicorn -c gunicorn.conf.py
   ```
   On Render, set **`FLASK_PORT`** to the service **`PORT`** (Render injects `PORT`; `gunicorn.conf.py` reads `FLASK_PORT` for the bind address).

4. **Required environment variables:**

| Variable | Notes |
|----------|--------|
| `ENVIRONMENT` | `production` (enforces security checks at startup) |
| `GROQ_API_KEY` | Groq LLM key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB key |
| `INTERNAL_API_KEY` | 32+ character secret; same value analysts enter in the dashboard unlock screen |
| `FRONTEND_ORIGIN` | Exact Vercel URL, e.g. `https://your-app.vercel.app` |
| `FLASK_PORT` | Match Render `$PORT` |
| `SESSION_SECRET_KEY` | Optional; defaults to `INTERNAL_API_KEY` if unset |
| `SESSION_COOKIE_SECURE` | Optional; defaults to `true` for HTTPS frontend origins |
| `SESSION_COOKIE_SAMESITE` | Optional; defaults to `None` for HTTPS frontend origins |

Generate a strong `INTERNAL_API_KEY`:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

5. Deploy. Render provides a URL like `https://<your-service>.onrender.com`.

**Note:** Free tier may sleep after inactivity (cold starts).

---

## Quick Vercel (Frontend)

1. Import the repo on [Vercel](https://vercel.com), root directory **`frontend/`**.
2. **Build:** `npm run build` — **Output:** `dist`.
3. **Environment variable:**
   - `VITE_API_URL=https://<your-render-url>` (no trailing path; must match `https://`)
4. Deploy.

The dashboard authenticates with `POST /api/v1/auth/login` using your `INTERNAL_API_KEY`. Do **not** put the API key in `VITE_*` variables (removed from `frontend/.env.example`).

Ensure Render `FRONTEND_ORIGIN` exactly matches the Vercel origin so CORS and session cookies work.

---

## Models

Commit trained artifacts under `models/` (`rf_model.pkl`, `scaler.pkl`, `shap_explainer.pkl`, `model_metadata.json`) or load them from object storage in your deploy pipeline.

---

## Troubleshooting

| Issue | Check |
|-------|--------|
| Frontend cannot reach API | `VITE_API_URL` is the Render HTTPS URL |
| Unlock screen returns after login | Redeploy backend; auth now uses a signed browser token plus deployment-safe cookies |
| CORS / login fails | `FRONTEND_ORIGIN` matches Vercel URL; if overriding cookies, use `SESSION_COOKIE_SAMESITE=None` with `SESSION_COOKIE_SECURE=true` |
| Startup crash in production | `validate_runtime_config()` — missing `INTERNAL_API_KEY`, `FRONTEND_ORIGIN`, or invalid CORS |
| GROQ errors | Valid `GROQ_API_KEY` on Render |
| AbuseIPDB limits | Reputation checks degrade gracefully |

---

## Local production smoke test

```bash
export ENVIRONMENT=production
export INTERNAL_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export FRONTEND_ORIGIN=http://localhost:5173
export FLASK_PORT=5005
gunicorn -c gunicorn.conf.py
```
