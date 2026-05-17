# Deploying the Agentic IDS (Render + Vercel)

This repository is configured for deployment using Render (backend) and Vercel (frontend) only. All Docker, docker-compose, and alternative hosting instructions were removed to keep the docs focused.

Summary:
- Backend: Render.com (Web Service)
- Frontend: Vercel (React/Vite)

## Quick Render (Backend) steps
1. Sign in to https://render.com and create a new **Web Service** connected to this GitHub repo.
2. Use these build / start commands in Render:

```bash
# Build step (Render will run this automatically)
pip install -r requirements.txt

# Start command (set as the start command in Render)
gunicorn --bind 0.0.0.0:$PORT 'src.app:app'
```

3. Add the required environment variables in the Render dashboard:
- `GROQ_API_KEY` — your GROQ LLM key
- `ABUSEIPDB_API_KEY` — AbuseIPDB key
- `INTERNAL_API_KEY` — a random secret for internal auth
- `FLASK_PORT` (optional) — default Render provides `$PORT`

4. Deploy. Render will provide a public URL like `https://<your-service>.onrender.com`.

Notes: the free tier may sleep after inactivity (short cold starts). This is the simplest recommended path.

## Quick Vercel (Frontend) steps
1. Sign in to https://vercel.com and import the frontend project from this repo (select the `frontend/` folder).
2. Set build command (Vercel usually detects this): `npm run build` and output dir: `dist`.
3. Add environment variable in Vercel: `VITE_API_URL=https://<your-render-url>`
4. Deploy. Vercel will build and publish the static frontend.

## Notes and Config
- We removed `frontend/Dockerfile` to keep the workflow simple (Render + Vercel).
- Keep your trained models either committed to `models/` or hosted in an object store and referenced by the app.

Environment variables to set on Render:
- `GROQ_API_KEY`
- `ABUSEIPDB_API_KEY`
- `INTERNAL_API_KEY`

Generate a secure `INTERNAL_API_KEY` locally:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Troubleshooting
- If the frontend cannot reach the backend: ensure `VITE_API_URL` is the exact Render URL (including `https://`).
- If GROQ calls fail: ensure `GROQ_API_KEY` is present and valid on Render.
- If AbuseIPDB calls hit limits: reputation checks will be skipped gracefully; system falls back to heuristics.

## What I changed
- Removed references to Docker, docker-compose, Cloudflare Tunnel, and DigitalOcean hosting options to keep instructions targeted.
- Deleted `frontend/Dockerfile` from the repo as requested.

If you'd like, I can also add a minimal `render.yaml` for automatic Render setup or create a short CI job to deploy on push — tell me which and I'll add it.
