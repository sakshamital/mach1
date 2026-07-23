# Your Sentinel v8.0

Free AI-powered scam detection for every Indian citizen.

## Quick start (local)

```powershell
cd your-sentinel
.\run.ps1
```

Or manually:

```powershell
cd your-sentinel\backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Open **http://localhost:8000**

## API keys (optional)

Copy `.env` and set keys for full AI power:

| Key | Purpose |
|-----|---------|
| `GEMINI_API_KEY` | Vision + deep text (AI 2) |
| `GROQ_API_KEY` | Police complaint generator (AI 4) |
| `HUGGINGFACE_API_KEY` | Indic-BERT classifier (AI 1) |
| `GOOGLE_SAFE_BROWSING_KEY` | URL threats (AI 3) |
| `VIRUSTOTAL_KEY` | URL threats (AI 3) |
| `DATABASE_URL` | PostgreSQL (persistence) |

Without keys, local behaviour engine + pattern fallbacks still work.

## PostgreSQL

```bash
psql $DATABASE_URL -f backend/database/migrations.sql
```

Or let the app auto-apply schema on startup when `DATABASE_URL` is set.

## Deploy (Render)

1. Connect repo to Render
2. Use included `render.yaml`
3. Add API keys in Render dashboard → Environment
4. Open the deployed URL

## Helpline

**1930** — National Cyber Crime Helpline | [cybercrime.gov.in](https://cybercrime.gov.in)
