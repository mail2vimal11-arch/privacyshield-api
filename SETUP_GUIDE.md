# PrivacyShield API — Setup & Deployment Guide

## What we've built so far

| File | Purpose |
|------|---------|
| `schema.sql` | Full Supabase database (all 4 products) |
| `privacyshield-api/main.py` | FastAPI app entry point |
| `privacyshield-api/app/core/config.py` | Environment variable loader |
| `privacyshield-api/app/core/database.py` | Supabase connection |
| `privacyshield-api/app/core/auth.py` | API key authentication |
| `privacyshield-api/app/ai_models/scanner.py` | AI model scanner (ChatGPT, Claude, Gemini, Perplexity) |
| `privacyshield-api/app/ai_models/routes.py` | All /v1/ai-models/ endpoints |

---

## Step 1 — Upload code to GitHub

1. Go to **github.com** → click **New repository**
2. Name it `privacyshield-api` → click **Create repository**
3. Upload all files from the `privacyshield-api/` folder
   - Drag & drop the entire folder onto the GitHub page
   - Click **Commit changes**

> ⚠️ Do NOT upload the `.env` file — it contains secrets. Only upload `.env.example`.

---

## Step 2 — Deploy to Railway

1. Go to **railway.app** → **New Project** → **Deploy from GitHub repo**
2. Select your `privacyshield-api` repository
3. Railway will auto-detect it's a Python app and start building

### Set Environment Variables in Railway

In Railway → your project → **Variables** tab, add these one by one:

```
SUPABASE_URL          = https://your-project-id.supabase.co
SUPABASE_SERVICE_KEY  = your-service-role-key  ← From Supabase → Settings → API
OPENAI_API_KEY        = sk-...                 ← From platform.openai.com/api-keys
APP_ENV               = production
API_BASE_URL          = https://your-app.railway.app
APP_URL               = https://app.privacyshield.io
API_KEY_SECRET        = (generate: paste this into Railway terminal → python -c "import secrets; print(secrets.token_hex(32))")
```

4. Click **Deploy** — Railway will build and start your API
5. Copy the Railway URL (e.g. `https://privacyshield-api.railway.app`)

---

## Step 3 — Test the API

Open your browser and visit:

```
https://your-railway-url.railway.app/docs
```

This opens the **Swagger UI** — an interactive page where you can test every endpoint.

### Test 1 — Health check
```
GET /health
```
Should return: `{"status": "ok"}`

### Test 2 — Scan AI models (requires API key)
```
POST /v1/ai-models/scan
```

First, you'll need to create a customer + API key in Supabase:

1. In Supabase → **Table Editor** → `customers` → **Insert row**:
   - email: `your@email.com`
   - full_name: `Your Name`
   - plan: `professional`
   - monthly_scan_quota: `100`
   - monthly_scans_used: `0`

2. Get the customer's UUID from the row you just created

3. In `api_keys` table → **Insert row**:
   - customer_id: (paste the UUID)
   - key_hash: (we'll automate this — for now use test key)
   - key_prefix: `ps_live_test`
   - name: `Test Key`

4. Use the Swagger UI to test the scan endpoint

---

## Step 4 — Get your OpenAI API key

The scanner needs this to actually query ChatGPT.

1. Go to **platform.openai.com/api-keys**
2. Click **Create new secret key**
3. Copy it and add it to Railway as `OPENAI_API_KEY`

Without this key, the ChatGPT scanner will skip gracefully and return a "skipped" status.

---

## Current API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/docs` | Interactive API docs |
| POST | `/v1/ai-models/scan` | Scan AI models for personal data |
| POST | `/v1/ai-models/remove` | Submit GDPR removal requests |
| GET | `/v1/ai-models/requests/{id}` | Check removal status |
| POST | `/v1/ai-models/monitor` | Set up continuous monitoring |
| GET | `/v1/ai-models/supported` | List supported AI models |
| GET | `/v1/ai-models/shame-board` | Public vendor response stats |

---

## What's next (Day 3)

- Auto-generate GDPR letters (PDF)
- Email sending via SendGrid
- Shame dashboard page
- Customer signup + API key generation endpoint
