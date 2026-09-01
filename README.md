# PhishGuard — PS2 Solution

Evidence-based phishing email investigation platform.

## Team modules

- `backend/` — FastAPI APIs, database, and integration (Member 1)
- `frontend/` — Dashboard and investigation UI (Member 5)
- `detection/` — Phishing rules and risk engine (Member 3)
- `intelligence/` — Organization impersonation and campaigns (Member 4)
- `data/` — Mock emails for development and demo
- `gmail_service/` — Gmail fetch and parsing (Member 2)

## Quick start

```bash
python -m venv .venv
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000/docs`.

## Core API contract

Email input:

```json
{
  "id": "email_001",
  "sender": "security@paypa1-login.com",
  "recipient": "user@company.com",
  "subject": "Your account will be suspended!",
  "body": "Verify your account immediately",
  "urls": ["http://paypa1-login.com/verify"],
  "attachments": [],
  "headers": {}
}
```

Analysis output:

```json
{
  "email_id": "email_001",
  "risk_score": 94,
  "verdict": "HIGH_RISK",
  "reasons": [],
  "impersonation": null,
  "campaign_id": null
}
```
