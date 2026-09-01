from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.database import initialize_database, save_analysis, save_email
from backend.schemas import AnalysisResult, EmailInput
from detection.risk_engine import analyze_email


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="PhishGuard API",
    version="0.1.0",
    description="Evidence-based phishing email investigation API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

emails: dict[str, EmailInput] = {}
results: dict[str, dict] = {}


@app.get("/")
def root():
    return {"name": "PhishGuard API", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/emails")
def get_emails():
    return list(emails.values())


@app.get("/emails/{email_id}")
def get_email(email_id: str):
    if email_id not in emails:
        raise HTTPException(status_code=404, detail="Email not found")
    return emails[email_id]


@app.post("/analyze", response_model=AnalysisResult)
def analyze(email: EmailInput):
    result = analyze_email(email)
    emails[email.id] = email
    results[email.id] = result
    save_email(email)
    save_analysis(result)
    return result


@app.get("/threats")
def get_threats():
    return [
        result
        for result in results.values()
        if result["verdict"] in {"SUSPICIOUS", "HIGH_RISK"}
    ]


@app.get("/campaigns")
def get_campaigns():
    return []


@app.get("/organization")
def get_organization():
    return {"company_name": "", "official_domain": "", "employees": []}


@app.post("/quarantine/{email_id}")
def quarantine(email_id: str):
    if email_id not in emails:
        raise HTTPException(status_code=404, detail="Email not found")
    return {"email_id": email_id, "status": "quarantined"}
