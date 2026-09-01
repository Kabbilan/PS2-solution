from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from gmail_service.gmail_service import get_emails as fetch_gmail_emails, get_gmail_service, get_message
from gmail_service.email_parser import parse_gmail_message
from backend.database import (
    create_employee, create_organization, create_vendor, fetch_analysis, fetch_email,
    fetch_emails, fetch_employees, fetch_organizations, fetch_threats, fetch_vendors,
    initialize_database, save_analysis, save_email, save_incident_report, update_email_status,
)
from backend.schemas import AnalysisResult, EmailInput, EmployeeInput, OrganizationInput, VendorInput
from detection.analyzer import analyze_email
from intelligence.campaign import detect_campaign


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="PhishGuard API", version="0.7.0", description="Evidence-based phishing email investigation API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5500", "http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"name": "PhishGuard API", "status": "running", "database": "Supabase"}


@app.get("/health")
def health():
    return {"status": "healthy", "database": "connected"}


def build_email(parsed):
    return EmailInput(
        id=parsed["id"], sender=parsed["sender"], recipient=parsed["recipient"],
        subject=parsed["subject"], body=parsed["body"], urls=parsed["urls"],
        attachments=parsed["attachments"], headers=parsed["headers"],
    )


def analyze_and_save(email):
    result = analyze_email(email.model_dump())
    save_email(email)
    campaign = detect_campaign(fetch_emails())
    if campaign:
        result["campaign_id"] = campaign["campaign_id"]
    save_analysis(result)
    return result


@app.get("/emails")
def get_emails():
    try:
        return [parse_gmail_message(raw) for raw in fetch_gmail_emails(5)]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gmail connection failed: {exc}") from exc


@app.get("/gmail/fetch")
def fetch_from_gmail():
    try:
        raw_emails = fetch_gmail_emails(5)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gmail connection failed: {exc}") from exc
    results = []
    for raw in raw_emails:
        email = build_email(parse_gmail_message(raw))
        result = analyze_and_save(email)
        results.append({"email": email.model_dump(), "analysis": result})
    return results


@app.get("/emails/{email_id}")
def get_email(email_id: str):
    email = fetch_email(email_id)
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    return email


@app.post("/analyze", response_model=AnalysisResult)
def analyze(email: EmailInput):
    return analyze_and_save(email)


@app.post("/analyze-gmail/{email_id}", response_model=AnalysisResult)
def analyze_gmail(email_id: str):
    try:
        service = get_gmail_service()
        raw = get_message(service, email_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to fetch Gmail message: {exc}") from exc
    return analyze_and_save(build_email(parse_gmail_message(raw)))


@app.get("/threats")
def get_threats():
    return fetch_threats()


@app.get("/campaigns")
def get_campaigns():
    campaign = detect_campaign(fetch_emails())
    return [campaign] if campaign else []


@app.post("/organization")
def add_organization(organization: OrganizationInput):
    return create_organization(organization)


@app.get("/organization")
def get_organization():
    return fetch_organizations()


@app.post("/employees")
def add_employee(employee: EmployeeInput):
    return create_employee(employee)


@app.get("/employees")
def get_employees():
    return fetch_employees()


@app.post("/vendors")
def add_vendor(vendor: VendorInput):
    return create_vendor(vendor)


@app.get("/vendors")
def get_vendors():
    return fetch_vendors()


@app.get("/report/{email_id}")
def generate_report(email_id: str):
    email = fetch_email(email_id)
    analysis = fetch_analysis(email_id)
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis result not found")
    score = analysis["risk_score"]
    if score >= 70:
        action = "Quarantine the email, block the sender domain, and notify the security team."
    elif score >= 40:
        action = "Do not open links or attachments. Review the email and sender before taking action."
    else:
        action = "No immediate action required. Continue normal monitoring."
    report = {
        "email_id": email_id, "verdict": analysis["verdict"], "risk_score": score,
        "evidence": analysis["reasons"],
        "indicators_of_compromise": {"sender": email["sender"], "urls": email["urls"], "attachments": email["attachments"]},
        "recommended_action": action,
    }
    save_incident_report(report)
    return report


@app.post("/quarantine/{email_id}")
def quarantine(email_id: str):
    if not fetch_email(email_id):
        raise HTTPException(status_code=404, detail="Email not found")
    update_email_status(email_id, "QUARANTINED")
    return {"email_id": email_id, "status": "quarantined"}
