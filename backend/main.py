from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.database import (
    create_employee,
    create_organization,
    create_vendor,
    fetch_analysis,
    fetch_email,
    fetch_emails,
    fetch_employees,
    fetch_organizations,
    fetch_threats,
    fetch_vendors,
    initialize_database,
    save_analysis,
    save_email,
    save_incident_report,
    update_email_status,
)

from backend.schemas import (
    AnalysisResult,
    EmailInput,
    EmployeeInput,
    OrganizationInput,
    VendorInput,
)

from detection.analyzer import analyze_email
from intelligence.campaign import detect_campaign


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="PhishGuard API",
    version="0.5.0",
    description="Evidence-based phishing email investigation API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "name": "PhishGuard API",
        "status": "running",
        "database": "Supabase",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "database": "connected",
    }


@app.get("/emails")
def get_emails():
    return fetch_emails()


@app.get("/emails/{email_id}")
def get_email(email_id: str):
    email = fetch_email(email_id)

    if not email:
        raise HTTPException(
            status_code=404,
            detail="Email not found",
        )

    return email


@app.post("/analyze", response_model=AnalysisResult)
def analyze(email: EmailInput):
    result = analyze_email(email.model_dump())

    save_email(email)

    all_emails = fetch_emails()
    campaign = detect_campaign(all_emails)

    if campaign:
        result["campaign_id"] = campaign["campaign_id"]

    save_analysis(result)

    return result


@app.get("/threats")
def get_threats():
    return fetch_threats()


@app.get("/campaigns")
def get_campaigns():
    all_emails = fetch_emails()
    campaign = detect_campaign(all_emails)

    if campaign:
        return [campaign]

    return []


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
        raise HTTPException(
            status_code=404,
            detail="Email not found",
        )

    if not analysis:
        raise HTTPException(
            status_code=404,
            detail="Analysis result not found",
        )

    score = analysis["risk_score"]

    if score >= 70:
        action = (
            "Quarantine the email, block the sender domain, "
            "and notify the security team."
        )
    elif score >= 40:
        action = (
            "Do not open links or attachments. "
            "Review the email and sender before taking action."
        )
    else:
        action = (
            "No immediate action required. "
            "Continue normal monitoring."
        )

    report = {
        "email_id": email_id,
        "verdict": analysis["verdict"],
        "risk_score": score,
        "evidence": analysis["reasons"],
        "indicators_of_compromise": {
            "sender": email["sender"],
            "urls": email["urls"],
            "attachments": email["attachments"],
        },
        "recommended_action": action,
    }

    save_incident_report(report)

    return report


@app.post("/quarantine/{email_id}")
def quarantine(email_id: str):
    email = fetch_email(email_id)

    if not email:
        raise HTTPException(
            status_code=404,
            detail="Email not found",
        )

    update_email_status(
        email_id,
        "QUARANTINED",
    )

    return {
        "email_id": email_id,
        "status": "quarantined",
    }