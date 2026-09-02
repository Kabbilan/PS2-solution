from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from gmail_service.gmail_service import get_emails as fetch_gmail_emails, get_gmail_service, get_message
from gmail_service.email_parser import parse_gmail_message
from gmail_service.oauth import FRONTEND_URL, create_authorization_url, delete_session, exchange_authorization_code
from backend.database import (
    create_employee, create_organization, create_vendor, fetch_analysis, fetch_email,
    fetch_emails, fetch_employees, fetch_organizations, fetch_threats, fetch_vendors,
    initialize_database, save_analysis, save_email, save_incident_report, update_email_status,
)
from backend.schemas import AnalysisResult, EmailInput, EmployeeInput, OrganizationInput, VendorInput
from detection.analyzer import analyze_email
from detection.modules.urls import analyze_urls
from detection.schemas import NormalizedEmail
from intelligence.campaign import detect_campaign


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="PhishGuard API", version="0.9.0", description="Evidence-based phishing email investigation API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5500", "http://127.0.0.1:5500", "https://ps2solution.vercel.app"],
    allow_origin_regex=r"https://ps2solution(?:-[a-z0-9-]+)?\.vercel\.app",
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


@app.get("/auth/google")
def google_auth():
    try:
        url, _ = create_authorization_url()
        return RedirectResponse(url)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Google OAuth configuration failed: {exc}") from exc


@app.get("/auth/google/callback")
def google_auth_callback(code: str = Query(...), state: str = Query(...)):
    try:
        session_id = exchange_authorization_code(code, state)
        return RedirectResponse(f"{FRONTEND_URL}/#google_session={session_id}")
    except Exception as exc:
        return RedirectResponse(f"{FRONTEND_URL}/#google_error={str(exc)}")


@app.post("/auth/logout")
def google_logout(x_session_id: str | None = Header(default=None)):
    if x_session_id:
        delete_session(x_session_id)
    return {"status": "logged_out"}


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


def build_gmail_date_query(from_date: str | None, to_date: str | None) -> str | None:
    if not from_date and not to_date:
        return None
    if not from_date or not to_date:
        raise HTTPException(status_code=400, detail="Both from_date and to_date are required.")
    try:
        start = datetime.strptime(from_date, "%Y-%m-%d").date()
        end = datetime.strptime(to_date, "%Y-%m-%d").date()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Dates must use YYYY-MM-DD format.") from exc
    today = date.today()
    if start > end:
        raise HTTPException(status_code=400, detail="from_date cannot be later than to_date.")
    if start > today or end > today:
        raise HTTPException(status_code=400, detail="Date range cannot include future dates.")
    inclusive_end = end + timedelta(days=1)
    return f"after:{start:%Y/%m/%d} before:{inclusive_end:%Y/%m/%d}"


@app.get("/scan-url")
def scan_url(url: str = Query(..., min_length=3)):
    try:
        email = NormalizedEmail.from_dict({
            "id": "url_xray",
            "sender": "scanner@phishguard.local",
            "recipient": "analyst@phishguard.local",
            "subject": "URL X-Ray",
            "body": url,
            "urls": [url],
            "attachments": [],
            "headers": {},
        })
        result = analyze_urls(email)
        score = int(round(result.score))
        verdict = "HIGH_RISK" if score >= 70 else "SUSPICIOUS" if score >= 40 else "SAFE"
        reasons = result.reasons or ["No suspicious URL indicators detected"]
        return {
            "url": url,
            "risk_score": score,
            "verdict": verdict,
            "reasons": reasons,
            "metadata": result.metadata,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"URL scan failed: {exc}") from exc


@app.get("/emails")
def get_emails(x_session_id: str | None = Header(default=None)):
    try:
        return [parse_gmail_message(raw) for raw in fetch_gmail_emails(20, x_session_id)]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gmail connection failed: {exc}") from exc


@app.get("/gmail/fetch")
def fetch_from_gmail(
    max_results: int | None = Query(default=None, ge=1, le=500),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    x_session_id: str | None = Header(default=None),
):
    query = build_gmail_date_query(from_date, to_date)
    result_limit = max_results if max_results is not None else (100 if query else 20)
    try:
        raw_emails = fetch_gmail_emails(result_limit, x_session_id, query=query)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gmail connection failed: {exc}") from exc

    results = []
    for raw in raw_emails:
        email = build_email(parse_gmail_message(raw))
        result = analyze_email(email.model_dump())
        save_email(email)
        save_analysis(result)
        results.append({"email": email.model_dump(), "analysis": result})

    campaign = detect_campaign(fetch_emails())
    if campaign:
        for item in results:
            item["analysis"]["campaign_id"] = campaign["campaign_id"]
            save_analysis(item["analysis"])

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
def analyze_gmail(email_id: str, x_session_id: str | None = Header(default=None)):
    try:
        service = get_gmail_service(x_session_id)
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
        "email_id": email_id,
        "verdict": analysis["verdict"],
        "risk_score": score,
        "evidence": analysis["reasons"],
        "email_details": {
            "sender": email.get("sender", ""),
            "recipient": email.get("recipient", ""),
            "subject": email.get("subject", ""),
            "body": email.get("body", ""),
        },
        "indicators_of_compromise": {
            "sender": email.get("sender", ""),
            "urls": email.get("urls", []),
            "attachments": email.get("attachments", []),
        },
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
