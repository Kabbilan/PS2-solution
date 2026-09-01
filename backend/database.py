import os

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

_client: Client | None = None


def get_supabase() -> Client:
    global _client

    if _client is not None:
        return _client

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")

    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")

    _client = create_client(url, key)
    return _client


def initialize_database():
    get_supabase().table("emails").select("id").limit(1).execute()


def save_email(email):
    data = email.model_dump()
    return get_supabase().table("emails").upsert(data).execute()


def save_analysis(result):
    return get_supabase().table("analysis_results").upsert({
        "email_id": result["email_id"],
        "risk_score": result["risk_score"],
        "verdict": result["verdict"],
        "reasons": result["reasons"],
        "impersonation": result["impersonation"],
        "campaign_id": result["campaign_id"]
    }, on_conflict="email_id").execute()


def fetch_emails():
    return (
        get_supabase()
        .table("emails")
        .select("*")
        .order("created_at", desc=True)
        .execute()
        .data
    )


def fetch_email(email_id: str):
    return (
        get_supabase()
        .table("emails")
        .select("*")
        .eq("id", email_id)
        .maybe_single()
        .execute()
        .data
    )


def fetch_analysis(email_id: str):
    return (
        get_supabase()
        .table("analysis_results")
        .select("*")
        .eq("email_id", email_id)
        .maybe_single()
        .execute()
        .data
    )


def fetch_threats():
    return (
        get_supabase()
        .table("analysis_results")
        .select("*")
        .in_("verdict", ["SUSPICIOUS", "HIGH_RISK"])
        .order("risk_score", desc=True)
        .execute()
        .data
    )


def create_organization(organization):
    return (
        get_supabase()
        .table("organizations")
        .insert(organization.model_dump())
        .execute()
        .data[0]
    )


def fetch_organizations():
    return (
        get_supabase()
        .table("organizations")
        .select("*, employees(*), trusted_vendors(*)")
        .order("created_at", desc=True)
        .execute()
        .data
    )


def create_employee(employee):
    return (
        get_supabase()
        .table("employees")
        .insert(employee.model_dump())
        .execute()
        .data[0]
    )


def fetch_employees():
    return (
        get_supabase()
        .table("employees")
        .select("*")
        .order("id")
        .execute()
        .data
    )


def create_vendor(vendor):
    return (
        get_supabase()
        .table("trusted_vendors")
        .insert(vendor.model_dump())
        .execute()
        .data[0]
    )


def fetch_vendors():
    return (
        get_supabase()
        .table("trusted_vendors")
        .select("*")
        .order("id")
        .execute()
        .data
    )


def save_incident_report(report: dict):
    return get_supabase().table("incident_reports").insert({
        "email_id": report["email_id"],
        "verdict": report["verdict"],
        "evidence": report["evidence"],
        "indicators_of_compromise": report["indicators_of_compromise"],
        "recommended_action": report["recommended_action"]
    }).execute()


def update_email_status(email_id: str, status: str):
    return (
        get_supabase()
        .table("emails")
        .update({"status": status})
        .eq("id", email_id)
        .execute()
    )
