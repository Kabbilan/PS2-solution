"""
Main entry point for the PhishGuard Phishing Detection Engine.
Orchestrates input validation, sub-module execution, scoring, and output formatting.
"""

from typing import Any, Dict
from detection.schemas import NormalizedEmail
from detection.modules.sender_domain import analyze_sender_domain
from detection.modules.urls import analyze_urls
from detection.modules.content import analyze_content
from detection.modules.auth import analyze_auth
from detection.modules.attachments import analyze_attachments
from detection.scorer import calculate_risk


def analyze_email(email_json: Any) -> Dict[str, Any]:
    """
    Analyzes an email payload for phishing indicators and returns a standardized risk report.

    Parameters:
        email_json (dict): Dictionary adhering to the common input schema:
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

    Returns:
        dict: Standardized output dictionary adhering to the frozen team schema:
            {
                "email_id": "email_001",
                "risk_score": 94,
                "verdict": "HIGH_RISK",
                "reasons": ["Look-alike domain", "Urgency language", "Suspicious URL"],
                "impersonation": None,
                "campaign_id": None
            }
    """
    try:
        # 1. Normalize and sanitize input safely
        email = NormalizedEmail.from_dict(email_json)

        # 2. Run all specialized static sub-analyzers
        res_sender_domain = analyze_sender_domain(email)
        res_urls = analyze_urls(email)
        res_content = analyze_content(email)
        res_auth = analyze_auth(email)
        res_attachments = analyze_attachments(email)

        # 3. Aggregate results and calculate deterministic risk score
        results = [
            res_sender_domain,
            res_urls,
            res_content,
            res_auth,
            res_attachments,
        ]

        output = calculate_risk(email_id=email.id, results=results)
        return output.to_dict()

    except Exception:
        # Absolute safety fallback: an analysis failure must NEVER be reported as SAFE
        fallback_id = "unknown_id"
        if isinstance(email_json, dict) and email_json.get("id") is not None:
            fallback_id = str(email_json["id"])

        return {
            "email_id": fallback_id,
            "risk_score": 50,
            "verdict": "SUSPICIOUS",
            "reasons": ["Analysis failure: unexpected exception during inspection - manual review required"],
            "impersonation": None,
            "campaign_id": None,
        }
