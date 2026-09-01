from backend.schemas import EmailInput


def analyze_email(email: EmailInput) -> dict:
    score = 0
    reasons = []
    combined_text = f"{email.subject} {email.body}".lower()

    urgency_terms = ["urgent", "immediately", "suspended", "act now", "verify now"]
    credential_terms = ["password", "otp", "login", "verify your account"]

    if any(term in combined_text for term in urgency_terms):
        score += 20
        reasons.append("Urgency language detected")

    if any(term in combined_text for term in credential_terms):
        score += 25
        reasons.append("Credential or account verification request detected")

    if any(url.lower().startswith("http://") for url in email.urls):
        score += 20
        reasons.append("Unencrypted HTTP link detected")

    if email.urls:
        sender_domain = email.sender.split("@")[-1].lower()
        if any(sender_domain not in url.lower() for url in email.urls):
            score += 20
            reasons.append("Sender domain and link domain may not match")

    score = min(score, 100)
    verdict = "HIGH_RISK" if score >= 70 else "SUSPICIOUS" if score >= 40 else "SAFE"

    return {
        "email_id": email.id,
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "impersonation": None,
        "campaign_id": None,
    }
