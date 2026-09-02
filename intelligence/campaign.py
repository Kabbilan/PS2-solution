from difflib import SequenceMatcher


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, str(a or "").lower(), str(b or "").lower()).ratio()


def detect_campaign(analyzed_emails: list) -> dict | None:
    analyzed_emails = [email for email in (analyzed_emails or []) if isinstance(email, dict)]
    if len(analyzed_emails) < 2:
        return None

    for i in range(len(analyzed_emails)):
        for j in range(i + 1, len(analyzed_emails)):
            email1 = analyzed_emails[i]
            email2 = analyzed_emails[j]

            subject_score = similarity(email1.get("subject"), email2.get("subject"))
            body_score = similarity(email1.get("body"), email2.get("body"))

            urls1 = set(email1.get("urls") or [])
            urls2 = set(email2.get("urls") or [])
            url_match = bool(urls1.intersection(urls2))

            if subject_score >= 0.8 or body_score >= 0.8 or url_match:
                return {
                    "campaign_id": "CAMP-001",
                    "type": "PHISHING_CAMPAIGN",
                    "email_ids": [email1.get("id"), email2.get("id")],
                    "similarity": round(max(subject_score, body_score) * 100, 2),
                    "reason": "Related email content or URL indicators were correlated."
                }

    return None
