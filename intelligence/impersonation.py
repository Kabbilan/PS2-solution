from backend.schemas import EmailInput
from backend.database import get_supabase


def check_impersonation(email: EmailInput) -> dict | None:
    sender = email.sender.lower()

    if "@" not in sender:
        return None

    sender_domain = sender.split("@")[-1]

    display_name = str(
        email.headers.get("display_name", "")
    ).lower()

    reply_to = str(
        email.headers.get("reply_to", "")
    ).lower()

    subject = email.subject.lower()
    body = email.body.lower()

    # EMPLOYEE CHECK
    employees = (
        get_supabase()
        .table("employees")
        .select("*")
        .execute()
        .data
    )

    for employee in employees:
        name = employee["name"].lower()
        official_email = employee["official_email"].lower()
        official_domain = official_email.split("@")[-1]

        claimed = (
            name in sender
            or name in display_name
            or name in subject
            or name in body
        )

        sender_mismatch = sender_domain != official_domain

        reply_mismatch = (
            bool(reply_to)
            and "@" in reply_to
            and reply_to.split("@")[-1] != official_domain
        )

        if claimed and (sender_mismatch or reply_mismatch):
            reasons = []

            if name in display_name:
                reasons.append("Employee name found in display name")

            if name in subject:
                reasons.append("Employee name found in subject")

            if name in body:
                reasons.append("Employee name found in body")

            if sender_mismatch:
                reasons.append(
                    "Sender domain does not match official domain"
                )

            if reply_mismatch:
                reasons.append(
                    "Reply-To domain does not match official domain"
                )

            return {
                "detected": True,
                "type": f"{employee['role']}_IMPERSONATION",
                "claimed_identity": employee["name"],
                "actual_sender": email.sender,
                "expected_domain": official_domain,
                "actual_domain": sender_domain,
                "confidence": 0.95,
                "reasons": reasons,
            }

    # VENDOR CHECK
    vendors = (
        get_supabase()
        .table("trusted_vendors")
        .select("*")
        .execute()
        .data
    )

    for vendor in vendors:
        vendor_name = vendor["vendor_name"].lower()
        official_domain = vendor["official_domain"].lower()

        claimed = (
            vendor_name in sender
            or vendor_name in display_name
            or vendor_name in subject
            or vendor_name in body
        )

        sender_mismatch = sender_domain != official_domain

        reply_mismatch = (
            bool(reply_to)
            and "@" in reply_to
            and reply_to.split("@")[-1] != official_domain
        )

        if claimed and (sender_mismatch or reply_mismatch):
            reasons = []

            if vendor_name in display_name:
                reasons.append("Vendor name found in display name")

            if vendor_name in subject:
                reasons.append("Vendor name found in subject")

            if vendor_name in body:
                reasons.append("Vendor name found in body")

            if sender_mismatch:
                reasons.append(
                    "Sender domain does not match official vendor domain"
                )

            if reply_mismatch:
                reasons.append(
                    "Reply-To domain does not match official vendor domain"
                )

            return {
                "detected": True,
                "type": "VENDOR_IMPERSONATION",
                "claimed_identity": vendor["vendor_name"],
                "actual_sender": email.sender,
                "expected_domain": official_domain,
                "actual_domain": sender_domain,
                "confidence": 0.90,
                "reasons": reasons,
            }

    return None