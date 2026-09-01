from backend.schemas import EmailInput
from backend.database import get_supabase


def check_impersonation(email: EmailInput) -> dict | None:
    sender = email.sender.lower()

    if "@" not in sender:
        return None

    sender_domain = sender.split("@")[-1]

    # Check employees from Supabase
    employees = get_supabase().table("employees").select("*").execute().data

    for employee in employees:
        name = employee["name"].lower()
        official_email = employee["official_email"].lower()
        official_domain = official_email.split("@")[-1]

        if name in sender and sender_domain != official_domain:
            return {
                "detected": True,
                "type": f"{employee['role']}_IMPERSONATION",
                "claimed_identity": employee["name"],
                "actual_sender": email.sender,
                "expected_domain": official_domain,
                "actual_domain": sender_domain,
                "confidence": 0.95,
                "reasons": [
                    "Employee identity matched",
                    "Sender domain does not match official domain"
                ]
            }

    # Check trusted vendors from Supabase
    vendors = get_supabase().table("trusted_vendors").select("*").execute().data

    for vendor in vendors:
        vendor_name = vendor["vendor_name"].lower()
        official_domain = vendor["official_domain"].lower()

        if vendor_name in sender and sender_domain != official_domain:
            return {
                "detected": True,
                "type": "VENDOR_IMPERSONATION",
                "claimed_identity": vendor["vendor_name"],
                "actual_sender": email.sender,
                "expected_domain": official_domain,
                "actual_domain": sender_domain,
                "confidence": 0.90,
                "reasons": [
                    "Trusted vendor identity matched",
                    "Sender domain does not match official vendor domain"
                ]
            }

    return None