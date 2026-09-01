from backend.schemas import EmailInput


def check_impersonation(email: EmailInput) -> dict | None:
    sender = email.sender.lower()

    if "@" not in sender:
        return None

    sender_domain = sender.split("@")[-1]

    # Temporary test data
    employees = [
        {
            "name": "arun",
            "role": "CEO",
            "official_email": "arun@abc.com"
        },
        {
            "name": "priya",
            "role": "HR",
            "official_email": "priya@abc.com"
        },
        {
            "name": "kumar",
            "role": "CFO",
            "official_email": "kumar@abc.com"
        }
    ]

    for employee in employees:
        name = employee["name"]
        official_email = employee["official_email"]
        official_domain = official_email.split("@")[-1]

        if name in sender and sender_domain != official_domain:
            return {
                "type": f"{employee['role']}_IMPERSONATION",
                "employee": employee["name"],
                "expected_domain": official_domain,
                "actual_domain": sender_domain
            }

    return None
