from backend.schemas import EmailInput


def normalize_email(raw_email: dict) -> EmailInput:
    return EmailInput(**raw_email)
