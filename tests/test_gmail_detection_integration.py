from gmail_service.email_parser import parse_gmail_message, normalize_email
from detection.analyzer import analyze_email


def test_gmail_email_flows_into_detection_engine():
    raw_gmail_message = {
        "id": "gmail_test_001",
        "threadId": "thread_test_001",
        "payload": {
            "headers": [
                {
                    "name": "From",
                    "value": "PayPal Security <security@paypa1-login.com>",
                },
                {
                    "name": "To",
                    "value": "employee@company.com",
                },
                {
                    "name": "Subject",
                    "value": "Your account will be suspended!",
                },
                {
                    "name": "Date",
                    "value": "Tue, 01 Sep 2026 01:55:26 -0700",
                },
            ],
            "mimeType": "text/plain",
            "body": {
                "data": (
                    "Your account will be suspended. "
                    "Verify your account immediately: "
                    "http://paypa1-login.com/verify"
                )
            },
        },
    }

    # M2: Gmail API message -> normalized email
    parsed = parse_gmail_message(raw_gmail_message)
    email = normalize_email(parsed)

    # M3: normalized email -> phishing detection engine
    result = analyze_email(email.model_dump())

    assert result["email_id"] == "gmail_test_001"
    assert result["verdict"] in {"SUSPICIOUS", "HIGH_RISK"}
    assert 0 <= result["risk_score"] <= 100
    assert result["reasons"]