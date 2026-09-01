from unittest.mock import Mock, patch

from gmail_service.gmail_detection import (
    analyze_gmail_message,
    analyze_recent_gmail_messages,
)


def test_analyze_gmail_message():
    service = Mock()

    service.users().messages().get().execute.return_value = {
        "id": "gmail_001",
        "threadId": "thread_001",
        "payload": {
            "mimeType": "text/plain",
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
            ],
            "body": {
                "data": (
                    "Verify your account immediately: "
                    "http://paypa1-login.com/verify"
                )
            },
        },
    }

    result = analyze_gmail_message(
        service,
        "gmail_001",
    )

    assert result["email_id"] == "gmail_001"
    assert 0 <= result["risk_score"] <= 100
    assert result["verdict"] in {
        "SAFE",
        "SUSPICIOUS",
        "HIGH_RISK",
    }
    assert isinstance(result["reasons"], list)


@patch("gmail_service.gmail_detection.get_gmail_service")
@patch("gmail_service.gmail_detection.get_recent_messages")
@patch("gmail_service.gmail_detection.get_message")
def test_analyze_recent_gmail_messages(
    mock_get_message,
    mock_get_recent_messages,
    mock_get_gmail_service,
):
    service = Mock()

    mock_get_gmail_service.return_value = service

    mock_get_recent_messages.return_value = [
        {"id": "gmail_001"},
        {"id": "gmail_002"},
    ]

    mock_get_message.side_effect = [
        {
            "id": "gmail_001",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {
                        "name": "From",
                        "value": "security@example.com",
                    },
                    {
                        "name": "To",
                        "value": "employee@company.com",
                    },
                    {
                        "name": "Subject",
                        "value": "Meeting update",
                    },
                ],
                "body": {
                    "data": "Please review the meeting schedule."
                },
            },
        },
        {
            "id": "gmail_002",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {
                        "name": "From",
                        "value": "security@paypa1-login.com",
                    },
                    {
                        "name": "To",
                        "value": "employee@company.com",
                    },
                    {
                        "name": "Subject",
                        "value": "Urgent account verification",
                    },
                ],
                "body": {
                    "data": (
                        "Verify your account immediately: "
                        "http://paypa1-login.com/verify"
                    )
                },
            },
        },
    ]

    results = analyze_recent_gmail_messages(
        max_results=2,
    )

    assert len(results) == 2
    assert results[0]["email_id"] == "gmail_001"
    assert results[1]["email_id"] == "gmail_002"

    mock_get_gmail_service.assert_called_once()
    mock_get_recent_messages.assert_called_once_with(
        service,
        max_results=2,
    )