from unittest.mock import MagicMock

from gmail_service.gmail_service import (
    get_recent_messages,
    get_message,
)

from gmail_service.email_parser import parse_gmail_message


def test_gmail_to_normalized_email():
    service = MagicMock()

    service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
        "messages": [
            {
                "id": "email_001",
                "threadId": "thread_001",
            }
        ]
    }

    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "id": "email_001",
        "threadId": "thread_001",
        "payload": {
            "headers": [
                {
                    "name": "From",
                    "value": "CEO <ceo@company.com>",
                },
                {
                    "name": "To",
                    "value": "employee@company.com",
                },
                {
                    "name": "Subject",
                    "value": "Important Update",
                },
            ],
            "body": {
                "data": "SGVsbG8gZnJvbSB0aGUgQ0VP",
            },
        },
    }

    messages = get_recent_messages(
        service,
        max_results=1,
    )

    raw_message = get_message(
        service,
        messages[0]["id"],
    )

    parsed = parse_gmail_message(raw_message)

    assert parsed["id"] == "email_001"
    assert parsed["thread_id"] == "thread_001"
    assert parsed["sender_email"] == "ceo@company.com"
    assert parsed["recipient"] == "employee@company.com"
    assert parsed["subject"] == "Important Update"
    assert parsed["body"] == "Hello from the CEO"

    assert isinstance(parsed["urls"], list)
    assert isinstance(parsed["attachments"], list)
    assert isinstance(parsed["headers"], dict)