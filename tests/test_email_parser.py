from gmail_service.email_parser import parse_gmail_message


def test_parse_gmail_message():
    message = {
        "id": "email_001",
        "threadId": "thread_001",
        "payload": {
            "headers": [
                {
                    "name": "From",
                    "value": "Arun <arun@abc.com>",
                },
                {
                    "name": "To",
                    "value": "employee@abc.com",
                },
                {
                    "name": "Subject",
                    "value": "Urgent Payment Required",
                },
                {
                    "name": "Date",
                    "value": "Mon, 1 Sep 2026 10:30:00 +0530",
                },
            ],
            "mimeType": "text/plain",
            "body": {
                "data": (
                    "UGxlYXNlIHByb2Nlc3MgdGhlIHBheW1lbnQu"
                )
            },
        },
    }

    result = parse_gmail_message(message)

    assert result["id"] == "email_001"
    assert result["thread_id"] == "thread_001"

    assert result["sender_name"] == "Arun"
    assert result["sender_email"] == "arun@abc.com"

    assert result["recipient"] == "employee@abc.com"
    assert result["subject"] == "Urgent Payment Required"

    assert result["body"] == "Please process the payment."

    assert result["urls"] == []
    assert result["attachments"] == []


def test_parser_extracts_urls():
    message = {
        "id": "email_002",
        "payload": {
            "headers": [
                {
                    "name": "From",
                    "value": "Attacker <attacker@fake.com>",
                },
                {
                    "name": "To",
                    "value": "user@company.com",
                },
                {
                    "name": "Subject",
                    "value": "Verify Account",
                },
            ],
            "mimeType": "text/plain",
            "body": {
                "data": (
                    "Q2xpY2sgaHR0cHM6Ly9mYWtlLWxvZ2luLmNvbQ=="
                )
            },
        },
    }

    result = parse_gmail_message(message)

    assert result["urls"] == [
        "https://fake-login.com"
    ]


def test_parser_extracts_attachments():
    message = {
        "id": "email_003",
        "payload": {
            "headers": [
                {
                    "name": "From",
                    "value": "Attacker <attacker@fake.com>",
                }
            ],
            "mimeType": "multipart/mixed",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {
                        "data": "SGVsbG8="
                    },
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "invoice.pdf",
                    "body": {
                        "attachmentId": "ATT001",
                        "size": 5000,
                    },
                },
            ],
        },
    }

    result = parse_gmail_message(message)

    assert len(result["attachments"]) == 1

    assert result["attachments"][0]["filename"] == (
        "invoice.pdf"
    )

    assert result["attachments"][0]["attachment_id"] == (
        "ATT001"
    )
