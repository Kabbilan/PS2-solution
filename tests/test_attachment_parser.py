from gmail_service.attachment_parser import extract_attachments


def test_extract_single_attachment():
    payload = {
        "mimeType": "multipart/mixed",
        "parts": [
            {
                "mimeType": "application/pdf",
                "filename": "invoice.pdf",
                "body": {
                    "attachmentId": "ATT001",
                    "size": 18234,
                },
            }
        ],
    }

    attachments = extract_attachments(payload)

    assert len(attachments) == 1

    assert attachments[0]["filename"] == "invoice.pdf"
    assert attachments[0]["mime_type"] == "application/pdf"
    assert attachments[0]["size"] == 18234
    assert attachments[0]["attachment_id"] == "ATT001"


def test_extract_multiple_attachments():
    payload = {
        "mimeType": "multipart/mixed",
        "parts": [
            {
                "mimeType": "application/pdf",
                "filename": "invoice.pdf",
                "body": {
                    "attachmentId": "ATT001",
                    "size": 1000,
                },
            },
            {
                "mimeType": "application/octet-stream",
                "filename": "invoice.pdf.exe",
                "body": {
                    "attachmentId": "ATT002",
                    "size": 2000,
                },
            },
        ],
    }

    attachments = extract_attachments(payload)

    assert len(attachments) == 2

    filenames = [
        attachment["filename"]
        for attachment in attachments
    ]

    assert "invoice.pdf" in filenames
    assert "invoice.pdf.exe" in filenames


def test_nested_attachment():
    payload = {
        "mimeType": "multipart/mixed",
        "parts": [
            {
                "mimeType": "multipart/alternative",
                "parts": [
                    {
                        "mimeType": "application/pdf",
                        "filename": "document.pdf",
                        "body": {
                            "attachmentId": "ATT003",
                            "size": 5000,
                        },
                    }
                ],
            }
        ],
    }

    attachments = extract_attachments(payload)

    assert len(attachments) == 1
    assert attachments[0]["filename"] == "document.pdf"


def test_no_attachments():
    payload = {
        "mimeType": "text/plain",
        "body": {
            "data": "hello"
        },
    }

    attachments = extract_attachments(payload)

    assert attachments == []
