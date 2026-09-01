from __future__ import annotations

import base64
from email.utils import parseaddr
from typing import Any

from backend.schemas import EmailInput
from gmail_service.attachment_parser import extract_attachments
from gmail_service.url_extractor import extract_urls


def decode_base64url(data: str) -> str:
    """Decode Gmail's URL-safe base64 encoded content."""

    if not data:
        return ""

    padding = "=" * (-len(data) % 4)

    try:
        decoded = base64.urlsafe_b64decode(data + padding)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_headers(
    headers: list[dict[str, str]],
) -> dict[str, str]:
    """Convert Gmail header list into a simple dictionary."""

    result: dict[str, str] = {}

    for header in headers:
        name = header.get("name", "").strip()
        value = header.get("value", "").strip()

        if name:
            result[name] = value

    return result


def get_header(
    headers: dict[str, str],
    name: str,
) -> str:
    """Retrieve a header case-insensitively."""

    target = name.lower()

    for key, value in headers.items():
        if key.lower() == target:
            return value

    return ""


def extract_sender(sender: str) -> dict[str, str]:
    """Separate display name and email address."""

    display_name, email_address = parseaddr(sender)

    return {
        "display_name": display_name,
        "email": email_address,
    }


def parse_gmail_message(
    message: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert a Gmail API message into our standard email format.

    This is the main entry point for M2.
    """

    payload = message.get("payload", {})

    headers = extract_headers(
        payload.get("headers", [])
    )

    sender = get_header(headers, "From")
    recipient = get_header(headers, "To")
    subject = get_header(headers, "Subject")
    date = get_header(headers, "Date")
    reply_to = get_header(headers, "Reply-To")

    sender_info = extract_sender(sender)

    body = extract_body(payload)

    is_html = contains_html(payload)

    urls = extract_urls(
        body,
        is_html=is_html,
    )

    attachments = extract_attachments(payload)

    return {
        "id": message.get("id", ""),
        "thread_id": message.get("threadId", ""),
        "sender": sender,
        "sender_name": sender_info["display_name"],
        "sender_email": sender_info["email"],
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "urls": urls,
        "attachments": attachments,
        "headers": headers,
        "reply_to": reply_to,
        "date": date,
    }


def extract_body(
    payload: dict[str, Any],
) -> str:
    """Extract readable text from Gmail message payload."""

    body_data = payload.get("body", {}).get("data")

    if body_data:
        return decode_base64url(body_data)

    parts = payload.get("parts", [])

    plain_text = ""
    html_text = ""

    for part in parts:
        part_mime = part.get("mimeType", "")
        part_body = part.get("body", {}).get("data")

        if part_body:
            decoded = decode_base64url(part_body)

            if part_mime == "text/plain":
                plain_text = decoded

            elif part_mime == "text/html":
                html_text = decoded

        elif part_mime.startswith("multipart/"):
            nested_body = extract_body(part)

            if nested_body:
                plain_text = nested_body

    if plain_text:
        return plain_text

    if html_text:
        return html_to_text(html_text)

    return ""


def contains_html(
    payload: dict[str, Any],
) -> bool:
    """Determine whether the Gmail payload contains HTML content."""

    mime_type = payload.get("mimeType", "")

    if mime_type == "text/html":
        return True

    for part in payload.get("parts", []):
        if contains_html(part):
            return True

    return False


def html_to_text(html: str) -> str:
    """Convert HTML email content into readable plain text."""

    from bs4 import BeautifulSoup

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    return soup.get_text(
        separator=" ",
        strip=True,
    )


def normalize_email(raw_email: dict[str, Any]) -> EmailInput:
    """Validate and normalize parsed email data using the shared API schema."""

    return EmailInput(**raw_email)