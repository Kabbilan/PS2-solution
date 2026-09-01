from __future__ import annotations

from typing import Any

from detection.analyzer import analyze_email
from gmail_service.email_parser import normalize_email, parse_gmail_message
from gmail_service.gmail_service import (
    get_gmail_service,
    get_message,
    get_recent_messages,
)


def analyze_gmail_message(
    service: Any,
    message_id: str,
) -> dict[str, Any]:
    """
    Fetch one Gmail message, normalize it, and analyze it
    using the PhishGuard detection engine.
    """

    raw_message = get_message(service, message_id)

    parsed_email = parse_gmail_message(raw_message)

    normalized_email = normalize_email(parsed_email)

    return analyze_email(normalized_email.model_dump())


def analyze_recent_gmail_messages(
    max_results: int = 10,
) -> list[dict[str, Any]]:
    """
    Fetch recent Gmail messages and run them through
    the PhishGuard detection engine.
    """

    service = get_gmail_service()

    messages = get_recent_messages(
        service,
        max_results=max_results,
    )

    results: list[dict[str, Any]] = []

    for message in messages:
        message_id = message.get("id")

        if not message_id:
            continue

        result = analyze_gmail_message(
            service,
            message_id,
        )

        results.append(result)

    return results