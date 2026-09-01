from __future__ import annotations

from typing import Any

from googleapiclient.discovery import Resource
from googleapiclient.discovery import build

from gmail_service.oauth import get_gmail_credentials


def get_gmail_service() -> Resource:
    """
    Create and return an authenticated Gmail API service.
    """

    credentials = get_gmail_credentials()

    return build(
        "gmail",
        "v1",
        credentials=credentials,
    )


def get_recent_messages(
    service: Resource,
    max_results: int = 50,
) -> list[dict[str, Any]]:
    """
    Fetch recent Gmail messages.

    Only message IDs and thread IDs are retrieved initially.
    Full message contents are fetched separately.
    """

    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            maxResults=max_results,
        )
        .execute()
    )

    return response.get("messages", [])


def get_message(
    service: Resource,
    message_id: str,
) -> dict[str, Any]:
    """
    Fetch a complete Gmail message by ID.
    """

    return (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full",
        )
        .execute()
    )


def get_emails(
    max_results: int = 5,
) -> list[dict[str, Any]]:
    """
    Fetch recent Gmail messages with their full contents.
    """

    service = get_gmail_service()

    messages = get_recent_messages(
        service,
        max_results=max_results,
    )

    emails = []

    for message in messages:
        email = get_message(
            service,
            message["id"],
        )

        emails.append(email)

    return emails