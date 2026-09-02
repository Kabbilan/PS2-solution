from __future__ import annotations

from typing import Any

from googleapiclient.discovery import Resource, build

from gmail_service.oauth import get_gmail_credentials, get_session_credentials


def get_gmail_service(session_id: str | None = None) -> Resource:
    credentials = get_session_credentials(session_id) if session_id else get_gmail_credentials()
    return build("gmail", "v1", credentials=credentials)


def get_recent_messages(
    service: Resource,
    max_results: int = 50,
    query: str | None = None,
) -> list[dict[str, Any]]:
    request = {"userId": "me", "maxResults": max_results}
    if query:
        request["q"] = query
    response = service.users().messages().list(**request).execute()
    return response.get("messages", [])


def get_message(service: Resource, message_id: str) -> dict[str, Any]:
    return service.users().messages().get(userId="me", id=message_id, format="full").execute()


def get_emails(
    max_results: int = 5,
    session_id: str | None = None,
    query: str | None = None,
) -> list[dict[str, Any]]:
    service = get_gmail_service(session_id)
    messages = get_recent_messages(service, max_results=max_results, query=query)
    return [get_message(service, message["id"]) for message in messages]
