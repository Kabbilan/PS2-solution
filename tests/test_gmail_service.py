from unittest.mock import MagicMock

from gmail_service.gmail_service import (
    get_recent_messages,
    get_message,
)


def test_get_recent_messages():
    service = MagicMock()

    service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
        "messages": [
            {"id": "email_001", "threadId": "thread_001"},
            {"id": "email_002", "threadId": "thread_002"},
        ]
    }

    result = get_recent_messages(
        service,
        max_results=50,
    )

    assert len(result) == 2
    assert result[0]["id"] == "email_001"


def test_get_recent_messages_empty():
    service = MagicMock()

    service.users.return_value.messages.return_value.list.return_value.execute.return_value = {}

    result = get_recent_messages(service)

    assert result == []


def test_get_message():
    service = MagicMock()

    service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
        "id": "email_001",
        "threadId": "thread_001",
        "payload": {},
    }

    result = get_message(
        service,
        "email_001",
    )

    assert result["id"] == "email_001"
    assert result["threadId"] == "thread_001"