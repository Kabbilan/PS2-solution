from datetime import date, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from backend.main import build_gmail_date_query
from backend import main
from gmail_service.gmail_service import get_recent_messages


def test_date_query_includes_selected_end_date():
    assert build_gmail_date_query("2026-08-20", "2026-09-02") == (
        "after:2026/08/20 before:2026/09/03"
    )


def test_date_query_supports_same_day():
    assert build_gmail_date_query("2026-09-02", "2026-09-02") == (
        "after:2026/09/02 before:2026/09/03"
    )


@pytest.mark.parametrize(
    ("start", "end", "message"),
    [
        ("2026-09-02", None, "Both from_date and to_date are required."),
        (None, "2026-09-02", "Both from_date and to_date are required."),
        ("not-a-date", "2026-09-02", "Dates must use YYYY-MM-DD format."),
        ("2026-09-02", "2026-08-20", "from_date cannot be later than to_date."),
    ],
)
def test_invalid_date_ranges_return_http_400(start, end, message):
    with pytest.raises(HTTPException) as exc:
        build_gmail_date_query(start, end)
    assert exc.value.status_code == 400
    assert exc.value.detail == message


def test_future_date_returns_http_400():
    future = (date.today() + timedelta(days=1)).isoformat()
    with pytest.raises(HTTPException) as exc:
        build_gmail_date_query(date.today().isoformat(), future)
    assert exc.value.status_code == 400
    assert exc.value.detail == "Date range cannot include future dates."


def test_gmail_query_is_forwarded_to_api():
    service = MagicMock()
    service.users.return_value.messages.return_value.list.return_value.execute.return_value = {}
    query = "after:2026/08/20 before:2026/09/03"
    assert get_recent_messages(service, max_results=100, query=query) == []
    service.users.return_value.messages.return_value.list.assert_called_once_with(
        userId="me", maxResults=100, q=query
    )


def _parsed_email():
    return {
        "id": "email_001",
        "sender": "security@paypa1-login.com",
        "recipient": "analyst@example.com",
        "subject": "Verify now",
        "body": "Verify your account immediately",
        "urls": ["http://paypa1-login.com/verify"],
        "attachments": [],
        "headers": {},
    }


def _analysis():
    return {
        "email_id": "email_001",
        "risk_score": 94,
        "verdict": "HIGH_RISK",
        "reasons": ["Look-alike domain"],
        "impersonation": None,
        "campaign_id": None,
    }


def test_unfiltered_fetch_keeps_latest_20_and_uses_existing_analyzer(monkeypatch):
    gmail_fetch = MagicMock(return_value=[{"id": "raw_001"}])
    analyzer = MagicMock(return_value=_analysis())
    save_email = MagicMock()
    save_analysis = MagicMock()
    monkeypatch.setattr(main, "fetch_gmail_emails", gmail_fetch)
    monkeypatch.setattr(main, "parse_gmail_message", lambda raw: _parsed_email())
    monkeypatch.setattr(main, "analyze_email", analyzer)
    monkeypatch.setattr(main, "save_email", save_email)
    monkeypatch.setattr(main, "save_analysis", save_analysis)
    monkeypatch.setattr(main, "fetch_emails", lambda: [])
    monkeypatch.setattr(main, "detect_campaign", lambda emails: None)

    rows = main.fetch_from_gmail(
        max_results=None, from_date=None, to_date=None, x_session_id="session"
    )

    gmail_fetch.assert_called_once_with(20, "session", query=None)
    analyzer.assert_called_once()
    save_email.assert_called_once()
    save_analysis.assert_called_once_with(_analysis())
    assert rows[0]["analysis"]["verdict"] == "HIGH_RISK"


def test_filtered_fetch_forwards_query_and_preserves_campaign_analysis(monkeypatch):
    gmail_fetch = MagicMock(return_value=[{"id": "raw_001"}])
    saved = []
    monkeypatch.setattr(main, "fetch_gmail_emails", gmail_fetch)
    monkeypatch.setattr(main, "parse_gmail_message", lambda raw: _parsed_email())
    monkeypatch.setattr(main, "analyze_email", lambda email: _analysis())
    monkeypatch.setattr(main, "save_email", lambda email: None)
    monkeypatch.setattr(main, "save_analysis", saved.append)
    monkeypatch.setattr(main, "fetch_emails", lambda: [_parsed_email()])
    monkeypatch.setattr(
        main, "detect_campaign", lambda emails: {"campaign_id": "campaign_001"}
    )

    rows = main.fetch_from_gmail(
        max_results=None,
        from_date="2026-08-20",
        to_date="2026-09-02",
        x_session_id="session",
    )

    gmail_fetch.assert_called_once_with(
        100, "session", query="after:2026/08/20 before:2026/09/03"
    )
    assert rows[0]["analysis"]["campaign_id"] == "campaign_001"
    assert saved[0]["email_id"] == "email_001"


def test_filtered_fetch_returns_empty_list_without_error(monkeypatch):
    monkeypatch.setattr(main, "fetch_gmail_emails", lambda *args, **kwargs: [])
    monkeypatch.setattr(main, "fetch_emails", lambda: [])
    monkeypatch.setattr(main, "detect_campaign", lambda emails: None)
    assert main.fetch_from_gmail(
        max_results=None,
        from_date=date.today().isoformat(),
        to_date=date.today().isoformat(),
        x_session_id="session",
    ) == []
