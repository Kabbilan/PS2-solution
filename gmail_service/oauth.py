from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDENTIALS_FILE = os.path.join(BASE_DIR, "credentials.json")
TOKEN_FILE = os.path.join(BASE_DIR, "token.json")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "https://phishguard-api-wrjw.onrender.com/auth/google/callback")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://ps2solution.vercel.app")

_user_sessions: dict[str, Credentials] = {}


def _client_config():
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise RuntimeError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required")
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI],
        }
    }


def _state_signing_key() -> bytes:
    secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not secret:
        raise RuntimeError("GOOGLE_CLIENT_SECRET is required")
    return secret.encode("utf-8")


def _create_state() -> str:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    payload = f"{timestamp}.{nonce}"
    signature = hmac.new(_state_signing_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def _validate_state(state: str) -> None:
    try:
        timestamp, nonce, signature = state.split(".", 2)
        payload = f"{timestamp}.{nonce}"
        expected = hmac.new(_state_signing_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        age = time.time() - int(timestamp)
        if age < 0 or age > 600:
            raise ValueError
    except (ValueError, TypeError):
        raise RuntimeError("Invalid or expired OAuth state")


def create_authorization_url():
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=REDIRECT_URI)
    state = _create_state()
    url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        state=state,
    )
    return url, state


def exchange_authorization_code(code: str, state: str):
    _validate_state(state)
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, state=state, redirect_uri=REDIRECT_URI)
    flow.fetch_token(code=code)
    session_id = secrets.token_urlsafe(32)
    _user_sessions[session_id] = flow.credentials
    return session_id


def get_session_credentials(session_id: str) -> Credentials:
    credentials = _user_sessions.get(session_id)
    if not credentials:
        raise RuntimeError("Google session expired. Sign in again.")
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
    return credentials


def delete_session(session_id: str):
    _user_sessions.pop(session_id, None)


def _credentials_from_environment() -> Credentials | None:
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    refresh_token = os.getenv("GOOGLE_REFRESH_TOKEN")
    if not all([client_id, client_secret, refresh_token]):
        return None
    return Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )


def get_gmail_credentials() -> Credentials:
    credentials = _credentials_from_environment()
    if credentials:
        credentials.refresh(Request())
        return credentials
    if os.path.exists(TOKEN_FILE):
        credentials = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        if credentials.valid:
            return credentials
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            with open(TOKEN_FILE, "w", encoding="utf-8") as token:
                token.write(credentials.to_json())
            return credentials
    if not os.path.exists(CREDENTIALS_FILE):
        raise FileNotFoundError("Gmail OAuth is not configured")
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
    credentials = flow.run_local_server(port=0)
    with open(TOKEN_FILE, "w", encoding="utf-8") as token:
        token.write(credentials.to_json())
    return credentials
