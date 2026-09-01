from __future__ import annotations

import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

CREDENTIALS_FILE = os.path.join(
    BASE_DIR,
    "credentials.json",
)

TOKEN_FILE = os.path.join(
    BASE_DIR,
    "token.json",
)


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
        credentials = Credentials.from_authorized_user_file(
            TOKEN_FILE,
            SCOPES,
        )

        if credentials.valid:
            return credentials

        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())

            with open(TOKEN_FILE, "w", encoding="utf-8") as token:
                token.write(credentials.to_json())

            return credentials

    if not os.path.exists(CREDENTIALS_FILE):
        raise FileNotFoundError(
            "Gmail OAuth is not configured. Set GOOGLE_CLIENT_ID, "
            "GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN, or provide "
            "local credentials.json for development."
        )

    flow = InstalledAppFlow.from_client_secrets_file(
        CREDENTIALS_FILE,
        SCOPES,
    )

    credentials = flow.run_local_server(port=0)

    with open(TOKEN_FILE, "w", encoding="utf-8") as token:
        token.write(credentials.to_json())

    return credentials
