from gmail_service.oauth import (
    CREDENTIALS_FILE,
    TOKEN_FILE,
    SCOPES,
)


def test_oauth_configuration():
    assert CREDENTIALS_FILE.endswith("credentials.json")
    assert TOKEN_FILE.endswith("token.json")
    assert SCOPES == [
        "https://www.googleapis.com/auth/gmail.readonly"
    ]