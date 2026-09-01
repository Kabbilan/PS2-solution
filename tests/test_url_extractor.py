from gmail_service.url_extractor import (
    extract_urls,
    extract_urls_from_html,
    extract_urls_from_text,
)


def test_extract_urls_from_plain_text():
    text = """
    Please login here:
    https://example.com/login

    Also visit http://example.org/help.
    """

    urls = extract_urls_from_text(text)

    assert urls == [
        "https://example.com/login",
        "http://example.org/help",
    ]


def test_extract_urls_from_html():
    html = """
    <html>
        <body>
            <p>Please verify your account.</p>

            <a href="https://fake-login.com">
                Click here
            </a>

            <a href="https://example.com/reset">
                https://example.com/reset
            </a>
        </body>
    </html>
    """

    urls = extract_urls_from_html(html)

    assert "https://fake-login.com" in urls
    assert "https://example.com/reset" in urls


def test_duplicate_urls_removed():
    text = """
    https://example.com
    https://example.com
    https://example.com
    """

    urls = extract_urls_from_text(text)

    assert urls == ["https://example.com"]


def test_invalid_urls_ignored():
    text = """
    example.com
    ftp://example.com
    javascript:alert('test')
    https://valid.com
    """

    urls = extract_urls_from_text(text)

    assert urls == ["https://valid.com"]


def test_empty_input():
    assert extract_urls("") == []
