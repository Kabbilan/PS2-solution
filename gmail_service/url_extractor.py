from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)


def clean_url(url: str) -> str:
    """Remove punctuation commonly attached to URLs in email text."""

    return url.rstrip(".,!?;:)]}>'\"")


def extract_urls_from_text(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from plain text."""

    if not text:
        return []

    matches = URL_PATTERN.findall(text)

    urls = [
        clean_url(url)
        for url in matches
        if is_valid_url(url)
    ]

    return unique_urls(urls)


def extract_urls_from_html(html: str) -> list[str]:
    """Extract URLs from HTML links and visible text."""

    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")

    urls: list[str] = []

    # Extract actual hyperlink destinations.
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "").strip()

        if is_valid_url(href):
            urls.append(clean_url(href))

        # Also inspect visible anchor text.
        visible_text = anchor.get_text(" ", strip=True)

        urls.extend(
            extract_urls_from_text(visible_text)
        )

    # Also scan the complete HTML text.
    visible_content = soup.get_text(" ", strip=True)

    urls.extend(
        extract_urls_from_text(visible_content)
    )

    return unique_urls(urls)


def is_valid_url(url: str) -> bool:
    """Check whether a string is an HTTP/HTTPS URL."""

    try:
        parsed = urlparse(url)

        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.netloc)
        )

    except ValueError:
        return False


def unique_urls(urls: list[str]) -> list[str]:
    """Remove duplicates while preserving original order."""

    seen: set[str] = set()
    result: list[str] = []

    for url in urls:
        if url not in seen:
            seen.add(url)
            result.append(url)

    return result


def extract_urls(content: str, is_html: bool = False) -> list[str]:
    """General URL extraction entry point."""

    if is_html:
        return extract_urls_from_html(content)

    return unique_urls(
        extract_urls_from_text(content)
    )