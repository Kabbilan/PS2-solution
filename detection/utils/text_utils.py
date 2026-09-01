"""
Text processing, regex tokenization, script analysis, and email parsing utilities.
"""

import re
import unicodedata
from email.utils import parseaddr
from typing import List, Tuple

# Zero-width / hidden unicode characters often used for filter evasion
ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
    "\u2060",  # Word joiner
    "\u00ad",  # Soft hyphen
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
}

# Regex to safely find URLs in raw plain text
URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))",
    re.IGNORECASE
)


def clean_text(text: str) -> str:
    """Normalize whitespace and strip non-printable control characters."""
    if not text:
        return ""
    # Normalize unicode forms
    normalized = unicodedata.normalize("NFKC", str(text))
    # Replace multiple whitespaces with single space
    cleaned = re.sub(r"\s+", " ", normalized).strip()
    return cleaned


def detect_zero_width_chars(text: str) -> bool:
    """Detect if hidden or zero-width evasion characters are present in the text."""
    if not text:
        return False
    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            return True
    return False


def detect_mixed_scripts(word: str) -> bool:
    """
    Detect if a single word mixes Latin and Cyrillic/Greek scripts,
    a common evasion tactic used in domain names and phishing phrases.
    """
    if not word or len(word) < 3:
        return False

    has_latin = False
    has_cyrillic_or_other = False

    for ch in word:
        if not ch.isalpha():
            continue
        try:
            script = unicodedata.name(ch, "").split()[0]
            if script == "LATIN":
                has_latin = True
            elif script in ("CYRILLIC", "GREEK"):
                has_cyrillic_or_other = True
        except Exception:
            continue

    return has_latin and has_cyrillic_or_other


def parse_email_address(sender_str: str) -> Tuple[str, str]:
    """
    Safely parse display name and raw email address from sender string.
    Handles standard RFC formats ('Display Name <user@domain.com>')
    and malformed inputs gracefully.

    Returns:
        (display_name, email_address)
    """
    if not sender_str:
        return "", ""

    sender_str = str(sender_str).strip()
    
    # Use standard library parser
    display_name, email_addr = parseaddr(sender_str)
    
    # If parseaddr failed to find email address, attempt regex extraction
    if not email_addr and "@" in sender_str:
        match = re.search(r"[\w\.\+\-]+@[\w\.\-]+\.[a-zA-Z0-9\.\-]+", sender_str)
        if match:
            email_addr = match.group(0)
            # Remove extracted email from sender_str to get display name
            display_name = sender_str.replace(email_addr, "").strip("<>()\"' ")
    
    return display_name.strip("\"' "), email_addr.strip("<>").lower()


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs found in freeform text."""
    if not text:
        return []
    matches = URL_REGEX.findall(str(text))
    urls = []
    for match in matches:
        if isinstance(match, tuple):
            urls.append(match[0])
        else:
            urls.append(match)
    return urls
