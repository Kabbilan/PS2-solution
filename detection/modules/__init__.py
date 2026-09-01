"""
Detection sub-modules package.
"""

from detection.modules.sender_domain import analyze_sender_domain
from detection.modules.urls import analyze_urls
from detection.modules.content import analyze_content
from detection.modules.auth import analyze_auth
from detection.modules.attachments import analyze_attachments

__all__ = [
    "analyze_sender_domain",
    "analyze_urls",
    "analyze_content",
    "analyze_auth",
    "analyze_attachments",
]
