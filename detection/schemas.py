"""
Data models, schema normalization, and strict output serialization.
Guarantees frozen JSON contract compliance.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedEmail:
    """
    Normalized internal representation of an input email payload.
    Ensures safe defaults and no NoneType / missing attribute crashes.
    """
    id: str = "unknown_id"
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    body: str = ""
    urls: List[str] = field(default_factory=list)
    attachments: List[Any] = field(default_factory=list)
    headers: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> "NormalizedEmail":
        """Safely ingest any dictionary or arbitrary object into a NormalizedEmail."""
        if not isinstance(data, dict):
            return cls()

        # Safely extract email ID
        raw_id = data.get("id")
        email_id = str(raw_id) if raw_id is not None else "unknown_id"

        # Safely extract text fields
        sender = str(data.get("sender") or "").strip()
        recipient = str(data.get("recipient") or "").strip()
        subject = str(data.get("subject") or "").strip()
        body = str(data.get("body") or "").strip()

        # Safely extract URLs
        raw_urls = data.get("urls")
        urls: List[str] = []
        if isinstance(raw_urls, list):
            for u in raw_urls:
                if u is not None and str(u).strip():
                    urls.append(str(u).strip())
        elif isinstance(raw_urls, str) and raw_urls.strip():
            urls.append(raw_urls.strip())

        # Safely extract attachments
        raw_attachments = data.get("attachments")
        attachments: List[Any] = []
        if isinstance(raw_attachments, list):
            for att in raw_attachments:
                if att is not None:
                    attachments.append(att)
        elif raw_attachments is not None:
            attachments.append(raw_attachments)

        # Safely extract headers (case-insensitive dictionary wrapper)
        raw_headers = data.get("headers")
        headers: Dict[str, Any] = {}
        if isinstance(raw_headers, dict):
            for k, v in raw_headers.items():
                if k is not None and v is not None:
                    headers[str(k)] = str(v)

        return cls(
            id=email_id,
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            urls=urls,
            attachments=attachments,
            headers=headers,
        )


@dataclass
class ModuleResult:
    """Standardized output of each individual detection sub-module."""
    name: str
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionOutput:
    """
    Strict representation of the team-wide frozen JSON output schema.
    DO NOT modify the structure or field names of to_dict().
    """
    email_id: str
    risk_score: int
    verdict: str
    reasons: List[str]
    impersonation: Optional[Any] = None
    campaign_id: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert strictly to the frozen team-wide JSON format."""
        return {
            "email_id": str(self.email_id),
            "risk_score": int(self.risk_score),
            "verdict": str(self.verdict),
            "reasons": list(self.reasons),
            "impersonation": self.impersonation,
            "campaign_id": self.campaign_id,
        }
