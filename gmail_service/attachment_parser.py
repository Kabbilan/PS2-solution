from __future__ import annotations

from typing import Any


def extract_attachments(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract attachment metadata from a Gmail message payload.

    This function does NOT download or execute attachments.
    """

    attachments: list[dict[str, Any]] = []

    walk_parts(payload, attachments)

    return attachments


def walk_parts(
    part: dict[str, Any],
    attachments: list[dict[str, Any]],
) -> None:
    """Recursively walk Gmail MIME parts."""

    filename = part.get("filename", "").strip()
    body = part.get("body", {})

    if filename:
        attachment = {
            "filename": filename,
            "mime_type": part.get("mimeType", ""),
            "size": body.get("size", 0),
            "attachment_id": body.get("attachmentId", ""),
        }

        attachments.append(attachment)

    for child in part.get("parts", []):
        walk_parts(child, attachments)