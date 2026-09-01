"""
Attachment Analysis Sub-module.
Performs safe static inspection of attachment filenames and extensions for
dangerous executables, double extensions, macro-enabled documents, and risky archives.
Never executes or runs any attachment code.
"""

import os
from typing import List, Any
from detection.config import (
    DANGEROUS_EXECUTABLE_EXTENSIONS,
    MACRO_DOCUMENT_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    BENIGN_EXTENSIONS,
)
from detection.schemas import NormalizedEmail, ModuleResult


def extract_filename(att: Any) -> str:
    """Extract string filename from string or dictionary attachment entry."""
    if isinstance(att, str):
        return att.strip()
    elif isinstance(att, dict):
        return str(att.get("filename") or att.get("name") or "").strip()
    return str(att).strip()


def check_double_extension(filename: str) -> bool:
    """
    Check if a filename contains a deceptive double extension.
    Example: 'Invoice_2026.pdf.exe', 'Photo.jpg.scr', 'Document.docx.vbs'.
    """
    clean_name = filename.lower()
    parts = clean_name.split(".")
    if len(parts) >= 3:
        first_ext = f".{parts[-2]}"
        final_ext = f".{parts[-1]}"
        # If the outer extension is dangerous/executable and the preceding extension looks like a benign document
        if final_ext in DANGEROUS_EXECUTABLE_EXTENSIONS and first_ext in BENIGN_EXTENSIONS:
            return True
    return False


def analyze_attachments(email: NormalizedEmail) -> ModuleResult:
    """
    Evaluates the attachments listed in the email payload.
    """
    reasons: List[str] = []
    max_score: float = 0.0
    attachment_names: List[str] = []

    if not email.attachments:
        return ModuleResult(
            name="attachments",
            score=0.0,
            reasons=[],
            metadata={"attachment_count": 0}
        )

    for att in email.attachments:
        fname = extract_filename(att)
        if not fname:
            continue
        attachment_names.append(fname)
        lower_fname = fname.lower()
        _, ext = os.path.splitext(lower_fname)

        # 1. Double Extension Detection (e.g. report.pdf.exe)
        if check_double_extension(lower_fname):
            max_score = max(max_score, 95.0)
            reasons.append("Double extension attachment")

        # 2. Dangerous Executable / Script Extension Detection
        elif ext in DANGEROUS_EXECUTABLE_EXTENSIONS:
            max_score = max(max_score, 90.0)
            reasons.append("Suspicious executable attachment")

        # 3. Macro-Enabled Document Detection (.docm, .xlsm, etc.)
        elif ext in MACRO_DOCUMENT_EXTENSIONS:
            max_score = max(max_score, 75.0)
            reasons.append("Macro-enabled document attachment")

        # 4. Container / Disk Image / Suspicious Archive
        elif ext in ARCHIVE_EXTENSIONS:
            if ext in {".iso", ".img", ".vhd", ".cab"}:
                max_score = max(max_score, 70.0)
                reasons.append("Suspicious container/disk image attachment")
            else:
                max_score = max(max_score, 40.0)
                reasons.append("Archive attachment")

    return ModuleResult(
        name="attachments",
        score=min(100.0, round(max_score, 2)),
        reasons=list(dict.fromkeys(reasons)),
        metadata={"attachment_count": len(attachment_names), "files": attachment_names},
    )
