"""
Content and NLP Analysis Sub-module.
Analyzes email subject and body for urgency, credential harvesting,
financial fraud language, generic greetings, and text obfuscation techniques.
"""

import re
from typing import List
from detection.config import (
    URGENCY_PATTERNS,
    CREDENTIAL_HARVESTING_PATTERNS,
    FINANCIAL_FRAUD_PATTERNS,
    GENERIC_GREETING_PATTERNS,
)
from detection.schemas import NormalizedEmail, ModuleResult
from detection.utils.text_utils import (
    clean_text,
    detect_zero_width_chars,
    detect_mixed_scripts,
)


def analyze_content(email: NormalizedEmail) -> ModuleResult:
    """
    Evaluates the textual content of the email subject and body.
    """
    reasons: List[str] = []
    score: float = 0.0
    metadata = {}

    subject = str(email.subject or "")
    body = str(email.body or "")
    combined_text = f"{subject} {body}".strip()

    if not combined_text:
        return ModuleResult(
            name="content",
            score=0.0,
            reasons=[],
            metadata={"content_length": 0}
        )

    # 1. Obfuscation Detection (Zero-width characters & Mixed Scripts)
    has_zero_width = detect_zero_width_chars(subject) or detect_zero_width_chars(body)
    if has_zero_width:
        score += 40.0
        reasons.append("Hidden text obfuscation detected")
        metadata["zero_width_obfuscation"] = True

    words = re.findall(r"\b\w+\b", combined_text)
    mixed_script_words = [w for w in words if detect_mixed_scripts(w)]
    if mixed_script_words:
        score += 35.0
        reasons.append("Mixed-script alphabet evasion detected")
        metadata["mixed_script_words"] = mixed_script_words[:5]

    # Clean text for regex matching
    cleaned = clean_text(combined_text)
    lower_text = cleaned.lower()

    # 2. Urgency & Coercive Phrasing Analysis
    urgency_matches = []
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, lower_text, re.IGNORECASE):
            urgency_matches.append(pattern)

    if urgency_matches:
        # Match count scaling: 1 match is mild (35 score), multiple matches are strong (50-70 score)
        urgency_score = min(75.0, 35.0 + (len(urgency_matches) - 1) * 15.0)
        score = max(score, urgency_score)
        reasons.append("Urgency language")
        metadata["urgency_matches"] = len(urgency_matches)

    # 3. Credential Harvesting Phrasing
    cred_matches = []
    for pattern in CREDENTIAL_HARVESTING_PATTERNS:
        if re.search(pattern, lower_text, re.IGNORECASE):
            cred_matches.append(pattern)

    if cred_matches:
        cred_score = min(75.0, 40.0 + (len(cred_matches) - 1) * 15.0)
        score = max(score, cred_score)
        reasons.append("Credential harvesting request")
        metadata["credential_harvesting_matches"] = len(cred_matches)

    # 4. Payment / Financial Fraud Phrasing
    fin_matches = []
    for pattern in FINANCIAL_FRAUD_PATTERNS:
        if re.search(pattern, lower_text, re.IGNORECASE):
            fin_matches.append(pattern)

    if fin_matches:
        fin_score = min(65.0, 30.0 + (len(fin_matches) - 1) * 15.0)
        score = max(score, fin_score)
        reasons.append("Payment or invoice fraud language")
        metadata["financial_fraud_matches"] = len(fin_matches)

    # 5. Generic / Suspicious Greetings
    greeting_matches = []
    for pattern in GENERIC_GREETING_PATTERNS:
        if re.search(pattern, lower_text, re.IGNORECASE):
            greeting_matches.append(pattern)

    if greeting_matches:
        # Generic greetings alone only contribute mildly (15-20 points)
        score += 15.0
        metadata["generic_greeting"] = True
        # Only add to reasons if combined with urgency or credential requests
        if urgency_matches or cred_matches:
            reasons.append("Impersonal generic greeting in security context")

    return ModuleResult(
        name="content",
        score=min(100.0, round(score, 2)),
        reasons=list(dict.fromkeys(reasons)),
        metadata=metadata,
    )
