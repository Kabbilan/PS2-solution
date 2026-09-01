"""
Email Authentication Sub-module (SPF, DKIM, DMARC).
Parses standard and extended authentication headers for verification status.
Ensures missing headers do NOT penalize clean legitimate emails.
"""

import re
from typing import Dict, List, Any
from detection.schemas import NormalizedEmail, ModuleResult


def analyze_auth(email: NormalizedEmail) -> ModuleResult:
    """
    Evaluates SPF, DKIM, and DMARC headers.
    Returns risk score and reason descriptions if authentication failures are present.
    """
    reasons: List[str] = []
    score: float = 0.0
    metadata: Dict[str, Any] = {
        "spf_status": "none",
        "dkim_status": "none",
        "dmarc_status": "none",
        "auth_passed": False,
    }

    if not email.headers or not isinstance(email.headers, dict):
        return ModuleResult(
            name="auth",
            score=0.0,
            reasons=[],
            metadata={"headers_present": False}
        )

    # Normalize header keys to lowercase for flexible matching
    headers_lower = {str(k).lower(): str(v).lower() for k, v in email.headers.items()}

    # Combine all auth-related header contents for comprehensive pattern scanning
    auth_header_blob = " ".join([
        headers_lower.get("received-spf", ""),
        headers_lower.get("authentication-results", ""),
        headers_lower.get("arc-authentication-results", ""),
        headers_lower.get("dmarc-filter", ""),
        headers_lower.get("x-dmarc-status", ""),
        headers_lower.get("x-spf-status", ""),
        headers_lower.get("x-dkim-status", ""),
        headers_lower.get("spf", ""),
        headers_lower.get("dkim", ""),
        headers_lower.get("dmarc", ""),
    ])

    if not auth_header_blob.strip():
        # Missing auth headers - DO NOT penalize
        return ModuleResult(
            name="auth",
            score=0.0,
            reasons=[],
            metadata={"headers_present": True, "auth_headers_found": False}
        )

    # =========================================================================
    # 1. SPF ANALYSIS
    # =========================================================================
    # Look for spf=pass, spf=fail, spf=softfail, spf=neutral, spf=temperror, spf=permerror
    spf_match = re.search(r"\b(?:received-)?spf[=:\s]+(pass|fail|softfail|neutral|temperror|permerror|none)\b", auth_header_blob)
    if not spf_match:
        # Check direct Received-SPF header
        recv_spf = headers_lower.get("received-spf", "")
        if "pass" in recv_spf:
            spf_match_status = "pass"
        elif "fail" in recv_spf:
            spf_match_status = "fail"
        elif "softfail" in recv_spf:
            spf_match_status = "softfail"
        else:
            spf_match_status = "none"
    else:
        spf_match_status = spf_match.group(1)

    metadata["spf_status"] = spf_match_status

    if spf_match_status == "fail":
        score += 45.0
        reasons.append("SPF authentication failure")
    elif spf_match_status in ("softfail", "permerror"):
        score += 25.0
        reasons.append("SPF softfail/configuration error")

    # =========================================================================
    # 2. DKIM ANALYSIS
    # =========================================================================
    dkim_match = re.search(r"\bdkim[=:\s]+(pass|fail|temperror|permerror|none)\b", auth_header_blob)
    if not dkim_match:
        dkim_hdr = headers_lower.get("dkim", "") or headers_lower.get("x-dkim-status", "")
        if "pass" in dkim_hdr:
            dkim_match_status = "pass"
        elif "fail" in dkim_hdr:
            dkim_match_status = "fail"
        else:
            dkim_match_status = "none"
    else:
        dkim_match_status = dkim_match.group(1)

    metadata["dkim_status"] = dkim_match_status

    if dkim_match_status == "fail":
        score += 45.0
        reasons.append("DKIM authentication failure")
    elif dkim_match_status in ("permerror", "temperror"):
        score += 20.0

    # =========================================================================
    # 3. DMARC ANALYSIS
    # =========================================================================
    dmarc_match = re.search(r"\bdmarc[=:\s]+(pass|fail|quarantine|reject|temperror|permerror|none)\b", auth_header_blob)
    if not dmarc_match:
        dmarc_hdr = headers_lower.get("dmarc", "") or headers_lower.get("x-dmarc-status", "")
        if "pass" in dmarc_hdr:
            dmarc_match_status = "pass"
        elif "fail" in dmarc_hdr or "reject" in dmarc_hdr or "quarantine" in dmarc_hdr:
            dmarc_match_status = "fail"
        else:
            dmarc_match_status = "none"
    else:
        dmarc_match_status = dmarc_match.group(1)

    metadata["dmarc_status"] = dmarc_match_status

    if dmarc_match_status in ("fail", "quarantine", "reject"):
        score += 55.0
        reasons.append("DMARC authentication failure")

    # If all existing authentication checks passed, record positive auth verification
    if (spf_match_status == "pass" or dkim_match_status == "pass" or dmarc_match_status == "pass") and score == 0:
        metadata["auth_passed"] = True

    return ModuleResult(
        name="auth",
        score=min(100.0, round(score, 2)),
        reasons=list(dict.fromkeys(reasons)),
        metadata=metadata,
    )
