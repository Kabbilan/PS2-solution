"""
Risk Scoring Engine.
Calculates deterministic weighted scores, applies critical overrides,
calibrates for false-positive prevention, and formats the strict frozen output JSON.
"""

from typing import List, Dict, Any
from detection.config import (
    WEIGHT_SENDER_DOMAIN,
    WEIGHT_URL,
    WEIGHT_AUTH,
    WEIGHT_CONTENT,
    WEIGHT_ATTACHMENT,
    THRESHOLD_SAFE_MAX,
    THRESHOLD_SUSPICIOUS_MAX,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    VERDICT_HIGH_RISK,
)
from detection.schemas import ModuleResult, DetectionOutput


def calculate_risk(
    email_id: str,
    results: List[ModuleResult],
) -> DetectionOutput:
    """
    Combines sub-module results into a final risk score (0-100),
    assigns the appropriate verdict, compiles explainable reasons,
    and returns a DetectionOutput object.
    """
    # Map results by module name
    res_map: Dict[str, ModuleResult] = {r.name: r for r in results}

    s_domain = res_map.get("sender_domain", ModuleResult(name="sender_domain")).score
    s_url = res_map.get("urls", ModuleResult(name="urls")).score
    s_auth = res_map.get("auth", ModuleResult(name="auth")).score
    s_content = res_map.get("content", ModuleResult(name="content")).score
    s_attach = res_map.get("attachments", ModuleResult(name="attachments")).score

    # 1. Base Weighted Score Calculation
    base_score = (
        (s_domain * WEIGHT_SENDER_DOMAIN)
        + (s_url * WEIGHT_URL)
        + (s_auth * WEIGHT_AUTH)
        + (s_content * WEIGHT_CONTENT)
        + (s_attach * WEIGHT_ATTACHMENT)
    )

    final_score = base_score

    # Aggregate reasons preserving order and uniqueness
    all_reasons: List[str] = []
    
    # Priority order for reason presentation
    ordered_module_names = ["sender_domain", "content", "urls", "attachments", "auth"]
    for mod_name in ordered_module_names:
        if mod_name in res_map:
            for r in res_map[mod_name].reasons:
                if r not in all_reasons:
                    all_reasons.append(r)

    # 2. Critical Overrides & Threat Synergy Boosts
    has_lookalike_domain = "Look-alike domain" in all_reasons or s_domain >= 85.0
    has_suspicious_url = "Suspicious URL" in all_reasons or s_url >= 80.0 or "Suspicious URL (IP address host)" in all_reasons
    has_urgency = "Urgency language" in all_reasons or s_content >= 45.0
    has_executable = "Suspicious executable attachment" in all_reasons or "Double extension attachment" in all_reasons or s_attach >= 85.0
    has_auth_fail = "SPF authentication failure" in all_reasons or "DMARC authentication failure" in all_reasons or "DKIM authentication failure" in all_reasons

    # High-Risk Synergy 1: Lookalike domain + (Suspicious URL or Urgency)
    # This is classic high-potency credential phishing (e.g. PayPal scam)
    if has_lookalike_domain and (has_suspicious_url or has_urgency):
        # Calculate high risk score proportional to signals (target around 90-96)
        synergy_score = 90.0
        if has_suspicious_url:
            synergy_score += 2.0
        if has_urgency:
            synergy_score += 2.0
        if has_auth_fail:
            synergy_score += 3.0
        final_score = max(final_score, synergy_score)

    # High-Risk Synergy 2: Executable or Double-Extension Attachment
    if has_executable:
        final_score = max(final_score, 88.0)

    # High-Risk Synergy 3: Brand Lookalike / Impersonation + Auth Hard Fail
    if (has_lookalike_domain or "Display name impersonation" in all_reasons) and has_auth_fail:
        final_score = max(final_score, 92.0)

    # High-Risk Synergy 4: IP-based URL + Credential Request
    if ("Suspicious URL (IP address host)" in all_reasons or "Deceptive URL (@ credential notation)" in all_reasons) and "Credential harvesting request" in all_reasons:
        final_score = max(final_score, 86.0)

    # 3. False Positive Controls & Authentication Trust Discount
    auth_meta = res_map.get("auth", ModuleResult(name="auth")).metadata
    if auth_meta.get("auth_passed", False):
        # If SPF/DKIM/DMARC passed and no critical malicious payload exists, apply trust discount
        if not has_lookalike_domain and not has_executable and not has_suspicious_url:
            final_score = max(0.0, final_score - 10.0)

    # Clean business email with no high-risk flags remains strictly SAFE
    if not has_lookalike_domain and not has_executable and not has_suspicious_url and not has_auth_fail:
        if s_content <= 35.0:
            final_score = min(final_score, 25.0)

    # 4. Score Normalization (0 - 100)
    int_score = int(round(max(0.0, min(100.0, final_score))))

    # 5. Determine Verdict
    if int_score <= THRESHOLD_SAFE_MAX:
        verdict = VERDICT_SAFE
    elif int_score <= THRESHOLD_SUSPICIOUS_MAX:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_HIGH_RISK

    # Clean reasons if score is SAFE and reasons only contained mild noise
    if verdict == VERDICT_SAFE and not has_urgency and not has_auth_fail:
        # Keep reasons clean for safe emails
        filtered_reasons = [r for r in all_reasons if not r.startswith("Impersonal")]
        all_reasons = filtered_reasons

    return DetectionOutput(
        email_id=email_id,
        risk_score=int_score,
        verdict=verdict,
        reasons=all_reasons,
        impersonation=None,
        campaign_id=None,
    )
