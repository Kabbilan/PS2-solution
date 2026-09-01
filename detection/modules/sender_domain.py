"""
Sender and Domain Analysis Sub-module.
Analyzes sender address, domain reputation, look-alike/typosquatting domains,
display name spoofing, suspicious TLDs, IP-based senders, and Reply-To mismatches.
"""

from typing import List, Optional
from detection.config import (
    TARGET_BRANDS,
    BRAND_LEGITIMATE_DOMAINS,
    FREE_WEBMAIL_DOMAINS,
    SUSPICIOUS_TLDS,
)
from detection.schemas import NormalizedEmail, ModuleResult
from detection.utils.domain_utils import (
    extract_domain_parts,
    find_lookalike_brand,
    has_suspicious_tld,
    is_ip_address,
    is_punycode,
)
from detection.utils.text_utils import parse_email_address, clean_text


def analyze_sender_domain(email: NormalizedEmail) -> ModuleResult:
    """
    Evaluates the sender string, domain properties, and domain-level headers.
    """
    reasons: List[str] = []
    score: float = 0.0
    metadata = {}

    if not email.sender:
        return ModuleResult(name="sender_domain", score=0.0, reasons=[], metadata={"sender": "empty"})

    display_name, email_address = parse_email_address(email.sender)
    metadata["display_name"] = display_name
    metadata["email_address"] = email_address

    domain_parts = extract_domain_parts(email_address)
    metadata["domain_parts"] = domain_parts
    fqdn = domain_parts["fqdn"]
    domain_stem = domain_parts["domain"]
    registered_domain = domain_parts["registered_domain"]

    # 1. Check for IP-based Sender
    if domain_parts["is_ip"] or (fqdn and is_ip_address(fqdn)):
        score = max(score, 70.0)
        reasons.append("IP-based sender address")
        metadata["ip_sender"] = True

    # 2. Look-alike / Typosquatting / Combosquatting Domain Detection
    if registered_domain and not domain_parts["is_ip"]:
        matched_brand, confidence, reason_desc = find_lookalike_brand(registered_domain)
        if matched_brand and confidence > 0:
            score = max(score, confidence)
            reasons.append("Look-alike domain")
            metadata["lookalike_brand"] = matched_brand
            metadata["lookalike_desc"] = reason_desc

    # 3. Suspicious TLD Detection
    if registered_domain and has_suspicious_tld(registered_domain):
        # Add risk if TLD is known high-abuse
        score = min(100.0, score + 45.0) if score > 0 else 45.0
        reasons.append("Suspicious TLD")
        metadata["suspicious_tld"] = domain_parts["suffix"]

    # 4. Punycode / IDN Homoglyph in Domain
    if is_punycode(fqdn):
        score = max(score, 65.0)
        reasons.append("Punycode/homoglyph domain indicator")
        metadata["punycode"] = True

    # 5. Display Name Brand Impersonation
    # Example: Display name says "PayPal Security", but sender is "support@gmail.com" or "user@scam-host.xyz"
    if display_name:
        clean_disp = clean_text(display_name).lower()
        for brand in TARGET_BRANDS:
            if brand in clean_disp:
                # Brand is mentioned in display name
                legit_domains = BRAND_LEGITIMATE_DOMAINS.get(brand, set())
                if registered_domain not in legit_domains:
                    score = max(score, 75.0)
                    if "Display name impersonation" not in reasons and "Look-alike domain" not in reasons:
                        reasons.append("Display name impersonation")
                    metadata["display_name_spoofed_brand"] = brand
                    break

    # 6. Reply-To Header Mismatch Detection
    reply_to = email.headers.get("Reply-To") or email.headers.get("reply-to") or email.headers.get("Reply-to")
    if reply_to:
        _, reply_address = parse_email_address(str(reply_to))
        if reply_address and email_address:
            reply_domain_parts = extract_domain_parts(reply_address)
            reply_reg_domain = reply_domain_parts["registered_domain"]

            # If sender is not free webmail, and reply domain is totally different
            if registered_domain and reply_reg_domain and registered_domain != reply_reg_domain:
                # Flag mismatch especially if reply-to is a free webmail or suspicious domain
                if reply_reg_domain in FREE_WEBMAIL_DOMAINS or has_suspicious_tld(reply_reg_domain):
                    score = max(score, 60.0)
                    reasons.append("Reply-To mismatch")
                    metadata["reply_to_mismatch"] = f"{registered_domain} vs {reply_reg_domain}"
                else:
                    # Minor indicator
                    score = max(score, 30.0)
                    reasons.append("Reply-To mismatch")
                    metadata["reply_to_mismatch"] = f"{registered_domain} vs {reply_reg_domain}"

    return ModuleResult(
        name="sender_domain",
        score=min(100.0, round(score, 2)),
        reasons=list(dict.fromkeys(reasons)),
        metadata=metadata,
    )
