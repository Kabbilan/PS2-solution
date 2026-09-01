"""
URL Analysis Sub-module.
Analyzes URLs for IP addresses, URL shorteners, misleading subdomains,
@-based deceptive URLs, Punycode/homoglyphs, excessive subdomains, and look-alike hosts.
"""

from typing import List, Set
from urllib.parse import urlparse
from detection.config import (
    URL_SHORTENERS,
    SUSPICIOUS_TLDS,
    TARGET_BRANDS,
    BRAND_LEGITIMATE_DOMAINS,
)
from detection.schemas import NormalizedEmail, ModuleResult
from detection.utils.domain_utils import (
    extract_domain_parts,
    find_lookalike_brand,
    has_suspicious_tld,
    is_ip_address,
    is_punycode,
    count_subdomain_levels,
)
from detection.utils.text_utils import extract_urls_from_text


def analyze_urls(email: NormalizedEmail) -> ModuleResult:
    """
    Evaluates all URLs present in email.urls and extracted from email.body.
    """
    reasons: List[str] = []
    max_url_score: float = 0.0
    evaluated_urls: List[str] = []

    # Gather URLs from both the input field and raw body
    url_set: Set[str] = set()
    for u in email.urls:
        if u and str(u).strip():
            url_set.add(str(u).strip())
    
    # Also extract any URLs embedded in the body that might not be in the list
    if email.body:
        extracted = extract_urls_from_text(email.body)
        for u in extracted:
            url_set.add(u)

    if not url_set:
        return ModuleResult(
            name="urls",
            score=0.0,
            reasons=[],
            metadata={"url_count": 0}
        )

    for raw_url in url_set:
        url_score = 0.0
        evaluated_urls.append(raw_url)
        clean_url = raw_url.strip()

        # Parse URL
        parsed = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()

        # Extract domain parts of the URL host
        domain_parts = extract_domain_parts(host)
        registered_domain = domain_parts["registered_domain"]
        subdomain = domain_parts["subdomain"]
        fqdn = domain_parts["fqdn"]

        # 1. Check for @-based deceptive URL (e.g. http://paypal.com@evil.com/path)
        if "@" in parsed.netloc:
            url_score = max(url_score, 85.0)
            reasons.append("Deceptive URL (@ credential notation)")

        # 2. Check for IP-based URL (e.g. http://192.168.1.1/login)
        if domain_parts["is_ip"] or is_ip_address(host.split(":")[0]):
            url_score = max(url_score, 80.0)
            reasons.append("Suspicious URL (IP address host)")

        # 3. Check for Punycode / IDN Homoglyphs
        if is_punycode(host) or is_punycode(fqdn):
            url_score = max(url_score, 75.0)
            reasons.append("Punycode/homoglyph URL")

        # 4. Check for URL Shorteners (e.g. bit.ly, tinyurl.com)
        if registered_domain in URL_SHORTENERS or host in URL_SHORTENERS:
            url_score = max(url_score, 50.0)
            reasons.append("URL shortener used")

        # 5. Check for Misleading Subdomains & Brand in Subdomain/Path
        # e.g., paypal.com.account-verify.com or secure.paypal.phishhost.net
        if subdomain and not domain_parts["is_ip"]:
            for brand in TARGET_BRANDS:
                # If brand is in subdomain but registered domain is not authentic
                if brand in subdomain.lower():
                    legit_domains = BRAND_LEGITIMATE_DOMAINS.get(brand, set())
                    if registered_domain not in legit_domains:
                        url_score = max(url_score, 85.0)
                        reasons.append("Misleading subdomain in URL")
                        break

        # 6. Check for Look-alike / Typosquatting Brand Host in URL
        if registered_domain and not domain_parts["is_ip"]:
            matched_brand, confidence, _ = find_lookalike_brand(registered_domain)
            if matched_brand and confidence > 0:
                url_score = max(url_score, confidence)
                reasons.append("Suspicious URL")

        # 7. Check for Excessive Subdomain Depth (>= 3 levels of subdomains)
        if count_subdomain_levels(host) >= 3:
            url_score = max(url_score, 45.0)
            reasons.append("Excessive subdomains in URL")

        # 8. Check for Suspicious TLD in URL
        if registered_domain and has_suspicious_tld(registered_domain):
            url_score = max(url_score, 55.0)
            if "Suspicious URL" not in reasons:
                reasons.append("Suspicious URL")

        # 9. Generic Suspicious Path/Query tokens (e.g., /login/verify?id=... on unverified domain)
        if any(token in path or token in query for token in ["verify-account", "login-verify", "update-credentials", "secure-login"]):
            # If domain is not an official domain of any brand
            is_official = False
            for brand, legit_domains in BRAND_LEGITIMATE_DOMAINS.items():
                if registered_domain in legit_domains:
                    is_official = True
                    break
            if not is_official and not domain_parts["is_ip"]:
                url_score = max(url_score, 40.0)

        max_url_score = max(max_url_score, url_score)

    # Standardize general "Suspicious URL" label if specific URL flags triggered
    clean_reasons = []
    has_suspicious_url = False
    for r in reasons:
        if "Suspicious URL" in r or "Punycode" in r or "Deceptive URL" in r or "Misleading subdomain" in r:
            has_suspicious_url = True
        clean_reasons.append(r)

    # If high URL score exists, ensure "Suspicious URL" is represented
    if max_url_score >= 60.0 and "Suspicious URL" not in clean_reasons:
        clean_reasons.insert(0, "Suspicious URL")

    return ModuleResult(
        name="urls",
        score=min(100.0, round(max_url_score, 2)),
        reasons=list(dict.fromkeys(clean_reasons)),
        metadata={"url_count": len(url_set), "evaluated_urls": evaluated_urls},
    )
