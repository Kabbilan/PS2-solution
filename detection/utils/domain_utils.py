"""
Domain and Hostname utility functions for phishing detection.
Includes pure-Python TLD/SLD extraction, homoglyph normalization,
Levenshtein distance, IP detection, and typosquatting/combosquatting matching.
"""

import re
import ipaddress
from typing import Dict, Optional, Tuple, List
from detection.config import (
    TARGET_BRANDS,
    BRAND_LEGITIMATE_DOMAINS,
    SUSPICIOUS_TLDS,
    HOMOGLYPH_MAP,
)

# Common two-part public suffixes
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "net.za", "org.za", "web.za",
    "com.br", "net.br", "org.br", "gov.br",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.sg", "net.sg", "org.sg", "gov.sg",
    "com.mx", "org.mx", "net.mx", "edu.mx",
    "com.tr", "org.tr", "net.tr", "gov.tr",
    "co.kr", "ne.kr", "or.kr", "re.kr"
}


def is_ip_address(host: str) -> bool:
    """Check if the given host string is a valid IPv4 or IPv6 address."""
    if not host:
        return False
    # Strip brackets if IPv6
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def is_punycode(domain: str) -> bool:
    """Check if a domain or hostname utilizes IDN Punycode encoding."""
    if not domain:
        return False
    parts = domain.lower().split(".")
    for part in parts:
        if part.startswith("xn--"):
            return True
    return False


def normalize_homoglyphs(text: str) -> str:
    """
    Replace homoglyphs, lookalike characters, and leetspeak numbers with ASCII Latin equivalents.
    Handles multi-char replacements (e.g., 'vv' -> 'w') and character-by-character replacements.
    """
    if not text:
        return ""
    
    result = text.lower()
    
    # Handle multi-char substitutions first
    result = result.replace("vv", "w")
    result = result.replace("rn", "m")  # common visual spoof: 'rn' looks like 'm'
    
    # Character substitutions
    char_list = []
    for ch in result:
        char_list.append(HOMOGLYPH_MAP.get(ch, ch))
    
    return "".join(char_list)


def calculate_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Compute the Levenshtein edit distance between two strings using dynamic programming.
    """
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)

    v0 = list(range(len(s2) + 1))
    v1 = [0] * (len(s2) + 1)

    for i in range(len(s1)):
        v1[0] = i + 1
        for j in range(len(s2)):
            cost = 0 if s1[i] == s2[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0 = list(v1)

    return v0[len(s2)]


def extract_domain_parts(host_or_email_or_url: str) -> Dict[str, str]:
    """
    Parse a hostname, domain, email, or URL into its constituent parts:
    - fqdn: full normalized host
    - subdomain: prefix subdomain string (e.g. 'login.verify')
    - domain: second-level domain / registered stem (e.g. 'paypal')
    - suffix: TLD / public suffix (e.g. 'com', 'co.uk')
    - registered_domain: domain + '.' + suffix (e.g. 'paypal.com')
    - is_ip: boolean indicating if host is an IP address
    """
    if not host_or_email_or_url:
        return {
            "fqdn": "",
            "subdomain": "",
            "domain": "",
            "suffix": "",
            "registered_domain": "",
            "is_ip": False,
        }

    raw = host_or_email_or_url.strip().lower()

    # Extract host if email
    if "@" in raw:
        raw = raw.split("@")[-1]

    # Extract host if URL
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    
    # Strip paths, queries, fragments, ports
    raw = raw.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    raw = raw.strip(". ")

    if is_ip_address(raw):
        return {
            "fqdn": raw,
            "subdomain": "",
            "domain": raw,
            "suffix": "",
            "registered_domain": raw,
            "is_ip": True,
        }

    parts = raw.split(".")
    if len(parts) == 1:
        return {
            "fqdn": raw,
            "subdomain": "",
            "domain": raw,
            "suffix": "",
            "registered_domain": raw,
            "is_ip": False,
        }

    # Check two-part suffix
    suffix = parts[-1]
    domain = parts[-2]
    subdomain = ".".join(parts[:-2])

    if len(parts) >= 3:
        potential_two_part = f"{parts[-2]}.{parts[-1]}"
        if potential_two_part in TWO_PART_SUFFIXES:
            suffix = potential_two_part
            domain = parts[-3]
            subdomain = ".".join(parts[:-3])

    registered_domain = f"{domain}.{suffix}" if suffix else domain

    return {
        "fqdn": raw,
        "subdomain": subdomain,
        "domain": domain,
        "suffix": suffix,
        "registered_domain": registered_domain,
        "is_ip": False,
    }


def find_lookalike_brand(
    domain_or_host: str,
) -> Tuple[Optional[str], float, Optional[str]]:
    """
    Detects if a domain stem or hostname is attempting to impersonate or typosquat
    a known high-value brand.

    Returns:
        (matched_brand, confidence_score_0_to_100, reason_description)
        or (None, 0.0, None) if clean/no lookalike found.
    """
    if not domain_or_host:
        return None, 0.0, None

    parts = extract_domain_parts(domain_or_host)
    if parts["is_ip"]:
        return None, 0.0, None

    domain_stem = parts["domain"].lower()
    registered_domain = parts["registered_domain"].lower()
    fqdn = parts["fqdn"].lower()

    # Step 1: Check if registered domain is an authentic / official brand domain
    for brand, legit_domains in BRAND_LEGITIMATE_DOMAINS.items():
        if registered_domain in legit_domains:
            # Genuine official domain! Not a lookalike.
            return None, 0.0, None

    # Step 2: Check normalized homoglyph / leetspeak match (e.g. 'paypa1' -> 'paypal', 'micros0ft' -> 'microsoft')
    normalized_stem = normalize_homoglyphs(domain_stem)
    # Also test replacing '1' with 'i' (since '1' can be 'l' or 'i')
    normalized_stem_i = domain_stem.replace("1", "i")

    for brand in TARGET_BRANDS:
        # Direct exact match on normalized stem (e.g. 'paypa1' becomes 'paypal')
        if domain_stem != brand and (normalized_stem == brand or normalized_stem_i == brand):
            return brand, 95.0, f"Homoglyph/leetspeak look-alike of '{brand}'"

        # Combosquatting / hyphenated keywords with homoglyphs (e.g. 'paypa1-login', 'paypal-verify', 'login-paypal-sec')
        if brand in normalized_stem or brand in normalized_stem_i or brand in domain_stem:
            # If the actual brand name or homoglyph is embedded in the domain stem (e.g. paypa1-login)
            if registered_domain not in BRAND_LEGITIMATE_DOMAINS.get(brand, set()):
                return brand, 92.0, f"Deceptive brand combosquatting of '{brand}'"

        # Subdomain impersonation (e.g. 'paypal.com.attacker-domain.xyz' or 'login.paypal.verify-site.com')
        if parts["subdomain"]:
            sub_parts = parts["subdomain"].split(".")
            for sp in sub_parts:
                norm_sp = normalize_homoglyphs(sp)
                if norm_sp == brand or brand in norm_sp:
                    return brand, 88.0, f"Brand '{brand}' deceptive subdomain spoofing"

        # Step 3: Levenshtein distance on similar length domain stems (e.g., 'paypaal', 'microsft', 'gogle')
        # Only check brands with length >= 4 to avoid false positive matches on short words
        if len(brand) >= 4 and abs(len(domain_stem) - len(brand)) <= 2:
            dist = calculate_levenshtein_distance(domain_stem, brand)
            if dist == 1:
                return brand, 85.0, f"Typosquatting of '{brand}' (Levenshtein distance 1)"
            elif dist == 2 and len(brand) >= 7:
                return brand, 75.0, f"Typosquatting of '{brand}' (Levenshtein distance 2)"

    return None, 0.0, None


def has_suspicious_tld(domain_or_suffix: str) -> bool:
    """Check if the given domain or TLD suffix is in the suspicious TLD list."""
    if not domain_or_suffix:
        return False
    parts = extract_domain_parts(domain_or_suffix)
    suffix = parts["suffix"].lower()
    return suffix in SUSPICIOUS_TLDS


def count_subdomain_levels(host: str) -> int:
    """Count the depth/levels of subdomains in a host."""
    parts = extract_domain_parts(host)
    if not parts["subdomain"]:
        return 0
    return len(parts["subdomain"].split("."))
