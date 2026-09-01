"""
Detection utilities package.
"""

from detection.utils.domain_utils import (
    extract_domain_parts,
    is_ip_address,
    is_punycode,
    normalize_homoglyphs,
    calculate_levenshtein_distance,
    find_lookalike_brand,
    has_suspicious_tld,
    count_subdomain_levels,
)
from detection.utils.text_utils import (
    clean_text,
    detect_zero_width_chars,
    detect_mixed_scripts,
    parse_email_address,
    extract_urls_from_text,
)

__all__ = [
    "extract_domain_parts",
    "is_ip_address",
    "is_punycode",
    "normalize_homoglyphs",
    "calculate_levenshtein_distance",
    "find_lookalike_brand",
    "has_suspicious_tld",
    "count_subdomain_levels",
    "clean_text",
    "detect_zero_width_chars",
    "detect_mixed_scripts",
    "parse_email_address",
    "extract_urls_from_text",
]
