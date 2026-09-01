"""
Configuration, constants, risk weights, brand databases, and detection dictionaries
for the PhishGuard Phishing Detection Engine.
"""

from typing import Dict, List, Set

# ==============================================================================
# 1. RISK SCORING WEIGHTS & VERDICT THRESHOLDS
# ==============================================================================

# Sub-module component weights (must sum to 1.0)
WEIGHT_SENDER_DOMAIN: float = 0.30
WEIGHT_URL: float = 0.25
WEIGHT_AUTH: float = 0.15
WEIGHT_CONTENT: float = 0.15
WEIGHT_ATTACHMENT: float = 0.15

# Verdict Score Thresholds
# 0 - 39   => SAFE
# 40 - 69  => SUSPICIOUS
# 70 - 100 => HIGH_RISK
THRESHOLD_SAFE_MAX: int = 39
THRESHOLD_SUSPICIOUS_MAX: int = 69

VERDICT_SAFE: str = "SAFE"
VERDICT_SUSPICIOUS: str = "SUSPICIOUS"
VERDICT_HIGH_RISK: str = "HIGH_RISK"


# ==============================================================================
# 2. TARGET BRANDS & LEGITIMATE DOMAIN MAP
# ==============================================================================

# High-profile brands frequently targeted by phishing campaigns
TARGET_BRANDS: Set[str] = {
    "paypal",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "netflix",
    "chase",
    "bankofamerica",
    "wellsfargo",
    "citibank",
    "citi",
    "facebook",
    "meta",
    "instagram",
    "linkedin",
    "twitter",
    "x",
    "dropbox",
    "adobe",
    "docusign",
    "office365",
    "outlook",
    "yahoo",
    "binance",
    "coinbase",
    "metamask",
    "kraken",
    "stripe",
    "dhl",
    "fedex",
    "ups",
    "usps",
    "irs",
    "hmrc",
    "walmart",
    "target",
    "ebay",
    "shopify",
    "spotify",
    "whatsapp",
    "telegram",
    "slack",
    "zoom",
    "github",
    "gitlab",
    "steampowered",
    "steam"
}

# Authentic / Official domain mappings for key target brands
BRAND_LEGITIMATE_DOMAINS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypal-communication.com", "paypal-community.com"},
    "microsoft": {"microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "microsoftonline.com", "msn.com", "azure.com", "bing.com"},
    "apple": {"apple.com", "icloud.com", "itunes.com", "apple-support.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googlemail.com", "googleapis.com", "google.co.uk", "google.co.in", "google.de"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.ca", "aws.amazon.com", "amazonses.com", "primevideo.com"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com", "jpmorgan.com", "jpmorganchase.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citi": {"citi.com", "citibank.com"},
    "citibank": {"citibank.com", "citi.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "meta": {"meta.com", "facebook.com", "instagram.com", "whatsapp.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "office365": {"office.com", "office365.com", "microsoft.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "microsoft.com", "live.com", "hotmail.com"},
    "yahoo": {"yahoo.com", "ymail.com", "yahoo.co.uk", "yahoo.co.in"},
    "binance": {"binance.com", "binance.us"},
    "coinbase": {"coinbase.com"},
    "stripe": {"stripe.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com", "usps.gov"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de"},
    "spotify": {"spotify.com"},
    "github": {"github.com"},
    "gitlab": {"gitlab.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "slack": {"slack.com"},
    "whatsapp": {"whatsapp.com"}
}


# ==============================================================================
# 3. SUSPICIOUS TLDs, FREE WEBERVICES & SHORTENERS
# ==============================================================================

# High-abuse TLDs frequently encountered in spam/phishing infrastructures
SUSPICIOUS_TLDS: Set[str] = {
    "top", "xyz", "work", "click", "buzz", "cfd", "rest", "gq", "ml", "cf",
    "ga", "tk", "fit", "icu", "sbs", "monster", "quest", "live", "stream",
    "surf", "zip", "mov", "country", "kim", "party", "racing", "science",
    "download", "accountant", "faith", "review", "trade", "bid", "loan",
    "date", "wang", "win", "men", "club", "online", "site", "website",
    "space", "link", "guru", "uno", "casa", "mom", "vip", "pw"
}

# Free Webmail providers (used to detect executive / brand display name impersonation)
FREE_WEBMAIL_DOMAINS: Set[str] = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "msn.com", "aol.com", "mail.com",
    "protonmail.com", "proton.me", "zoho.com", "yandex.com", "gmx.com",
    "gmx.net", "tutanota.com", "tuta.io", "icloud.com", "fastmail.com"
}

# Known URL shortening services
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "shorturl.at", "tiny.cc", "cutt.ly", "rb.gy",
    "rebrand.ly", "bl.ink", "trib.al", "qr.ae", "v.gd", "shorte.st"
}


# ==============================================================================
# 4. ATTACHMENT RISK LISTS
# ==============================================================================

# Dangerous executable / script extensions
DANGEROUS_EXECUTABLE_EXTENSIONS: Set[str] = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".ps1", ".psm1", ".psd1", ".msi", ".msp", ".com",
    ".pif", ".reg", ".jar", ".vhd", ".vhdx", ".cpl", ".inf", ".lnk",
    ".gadget", ".application", ".msc"
}

# Macro-enabled document extensions
MACRO_DOCUMENT_EXTENSIONS: Set[str] = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm",
    ".ppam", ".ppsm", ".sldm"
}

# Container and archive extensions that may package malicious payloads
ARCHIVE_EXTENSIONS: Set[str] = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab",
    ".iso", ".img", ".dmg", ".pkg"
}

# Safe benign extensions
BENIGN_EXTENSIONS: Set[str] = {
    ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".png", ".jpg",
    ".jpeg", ".gif", ".svg", ".mp3", ".mp4", ".mov", ".wav"
}


# ==============================================================================
# 5. CONTENT / NLP ANALYSIS DICTIONARIES & REGEXES
# ==============================================================================

# Urgency & coercive phrasing patterns
URGENCY_PATTERNS: List[str] = [
    r"\baccount\s+(?:will\s+be|has\s+been|is)\s+(?:suspended|terminated|locked|closed|disabled)\b",
    r"\bimmediate(?:ly)?\s+action\s+required\b",
    r"\bverify\s+your\s+account\s+(?:immediately|now|within\s+\d+\s+hours?)\b",
    r"\bsuspended\s+within\s+\d+\s+hours?\b",
    r"\baction\s+required\b",
    r"\bsecurity\s+alert\b",
    r"\bunauthorized\s+access(?:\s+detected)?\b",
    r"\bunusual\s+(?:activity|login|sign-in)\b",
    r"\btemporarily\s+(?:locked|restricted|suspended)\b",
    r"\bsecurity\s+warning\b",
    r"\bfinal\s+notice\b",
    r"\bdeadline\b",
    r"\baccount\s+deletion\b",
    r"\brestricted\s+access\b",
    r"\bfailure\s+to\s+respond\b",
    r"\btake\s+action\s+now\b",
    r"\bwithin\s+24\s+hours\b",
    r"\bwithin\s+48\s+hours\b"
]

# Credential harvesting indicators
CREDENTIAL_HARVESTING_PATTERNS: List[str] = [
    r"\bverify\s+your\s+(?:account|identity|information|details|credentials|email)\b",
    r"\bconfirm\s+your\s+(?:password|identity|account|credentials|pin)\b",
    r"\blogin\s+to\s+(?:verify|confirm|unlock|update|restore)\b",
    r"\bupdate\s+your\s+(?:credentials|password|billing|account\s+details)\b",
    r"\breset\s+your\s+password\b",
    r"\benter\s+your\s+(?:login|credentials|password|passcode|ssn)\b",
    r"\bvalidate\s+your\s+account\b",
    r"\bsecurity\s+verification\b",
    r"\bauthenticate\s+your\s+account\b",
    r"\bre-enter\s+your\s+password\b",
    r"\bclick\s+here\s+to\s+(?:verify|login|unlock|update)\b"
]

# Payment / Financial fraud patterns
FINANCIAL_FRAUD_PATTERNS: List[str] = [
    r"\bwire\s+transfer\b",
    r"\boverdue\s+invoice\b",
    r"\bgift\s+card\b",
    r"\bbitcoin\b",
    r"\bcryptocurrency\b",
    r"\bwallet\s+address\b",
    r"\bpayment\s+pending\b",
    r"\bbilling\s+error\b",
    r"\bdirect\s+deposit\b",
    r"\btax\s+refund\b",
    r"\bpurchase\s+confirmation\b",
    r"\brefund\s+request\b",
    r"\bunpaid\s+bill\b",
    r"\bpayment\s+declined\b"
]

# Suspicious / Generic greetings
GENERIC_GREETING_PATTERNS: List[str] = [
    r"\bdear\s+customer\b",
    r"\bdear\s+user\b",
    r"\bdear\s+client\b",
    r"\bvalued\s+member\b",
    r"\bvalued\s+customer\b",
    r"\bdear\s+account\s+holder\b",
    r"\bdear\s+member\b",
    r"\bdear\s+sir\/madam\b",
    r"\battention\s+user\b"
]


# ==============================================================================
# 6. HOMOGLYPH & CHARACTER REPLACEMENTS
# ==============================================================================

# Mapping lookalike characters (Cyrillic, Greek, leetspeak numbers) to ASCII equivalents
HOMOGLYPH_MAP: Dict[str, str] = {
    # Numbers used in leetspeak
    "0": "o",
    "1": "l",  # also checked for 'i'
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
    "vv": "w",
    # Cyrillic small letters
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u04bb": "h",  # һ
    "\u043a": "k",  # к
    # Greek small letters
    "\u03b1": "a",  # α
    "\u03bf": "o",  # ο
    "\u03c1": "p",  # ρ
    "\u03bd": "v",  # ν
    # Fullwidth / special
    "\uff41": "a",
    "\uff45": "e",
    "\uff49": "i",
    "\uff4f": "o",
    "\uff55": "u"
}
