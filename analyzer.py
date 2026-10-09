from urllib.parse import urlparse
import ipaddress
import re


# Suspicious words commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "bank",
    "banking",
    "password",
    "signin",
    "wallet",
    "payment",
    "bonus",
    "reward",
    "claim",
    "urgent",
}


# Common URL-shortening services
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
}


# TLDs that deserve additional scrutiny
SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".zip",
    ".mov",
    ".work",
    ".loan",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
}


def is_ip_address(hostname):
    """Check whether the hostname is an IP address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url):
    """
    Analyze a URL and return a risk score, verdict and flags.
    """

    url = url.strip()

    if not url:
        raise ValueError("The QR code does not contain any URL.")

    # Add a scheme temporarily if missing
    parse_url = url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_url):
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    score = 0
    flags = []

    # -------------------------------------------------
    # 1. HTTPS check
    # -------------------------------------------------

    if parsed.scheme.lower() != "https":
        score += 10
        flags.append("Missing HTTPS scheme")

    # -------------------------------------------------
    # 2. URL length
    # -------------------------------------------------

    if len(url) > 100:
        score += 10
        flags.append("Long URL")

    if len(url) > 180:
        score += 10
        flags.append("Very long URL")

    # -------------------------------------------------
    # 3. IP address instead of domain
    # -------------------------------------------------

    if is_ip_address(hostname):
        score += 25
        flags.append("IP address used instead of domain")

    # -------------------------------------------------
    # 4. @ symbol
    # -------------------------------------------------

    if "@" in url:
        score += 20
        flags.append("@ symbol detected")

    # -------------------------------------------------
    # 5. Too many dots / subdomains
    # -------------------------------------------------

    dot_count = hostname.count(".")

    if dot_count >= 3:
        score += 10
        flags.append("Multiple subdomains detected")

    if dot_count >= 5:
        score += 10
        flags.append("Excessive number of subdomains")

    # -------------------------------------------------
    # 6. Hyphens
    # -------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 2:
        score += 5
        flags.append("Multiple hyphens in domain")

    if hyphen_count >= 4:
        score += 5
        flags.append("Many hyphens in domain")

    # -------------------------------------------------
    # 7. Digits in domain
    # -------------------------------------------------

    digit_count = sum(char.isdigit() for char in hostname)

    if digit_count >= 4:
        score += 5
        flags.append("Many digits in domain")

    # -------------------------------------------------
    # 8. Suspicious keywords
    # -------------------------------------------------

    url_lower = url.lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:
        score += min(len(found_keywords) * 5, 20)

        flags.append(
            "Suspicious keywords: " +
            ", ".join(sorted(found_keywords))
        )

    # -------------------------------------------------
    # 9. URL shortener
    # -------------------------------------------------

    if hostname in SHORTENERS:
        score += 15
        flags.append("URL shortening service detected")

    # -------------------------------------------------
    # 10. Suspicious TLD
    # -------------------------------------------------

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 15
            flags.append("Suspicious top-level domain")
            break

    # -------------------------------------------------
    # 11. Punycode / IDN
    # -------------------------------------------------

    if "xn--" in hostname:
        score += 20
        flags.append("Punycode / internationalized domain detected")

    # -------------------------------------------------
    # 12. Encoded characters
    # -------------------------------------------------

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))

    if encoded_count >= 3:
        score += 10
        flags.append("Multiple encoded characters detected")

    # -------------------------------------------------
    # 13. Special characters
    # -------------------------------------------------

    special_count = len(
        re.findall(r"[<>{}\[\]\\|^`]", url)
    )

    if special_count > 0:
        score += 10
        flags.append("Unusual special characters detected")

    # -------------------------------------------------
    # 14. Query length
    # -------------------------------------------------

    if len(parsed.query) > 80:
        score += 10
        flags.append("Long URL query detected")

    # -------------------------------------------------
    # 15. Path length
    # -------------------------------------------------

    if len(parsed.path) > 80:
        score += 5
        flags.append("Long URL path detected")

    # -------------------------------------------------
    # Limit score to 100
    # -------------------------------------------------

    score = min(score, 100)

    # -------------------------------------------------
    # Verdict
    # -------------------------------------------------

    if score >= 60:
        verdict = "MALICIOUS"

    elif score >= 30:
        verdict = "SUSPICIOUS"

    else:
        verdict = "SAFE"

    # If nothing suspicious was found
    if not flags:
        flags.append("No major risk indicators detected")

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "flags": flags,
    }