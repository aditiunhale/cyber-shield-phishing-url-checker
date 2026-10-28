"""Rule-based URL checks for the CyberShield learning tool.

This module deliberately performs no network requests. It only parses the
submitted text and looks for a small set of common warning signs.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


MAX_URL_LENGTH = 2048

SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "password",
    "otp",
    "bank",
    "wallet",
    "confirm",
    "billing",
    "urgent",
    "reward",
    "gift",
    "refund",
    "payment",
    "unlock",
)

KNOWN_BRANDS = {
    "amazon": {"amazon.com", "amazon.in"},
    "apple": {"apple.com", "icloud.com"},
    "facebook": {"facebook.com"},
    "google": {"google.com", "google.co.in"},
    "instagram": {"instagram.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "sbi": {"sbi.co.in"},
}

MULTI_PART_SUFFIXES = {
    "co.in",
    "com.in",
    "net.in",
    "org.in",
    "co.uk",
    "org.uk",
    "com.au",
    "net.au",
    "co.nz",
    "co.jp",
}

EMBEDDED_DOMAIN_SUFFIX = re.compile(
    r"\.(?:com|net|org|gov|edu|co\.in|com\.in|co\.uk|com\.au)\."
)


class URLValidationError(ValueError):
    """Raised when a submitted value is not a valid HTTP(S) URL."""


def _validated_host(host: str) -> tuple[str, bool]:
    """Return a normalized host and whether it is an IP address."""
    normalized = host.rstrip(".").lower()
    if not normalized:
        raise URLValidationError("Enter a URL with a valid host name.")

    try:
        ipaddress.ip_address(normalized)
        return normalized, True
    except ValueError:
        pass

    try:
        ascii_host = normalized.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise URLValidationError("The host name is not valid.") from exc

    if len(ascii_host) > 253:
        raise URLValidationError("The host name is too long.")

    labels = ascii_host.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise URLValidationError("The host name contains invalid characters.")

    return ascii_host, False


def _registrable_domain(host: str) -> str:
    """Estimate a registrable domain using a small suffix list.

    This is intentionally only a heuristic, not a public-suffix database.
    """
    labels = host.split(".")
    if len(labels) < 2:
        return host

    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _misleading_domain_reasons(host: str) -> list[str]:
    labels = host.split(".")
    reasons: list[str] = []

    if EMBEDDED_DOMAIN_SUFFIX.search(host):
        reasons.append("A familiar-looking domain ending appears inside the host name.")

    registered_domain = _registrable_domain(host)
    for brand, official_domains in KNOWN_BRANDS.items():
        brand_appears = any(brand in label for label in labels)
        if brand_appears and registered_domain not in official_domains:
            reasons.append(
                f"The name includes “{brand}” but the main domain is {registered_domain}."
            )
            break

    if len(labels) > 4:
        reasons.append("The host uses several nested subdomains.")

    return reasons


def check_url(value: str) -> dict[str, object]:
    """Validate a URL and return observed warning signs and safety guidance."""
    if not isinstance(value, str) or not value.strip():
        raise URLValidationError("Enter a URL to check.")

    raw_url = value.strip()
    if len(raw_url) > MAX_URL_LENGTH:
        raise URLValidationError(f"Keep the URL under {MAX_URL_LENGTH} characters.")
    if any(character.isspace() or ord(character) < 32 for character in raw_url):
        raise URLValidationError("Remove spaces and control characters from the URL.")

    if not re.match(r"^https?://", raw_url, flags=re.IGNORECASE):
        raise URLValidationError("Include http:// or https:// at the start of the URL.")

    try:
        parsed = urlsplit(raw_url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise URLValidationError("Only http:// and https:// URLs can be checked.")
        host_value = parsed.hostname
        if not parsed.netloc or not host_value:
            raise URLValidationError("Enter a URL with a valid host name.")
        # Accessing .port also validates that a provided port is numeric and in range.
        _ = parsed.port
        host, is_ip = _validated_host(host_value)
    except ValueError as exc:
        if isinstance(exc, URLValidationError):
            raise
        raise URLValidationError("That URL could not be parsed. Check its format.") from exc

    findings: list[dict[str, str]] = []
    score = 0

    def add_finding(
        title: str,
        detail: str,
        advice: str,
        weight: int,
        severity: str = "caution",
    ) -> None:
        nonlocal score
        score += weight
        findings.append(
            {
                "title": title,
                "detail": detail,
                "advice": advice,
                "severity": severity,
            }
        )

    if "@" in parsed.netloc:
        add_finding(
            "An @ symbol appears before the host",
            "Text before @ can look like a trusted site name, while the browser treats the host after @ as the destination.",
            "Read the host after @ carefully. Do not sign in unless you reached the organization through a source you trust.",
            3,
            "high",
        )

    if is_ip:
        add_finding(
            "The host is an IP address",
            "This URL points to a numeric network address instead of a recognizable domain name.",
            "Avoid entering credentials or payment details. Open the organization’s official site by typing its known address yourself.",
            3,
            "high",
        )

    domain_reasons = _misleading_domain_reasons(host)
    if domain_reasons:
        add_finding(
            "The domain structure may be misleading",
            " ".join(domain_reasons),
            "Focus on the main registered domain, not words or domain endings placed in front of it. Verify the address independently.",
            2,
            "high" if any("includes" in reason for reason in domain_reasons) else "caution",
        )

    if "xn--" in host:
        add_finding(
            "The host contains an internationalized domain label",
            "Some international characters can resemble familiar Latin letters in a domain name.",
            "Check the domain through a trusted bookmark or by typing the official address yourself.",
            2,
        )

    url_text = f"{host}{parsed.path}{parsed.query}".lower()
    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(rf"\b{re.escape(keyword)}\b", url_text)
    ]
    if matched_keywords:
        shown_keywords = ", ".join(matched_keywords[:5])
        add_finding(
            "The URL contains commonly used lure words",
            f"Found: {shown_keywords}. These words can appear in legitimate URLs too, but are often used to create urgency or request account action.",
            "Do not follow a sign-in or verification link from an unexpected message. Visit the service directly instead.",
            2,
        )

    if parsed.scheme.lower() == "http":
        add_finding(
            "The connection does not use HTTPS",
            "HTTP does not encrypt the connection between your browser and the site.",
            "Do not submit sensitive information over this link. HTTPS alone also does not prove a site is legitimate.",
            1,
        )

    has_high_signal = any(finding["severity"] == "high" for finding in findings)
    if has_high_signal:
        status = "elevated"
        summary = (
            "Multiple warning signs found"
            if len(findings) > 1
            else "A high-priority warning sign was found"
        )
    elif score:
        status = "caution"
        summary = "Warning signs found"
    else:
        status = "no-signals"
        summary = "No common warning signs detected"

    interpretation_note = (
        "No common warning sign was found; that does not prove the URL is trustworthy."
        if not findings
        else "Detected patterns are indicators, not proof that a site is harmful."
    )

    return {
        "host": host,
        "scheme": parsed.scheme.lower(),
        "status": status,
        "summary": summary,
        "findings": findings,
        "next_steps": [
            "Do not enter a password, one-time passcode, card number, or recovery code after following an unexpected link.",
            "If the message claims to be from an organization, contact it using the official app, a saved bookmark, or a phone number you already trust.",
            f"{interpretation_note} This learning aid uses simple rules, does not check the live website, and cannot guarantee safety.",
        ],
    }
