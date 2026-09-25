import re
from urllib.parse import urlsplit


URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
URGENT_RE = re.compile(r"\b(urgent|immediately|within \d+ (?:hours?|minutes?)|act now|account (?:will be )?suspended|final warning)\b", re.IGNORECASE)
SECRET_RE = re.compile(r"\b(otp|one.time password|verification code|password|pin)\b", re.IGNORECASE)
REQUEST_RE = re.compile(r"\b(send|share|reply|provide|enter|confirm|verify|submit)\b", re.IGNORECASE)
MONEY_RE = re.compile(r"\b(gift card|wire transfer|bank details|payment details|upi pin)\b", re.IGNORECASE)


def check_message(message: str) -> dict:
    """Explain visible warning signs; do not visit URLs or claim to verify a sender."""
    findings = []
    if URGENT_RE.search(message):
        findings.append({"sign": "Pressure to act quickly", "advice": "Pause and check through the organisation's official app or website."})
    if SECRET_RE.search(message) and REQUEST_RE.search(message):
        findings.append({"sign": "Request for a secret or code", "advice": "Do not share passwords, PINs, or verification codes from a message."})
    if MONEY_RE.search(message):
        findings.append({"sign": "Money or payment request", "advice": "Confirm the request using a contact method you already trust."})

    urls = []
    for raw in URL_RE.findall(message):
        url = raw.rstrip(".,;!?)")
        urls.append(url)
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.scheme.lower() == "http":
            findings.append({"sign": "Unencrypted HTTP link", "advice": "Do not enter sensitive information on this link."})
        if "@" in parsed.netloc or host.startswith("xn--") or ".xn--" in host:
            findings.append({"sign": "Potentially misleading link", "advice": "Open the organisation's website yourself instead of using the message link."})

    score = min(100, len(findings) * 25)
    return {
        "risk_level": "high" if score >= 50 else "caution" if score else "unknown",
        "warning_signs": findings,
        "links_found": urls,
        "note": "This checks wording and link format only. No warning signs does not prove a message is safe.",
    }
