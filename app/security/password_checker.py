import re


COMMON = {"password", "password123", "123456", "12345678", "123456789", "qwerty", "qwerty123", "admin", "letmein", "welcome", "iloveyou"}


def check_password(password: str) -> dict:
    """Check a password in memory; never return it or send it to another service."""
    lower = password.lower()
    findings = []
    if len(password) < 12:
        findings.append("Use at least 12 characters; longer is better.")
    if lower in COMMON:
        findings.append("This is a commonly guessed password.")
    if re.search(r"(1234|abcd|qwerty|asdf|password|letmein)", lower):
        findings.append("Avoid common words and keyboard or number sequences.")
    if re.search(r"(.)\1{3,}", password):
        findings.append("Avoid repeated characters.")

    classes = sum(bool(re.search(pattern, password)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
    variety = min(24, classes * 6)
    score = min(100, len(password) * 4 + variety)
    if lower in COMMON:
        score = min(score, 10)
    if any("sequences" in item or "repeated" in item for item in findings):
        score = min(score, 45)
    if len(password) < 12:
        score = min(score, 45)
    return {
        "rating": "strong" if score >= 80 else "moderate" if score >= 50 else "weak",
        "score": score,
        "suggestions": findings or ["Use a unique password for every account and enable two-factor authentication."],
        "note": "Local pattern check only; this does not establish whether a password has leaked. Avoid entering a real password into an unfamiliar website.",
    }
