import json
from urllib.request import Request, urlopen


class BreachChecker:
    def check_breaches(self, domains):
        """Check service domains against HIBP, never individual email addresses.

        Pass bare domains from Module 1, such as ["canva.com"].
        Only exact domain matches are reported; no match does not mean safe.
        Network, HTTP and invalid-response errors propagate to the caller.
        """
        domains = [domain.strip().lower().rstrip(".") for domain in domains]
        if any(not domain or "@" in domain for domain in domains):
            raise ValueError("Provide non-empty service domains, not email addresses.")
        if not domains:
            return []

        request = Request(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "Cyber-Twin"},
        )
        with urlopen(request, timeout=10) as response:
            catalogue = json.load(response)

        results = []
        for domain in domains:
            breaches = [
                {"name": breach["Title"], "breach_date": breach["BreachDate"]}
                for breach in catalogue
                if breach["Domain"].lower() == domain
                and breach["IsVerified"]
                and not breach["IsFabricated"]
                and not breach["IsSpamList"]
                and not breach["IsMalware"]
            ]
            results.append({
                "domain": domain,
                "known_breach": bool(breaches),
                "breaches": breaches,
                "source": "https://haveibeenpwned.com/",
                "note": "Service breach history only; individual exposure is unknown.",
            })

        return results
