import json
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

HIBP_API = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "Cyber-Twin"


class BreachChecker:
    def check_breaches(self, domains):
        """Check service domains against HIBP's public breach list.

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
            f"{HIBP_API}/breaches",
            headers={"User-Agent": USER_AGENT},
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

    def check_email(self, email, api_key):
        """Look up one email address in HIBP's breached-account search.

        Needs an HIBP API key (https://haveibeenpwned.com/API/Key).
        Only the connected user's own address should be passed here.
        Network, HTTP and invalid-response errors propagate to the caller.
        """
        email = email.strip()
        if "@" not in email:
            raise ValueError("Provide an email address.")

        request = Request(
            f"{HIBP_API}/breachedaccount/{quote(email)}?truncateResponse=false",
            headers={"User-Agent": USER_AGENT, "hibp-api-key": api_key},
        )

        try:
            breaches = self._get_json(request)
        except HTTPError as error:
            if error.code != 404:
                raise
            breaches = []  # HIBP answers 404 when the address is in no breach.

        breaches = [
            {
                "name": breach["Title"],
                "domain": breach["Domain"],
                "breach_date": breach["BreachDate"],
                "data_exposed": breach["DataClasses"],
            }
            for breach in breaches
            if not breach["IsFabricated"]
        ]
        return {
            "email": email,
            "breached": bool(breaches),
            "breaches": sorted(
                breaches, key=lambda b: b["breach_date"], reverse=True
            ),
            "source": "https://haveibeenpwned.com/",
        }

    def _get_json(self, request):
        try:
            with urlopen(request, timeout=10) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code != 429:
                raise
            # Rate limited: wait as long as HIBP asks, then try once more.
            time.sleep(min(int(error.headers.get("Retry-After", "2")), 10))
            with urlopen(request, timeout=10) as response:
                return json.load(response)
