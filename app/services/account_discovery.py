from datetime import datetime
from email.utils import parsedate_to_datetime


class AccountDiscoveryService:
    def discover_accounts(self, emails):
        accounts = {}

        for email in emails:
            domain = email.get("sender_domain", "").strip().lower()

            if not domain:
                continue

            # Skip obvious Google/Gmail system emails
            if domain in {
                "google.com",
                "gmail.com",
                "accounts.google.com",
            }:
                continue

            service_name = self._service_name(
                email.get("sender_name", ""),
                domain,
            )

            email_date = self._parse_date(email.get("date", ""))

            if domain not in accounts:
                accounts[domain] = {
                    "service_name": service_name,
                    "domain": domain,
                    "first_seen": email_date,
                    "evidence_subject": email.get("subject", ""),
                }
            else:
                old_date = accounts[domain]["first_seen"]

                if email_date and (
                    not old_date or email_date < old_date
                ):
                    accounts[domain]["first_seen"] = email_date
                    accounts[domain]["evidence_subject"] = email.get(
                        "subject", ""
                    )

        results = []

        for account in accounts.values():
            if account["first_seen"]:
                account["first_seen"] = account[
                    "first_seen"
                ].strftime("%Y-%m-%d")
            else:
                account["first_seen"] = None

            results.append(account)

        return sorted(
            results,
            key=lambda x: x["service_name"].lower()
        )

    def _service_name(self, sender_name, domain):
        if sender_name:
            return sender_name.strip()

        base = domain.split(".")[0]
        return base.replace("-", " ").title()

    def _parse_date(self, date_string):
        if not date_string:
            return None

        try:
            return parsedate_to_datetime(date_string)
        except Exception:
            return None