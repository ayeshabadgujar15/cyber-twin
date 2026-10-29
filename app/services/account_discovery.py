import re
from datetime import timezone
from email.utils import parsedate_to_datetime

# Subjects that show the mailbox owner has an account with the sender:
# sign-ups, verification, sign-in and password mail, receipts and billing.
ACCOUNT_SUBJECT = re.compile(
    r"welcome"
    r"|verif(y|ication)"
    r"|confirm (your|my)? ?(email|e-mail|account|registration|sign ?up|subscription)"
    r"|activat(e|ion)"
    r"|thanks? (you )?for (signing up|joining|registering|creating|subscribing)"
    r"|sign(ed|ing)? ?up"
    r"|regist(er|ered|ration)"
    r"|account"
    r"|password"
    r"|sign(-| )?in|log(-| )?in|new device"
    r"|security (alert|code|notice)"
    r"|two-factor|2-step|2fa|one-time (code|password|passcode)"
    r"|your (order|receipt|invoice|subscription|membership|trial|plan|booking)",
    re.IGNORECASE,
)

# Personal mailbox providers: mail from these domains is from people,
# not services. Google is skipped because the user is already on Gmail.
IGNORED_DOMAINS = {
    "google.com", "gmail.com", "googlemail.com",
    "yahoo.com", "ymail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com",
    "yandex.com", "zoho.com",
}

# Second-level labels used under country codes, e.g. example.co.uk.
COUNTRY_SECOND_LEVEL = {
    "ac", "co", "com", "edu", "gob", "gov", "go", "ltd", "ne", "net",
    "or", "org", "plc",
}


class AccountDiscoveryService:
    def discover_accounts(self, emails):
        accounts = {}

        for email in emails:
            sender_domain = email.get("sender_domain", "").strip().lower()

            if not sender_domain:
                continue

            domain = base_domain(sender_domain)
            if domain in IGNORED_DOMAINS:
                continue

            subject = email.get("subject", "")
            if not ACCOUNT_SUBJECT.search(subject):
                continue

            email_date = self._parse_date(email.get("date", ""))

            if domain not in accounts:
                accounts[domain] = {
                    "service_name": self._service_name(
                        email.get("sender_name", ""), domain
                    ),
                    "domain": domain,
                    "first_seen": email_date,
                    "evidence_subject": subject,
                    "account_emails": 1,
                }
                continue

            account = accounts[domain]
            account["account_emails"] += 1
            old_date = account["first_seen"]

            if email_date and (not old_date or email_date < old_date):
                account["first_seen"] = email_date
                account["evidence_subject"] = subject
                account["service_name"] = self._service_name(
                    email.get("sender_name", ""), domain
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
            parsed = parsedate_to_datetime(date_string)
        except Exception:
            return None

        # Dates with a "-0000" zone parse as naive; make every date comparable.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed


def base_domain(domain):
    """Reduce a sender domain to the service's own domain.

    mail.canva.com -> canva.com, email.bbc.co.uk -> bbc.co.uk.
    """
    labels = domain.rstrip(".").split(".")
    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in COUNTRY_SECOND_LEVEL
    ):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
