from email.utils import parseaddr
from googleapiclient.discovery import build


class GmailScanner:
    def __init__(self, credentials):
        self.service = build("gmail", "v1", credentials=credentials)

    def scan_registration_emails(self):
        queries = [
            '"welcome"',
            '"verify your email"',
            '"verify your account"',
            '"confirm your email"',
            '"confirm your account"',
            '"thanks for signing up"',
            '"account created"',
            '"registration successful"',
            '"activate your account"',
        ]

        seen_ids = set()
        results = []

        for query in queries:
            response = self.service.users().messages().list(
                userId="me",
                q=query,
                maxResults=100
            ).execute()

            for item in response.get("messages", []):
                message_id = item["id"]

                if message_id in seen_ids:
                    continue

                seen_ids.add(message_id)

                message = self.service.users().messages().get(
                    userId="me",
                    id=message_id,
                    format="metadata",
                    metadataHeaders=["From", "Subject", "Date"]
                ).execute()

                headers = {
                    h["name"]: h["value"]
                    for h in message.get("payload", {}).get("headers", [])
                }

                sender_name, sender_email = parseaddr(
                    headers.get("From", "")
                )

                domain = ""
                if "@" in sender_email:
                    domain = sender_email.split("@")[-1].lower()

                results.append({
                    "sender_name": sender_name,
                    "sender_email": sender_email,
                    "sender_domain": domain,
                    "subject": headers.get("Subject", ""),
                    "date": headers.get("Date", ""),
                })

        return results