import time
from email.utils import parseaddr

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Gmail allows 250 quota units per user per second and messages.get costs 5,
# so 50 requests per batch keeps each batch within one second's quota.
BATCH_SIZE = 50
LIST_PAGE_SIZE = 500
MAX_RETRIES = 6
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}


class GmailScanner:
    def __init__(self, credentials):
        self.service = build(
            "gmail", "v1", credentials=credentials, cache_discovery=False
        )

    def get_email_address(self):
        profile = self.service.users().getProfile(userId="me").execute()
        return profile["emailAddress"]

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

    def scan_inbox(self, on_progress=None):
        """Read the sender, subject and date of every message in the mailbox.

        Spam and trash are skipped and message bodies are never requested.
        on_progress(phase, done, total) is called as the scan advances;
        phase is "listing" while message IDs are collected (total is None),
        then "reading" while headers are fetched.
        """
        report = on_progress or (lambda phase, done, total: None)

        message_ids = self._list_message_ids(report)
        total = len(message_ids)
        report("reading", 0, total)

        results = []
        for start in range(0, total, BATCH_SIZE):
            chunk = message_ids[start:start + BATCH_SIZE]
            for message in self._fetch_metadata(chunk):
                results.append(self._parse_message(message))
            report("reading", min(start + BATCH_SIZE, total), total)

        return results

    def _list_message_ids(self, report):
        message_ids = []
        page_token = None

        while True:
            response = self.service.users().messages().list(
                userId="me",
                maxResults=LIST_PAGE_SIZE,
                pageToken=page_token,
                includeSpamTrash=False,
            ).execute()

            message_ids.extend(
                item["id"] for item in response.get("messages", [])
            )
            report("listing", len(message_ids), None)

            page_token = response.get("nextPageToken")
            if not page_token:
                return message_ids

    def _fetch_metadata(self, message_ids):
        messages = []
        pending = list(message_ids)

        for attempt in range(MAX_RETRIES + 1):
            retry = []
            errors = []

            def handle(request_id, response, exception):
                if exception is None:
                    messages.append(response)
                elif _is_retryable(exception):
                    retry.append(request_id)
                elif _status(exception) == 404:
                    pass  # Deleted while the scan was running.
                else:
                    errors.append(exception)

            batch = self.service.new_batch_http_request(callback=handle)
            for message_id in pending:
                batch.add(
                    self.service.users().messages().get(
                        userId="me",
                        id=message_id,
                        format="metadata",
                        metadataHeaders=["From", "Subject", "Date"],
                    ),
                    request_id=message_id,
                )
            batch.execute()

            if errors:
                raise errors[0]
            if not retry:
                return messages

            pending = retry
            time.sleep(min(2 ** attempt, 32))

        raise RuntimeError("Gmail kept rate-limiting the scan. Try again later.")

    def _parse_message(self, message):
        headers = {
            h["name"].lower(): h["value"]
            for h in message.get("payload", {}).get("headers", [])
        }

        sender_name, sender_email = parseaddr(headers.get("from", ""))

        domain = ""
        if "@" in sender_email:
            domain = sender_email.split("@")[-1].lower()

        return {
            "sender_name": sender_name,
            "sender_email": sender_email,
            "sender_domain": domain,
            "subject": headers.get("subject", ""),
            "date": headers.get("date", ""),
        }


def _status(exception):
    if isinstance(exception, HttpError):
        return exception.resp.status
    return None


def _is_retryable(exception):
    status = _status(exception)
    if status in RETRYABLE_STATUSES:
        return True
    # Gmail reports per-user rate limits as 403 with a rateLimitExceeded reason.
    return status == 403 and b"ateLimitExceeded" in (exception.content or b"")
