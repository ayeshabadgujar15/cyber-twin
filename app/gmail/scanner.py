from email.utils import parseaddr
from email.header import decode_header, make_header
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth_httplib2 import AuthorizedHttp
from httplib2 import Http


class GmailScanner:
    def scan_activity_emails(self, max_messages=5000, progress_callback=None):
        """Bounded metadata scan across all folders, with explicit coverage gaps."""
        if isinstance(max_messages, int) and not isinstance(max_messages, bool) and max_messages == 0:
            from app.gmail.full_mailbox_scanner import scan_full_mailbox
            return scan_full_mailbox(self.service, self._decode_subject, progress_callback)
        if isinstance(max_messages, bool) or not isinstance(max_messages, int) or not 1 <= max_messages <= 10000:
            raise ValueError('max_messages must be between 1 and 10000')
        messages, seen_ids, seen_tokens = [], set(), set()
        page_token = None
        pages_scanned = unavailable = excluded = 0
        def report():
            if progress_callback:
                progress_callback({'message_fetches': len(seen_ids), 'messages_scanned': len(messages),
                                   'message_limit': max_messages, 'pages_scanned': pages_scanned,
                                   'unavailable_messages': unavailable, 'excluded_sent_or_draft': excluded})
        report()
        while True:
            pages_scanned += 1
            report()
            response = self.service.users().messages().list(
                userId='me', includeSpamTrash=True,
                maxResults=min(500, max_messages - len(seen_ids)),
                fields='messages/id,nextPageToken',
                **({'pageToken': page_token} if page_token else {}),
            ).execute(num_retries=2)
            truncated_page = False
            for item in response.get('messages', []):
                message_id = item['id']
                if message_id in seen_ids:
                    continue
                if len(seen_ids) >= max_messages:
                    truncated_page = True
                    break
                seen_ids.add(message_id)
                report()
                try:
                    message = self.service.users().messages().get(
                        userId='me', id=message_id, format='metadata',
                        metadataHeaders=['From', 'Subject', 'Date'],
                        fields='internalDate,labelIds,payload/headers',
                    ).execute(num_retries=2)
                except HttpError as error:
                    if error.resp.status != 404:
                        raise
                    unavailable += 1  # Deleted between list and get; no content retained.
                    report()
                    continue
                if {'SENT', 'DRAFT'}.intersection(message.get('labelIds', [])):
                    excluded += 1
                    report()
                    continue
                headers = {h['name'].lower(): h['value'] for h in message.get('payload', {}).get('headers', [])}
                _, sender = parseaddr(headers.get('from', ''))
                messages.append({
                    'message_id': message_id,
                    'sender_domain': sender.rsplit('@', 1)[-1].lower() if '@' in sender else '',
                    'subject': self._decode_subject(headers.get('subject', '')),
                    'date': headers.get('date', ''),
                    'internal_date': message.get('internalDate'),
                })
                report()
            page_token = response.get('nextPageToken')
            if not page_token or len(seen_ids) >= max_messages or pages_scanned >= max_messages:
                exhausted = not bool(page_token) and not truncated_page
                reason = ('mailbox_end' if exhausted else
                          'message_limit' if len(seen_ids) >= max_messages else 'page_limit')
                return messages, {
                    'messages_scanned': len(messages), 'message_fetches': len(seen_ids),
                    'scan_complete': exhausted and unavailable == 0,
                    'message_limit': max_messages, 'pages_scanned': pages_scanned,
                    'unavailable_messages': unavailable, 'excluded_sent_or_draft': excluded,
                    'stop_reason': reason,
                }
            if page_token in seen_tokens:
                raise ValueError('Gmail returned a repeated pagination token')
            seen_tokens.add(page_token)

    @staticmethod
    def _decode_subject(subject):
        try:
            return str(make_header(decode_header(subject)))
        except (LookupError, UnicodeError, ValueError):
            return subject

    def __init__(self, credentials):
        self.service = build("gmail", "v1", http=AuthorizedHttp(credentials, http=Http(timeout=30)))

    def get_email_address(self):
        return self.service.users().getProfile(userId='me').execute(num_retries=2)['emailAddress']

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
