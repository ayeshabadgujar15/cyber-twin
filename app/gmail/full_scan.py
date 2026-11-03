"""Paginated full-mailbox metadata scan, adapted from the GitHub batch scanner.

Unlike the former scanner, retains message IDs, receipt dates and coverage gaps,
excludes sent/draft labels, detects pagination loops and supports cancellation.
"""
import time
from email.utils import parseaddr
from googleapiclient.errors import HttpError

BATCH_SIZE = 50
MAX_RETRIES = 3


def retryable(error):
    if not isinstance(error, HttpError):
        return False
    return error.resp.status in {429, 500, 502, 503, 504} or (
        error.resp.status == 403 and b'ateLimitExceeded' in (error.content or b''))


def scan_full_mailbox(service, decode_subject, progress_callback=None):
    messages, seen_ids, seen_tokens = [], set(), set()
    page_token = None
    pages = unavailable = excluded = fetched = 0

    def report():
        if progress_callback:
            progress_callback({'message_fetches': fetched, 'messages_scanned': len(messages),
                               'message_limit': 0, 'pages_scanned': pages,
                               'unavailable_messages': unavailable,
                               'excluded_sent_or_draft': excluded})

    try:
        while True:
            report()
            pages += 1
            page = service.users().messages().list(
                userId='me', includeSpamTrash=True, maxResults=500,
                fields='messages/id,nextPageToken',
                **({'pageToken': page_token} if page_token else {})).execute(num_retries=2)
            ids = []
            for item in page.get('messages', []):
                if item['id'] not in seen_ids:
                    ids.append(item['id'])
                    seen_ids.add(item['id'])
            for start in range(0, len(ids), BATCH_SIZE):
                pending = ids[start:start + BATCH_SIZE]
                for attempt in range(MAX_RETRIES + 1):
                    report()
                    retry, errors = [], []

                    def handle(request_id, response, exception):
                        nonlocal unavailable, excluded, fetched
                        if exception is not None:
                            if isinstance(exception, HttpError) and exception.resp.status == 404:
                                unavailable += 1
                                fetched += 1
                            elif retryable(exception) and attempt < MAX_RETRIES:
                                retry.append(request_id)
                            else:
                                errors.append(exception)
                            return
                        fetched += 1
                        if {'SENT', 'DRAFT'}.intersection(response.get('labelIds', [])):
                            excluded += 1
                            return
                        headers = {h['name'].lower(): h['value'] for h in response.get('payload', {}).get('headers', [])}
                        _, sender = parseaddr(headers.get('from', ''))
                        messages.append({'message_id': request_id,
                                         'sender_domain': sender.rsplit('@', 1)[-1].lower() if '@' in sender else '',
                                         'subject': decode_subject(headers.get('subject', '')),
                                         'date': headers.get('date', ''),
                                         'internal_date': response.get('internalDate')})

                    batch = service.new_batch_http_request(callback=handle)
                    for message_id in pending:
                        batch.add(service.users().messages().get(
                            userId='me', id=message_id, format='metadata',
                            metadataHeaders=['From', 'Subject', 'Date'],
                            fields='internalDate,labelIds,payload/headers'), request_id=message_id)
                    batch.execute()
                    report()
                    if errors:
                        raise errors[0]
                    # Pace batches; retries retain only the failed message IDs.
                    time.sleep(min(2 ** attempt, 8) if retry else 1)
                    if not retry:
                        break
                    pending = retry
            page_token = page.get('nextPageToken')
            if not page_token:
                return messages, {'messages_scanned': len(messages), 'message_fetches': fetched,
                                  'message_limit': 0, 'pages_scanned': pages,
                                  'unavailable_messages': unavailable,
                                  'excluded_sent_or_draft': excluded,
                                  'scan_complete': unavailable == 0, 'stop_reason': 'mailbox_end'}
            if page_token in seen_tokens:
                raise ValueError('Gmail returned a repeated pagination token')
            seen_tokens.add(page_token)
    except BaseException:
        messages.clear()
        raise
