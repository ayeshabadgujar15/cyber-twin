"""Offline scanner and real ASGI route checks; no Gmail or breach network calls."""
import asyncio
import json
import unittest
from unittest.mock import MagicMock, patch

import app.main as main
from app.gmail.oauth import SCOPES
from app.gmail.scanner import GmailScanner


def request(path, query='', method='GET', payload=None, headers=None, return_headers=False):
    async def run():
        output = []
        async def receive():
            return {'type': 'http.request', 'body': json.dumps(payload).encode() if payload is not None else b'', 'more_body': False}
        async def send(message):
            output.append(message)
        await main.app({'type': 'http', 'asgi': {'version': '3.0'},
                        'http_version': '1.1', 'method': method, 'scheme': 'http',
                        'path': path, 'raw_path': path.encode(),
                        'query_string': query.encode(), 'root_path': '',
                        'headers': [(b'content-type', b'application/json')] + (headers or []), 'server': ('localhost', 8000),
                        'client': ('localhost', 1234)}, receive, send)
        body = b''.join(m.get('body', b'') for m in output)
        result = (output[0]['status'], json.loads(body) if body else None)
        return (*result, dict(output[0].get('headers', []))) if return_headers else result
    return asyncio.run(run())


class ScannerTests(unittest.TestCase):
    def scanner(self, pages):
        service = MagicMock()
        api = service.users.return_value.messages.return_value
        api.list.return_value.execute.side_effect = pages
        api.get.return_value.execute.return_value = {
            'internalDate': '1767225600000',
            'payload': {'headers': [
                {'name': 'fRoM', 'value': 'Example <alerts@example.com>'},
                {'name': 'sUbJeCt', 'value': 'New login detected'}]}}
        with patch('app.gmail.scanner.build', return_value=service):
            scanner = GmailScanner(object())
        return scanner, api

    def test_pagination_deduplication_metadata_and_coverage(self):
        scanner, api = self.scanner([
            {'messages': [{'id': '1'}], 'nextPageToken': 'next'},
            {'messages': [{'id': '1'}, {'id': '2'}]}])
        emails, coverage = scanner.scan_activity_emails(3)
        self.assertEqual(len(emails), 2)
        self.assertTrue(coverage['scan_complete'])
        self.assertEqual(emails[0]['sender_domain'], 'example.com')
        self.assertEqual(api.list.call_args_list[1].kwargs['pageToken'], 'next')
        for call in api.list.call_args_list:
            self.assertTrue(call.kwargs['includeSpamTrash'])
        for call in api.get.call_args_list:
            self.assertEqual(call.kwargs['format'], 'metadata')
            self.assertEqual(call.kwargs['metadataHeaders'], ['From', 'Subject', 'Date'])

    def test_limit_and_empty_mailbox(self):
        scanner, api = self.scanner([{'messages': [{'id': '1'}], 'nextPageToken': 'next'}])
        emails, coverage = scanner.scan_activity_emails(1)
        self.assertFalse(coverage['scan_complete'])
        self.assertEqual(api.list.call_count, 1)
        self.assertEqual(api.list.call_args.kwargs['maxResults'], 1)
        scanner, _ = self.scanner([{}])
        self.assertEqual(scanner.scan_activity_emails(1)[1]['messages_scanned'], 0)
        for limit in (-1, 10001, False, 0.0):
            with self.assertRaises(ValueError):
                scanner.scan_activity_emails(limit)

    def test_repeated_token_fails(self):
        scanner, _ = self.scanner([{'nextPageToken': 'x'}, {'nextPageToken': 'x'}])
        with self.assertRaises(ValueError):
            scanner.scan_activity_emails()

    def test_oversized_page_and_nonprogressing_pages_stay_bounded(self):
        scanner, api = self.scanner([{'messages': [{'id': '1'}, {'id': '2'}]}])
        emails, coverage = scanner.scan_activity_emails(1)
        self.assertEqual(len(emails), 1)
        self.assertEqual(api.get.call_count, 1)
        self.assertFalse(coverage['scan_complete'])
        scanner, api = self.scanner([{'nextPageToken': 'a'}, {'nextPageToken': 'b'}])
        emails, coverage = scanner.scan_activity_emails(2)
        self.assertFalse(coverage['scan_complete'])
        self.assertEqual(api.list.call_count, 2)
        for limit in (True, 1.5, '2'):
            with self.assertRaises(ValueError):
                scanner.scan_activity_emails(limit)

    def test_encoded_subject(self):
        scanner, api = self.scanner([{'messages': [{'id': '1'}]}])
        api.get.return_value.execute.return_value = {'payload': {'headers': [
            {'name': 'Subject', 'value': '=?utf-8?q?New_login_detected?='}]}}
        emails, _ = scanner.scan_activity_emails(1)
        self.assertEqual(emails[0]['subject'], 'New login detected')

    def test_registration_scan_remains_compatible(self):
        scanner, api = self.scanner([{'messages': [{'id': '1'}]}] * 9)
        api.get.return_value.execute.return_value = {'payload': {'headers': [
            {'name': 'From', 'value': 'Example <hello@example.com>'},
            {'name': 'Subject', 'value': 'Account created'},
            {'name': 'Date', 'value': '1 Jan 2026 10:00:00 +0000'}]}}
        emails = scanner.scan_registration_emails()
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0]['sender_domain'], 'example.com')
        self.assertEqual(api.list.call_count, 9)


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.credentials = main.gmail_credentials
        self.state = main.oauth_state
        main.gmail_credentials = None

    def tearDown(self):
        main.gmail_credentials = self.credentials
        main.oauth_state = self.state

    def test_auth_and_validation(self):
        self.assertEqual(request('/accounts/activity')[0], 401)
        self.assertEqual(request('/accounts/activity/example.com')[0], 401)
        for limit in ('0', '10001', 'abc'):
            self.assertEqual(request('/accounts/activity', 'max_messages=' + limit)[0], 422)
        self.assertIn('error', request('/accounts/discover')[1])
        self.assertEqual(SCOPES, ['https://www.googleapis.com/auth/gmail.readonly'])

    def test_activity_timeline_privacy_and_failure(self):
        main.gmail_credentials = object()
        coverage = {'messages_scanned': 1, 'scan_complete': False, 'message_limit': 1}
        def scan(*args):
            return [dict(sender_domain='example.com', message_id='1',
                         subject='New login detected', internal_date='1767225600000')], coverage
        with patch.object(main.GmailScanner, 'scan_activity_emails', side_effect=scan), patch('app.gmail.scanner.build'):
            status, body = request('/accounts/activity', 'max_messages=1')
            self.assertEqual(status, 200)
            self.assertEqual(body['services_found'], 1)
            self.assertFalse(body['coverage']['scan_complete'])
            self.assertNotIn('subject', json.dumps(body))
            self.assertEqual(body['services'][0]['timeline'][0]['event_type'], 'login')
            self.assertEqual(request('/accounts/activity/EXAMPLE.COM')[0], 200)
            self.assertEqual(request('/accounts/activity/missing.com')[0], 404)
        with patch.object(main.GmailScanner, 'scan_activity_emails', side_effect=OSError('private detail')), patch('app.gmail.scanner.build'):
            status, body = request('/accounts/activity')
            self.assertEqual(status, 502)
            self.assertNotIn('private detail', json.dumps(body))

    def test_discovery_and_oauth_routes(self):
        with patch.object(main, 'setup_status', return_value={'configured': True, 'dashboard_url': 'http://localhost:8000/'}), patch.object(main, 'get_authorization_url', return_value=('https://example.com/oauth', 'state')):
            self.assertEqual(request('/gmail/login')[0], 307)
            self.assertEqual(main.oauth_state, 'state')
        with patch.object(main, 'fetch_credentials', return_value=object()) as fetch:
            self.assertEqual(request('/gmail/callback', 'code=code&state=state', headers=[(b'cookie', b'cybertwin_oauth_state=state')])[0], 200)
            fetch.assert_called_once_with('code', 'state')
        with patch('app.gmail.scanner.build'), patch.object(main.GmailScanner, 'scan_registration_emails', return_value=[
            {'sender_domain': 'example.com', 'sender_name': 'Example', 'subject': 'Account created', 'date': '1 Jan 2026 10:00:00 +0000'}]), patch.object(main.BreachChecker, 'check_breaches', return_value=[{'known_breach': False, 'breaches': []}]):
            status, body = request('/accounts/discover')
            self.assertEqual(status, 200)
            self.assertEqual(body['accounts_found'], 1)
            self.assertEqual(body['accounts'][0]['breach_check']['status'], 'checked')


if __name__ == '__main__':
    unittest.main()
