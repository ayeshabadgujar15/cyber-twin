import unittest
from unittest.mock import MagicMock, patch
from httplib2 import Response
from googleapiclient.errors import HttpError

from app.gmail.full_scan import scan_full_mailbox
from app.gmail.scanner import GmailScanner
from app.services.account_discovery import AccountDiscoveryService
from app.services.scan_jobs import ScanCancelled, ScanJobManager
from test_activity_integration import request
import app.main as main


def message(labels=None):
    return {'internalDate': '1767225600000', 'labelIds': labels or [],
            'payload': {'headers': [{'name':'From', 'value':'Test <notice@example.com>'},
                                    {'name':'Subject', 'value':'New login detected'}]}}


class FullMailboxTests(unittest.TestCase):
    def service(self, pages, failures=None):
        service = MagicMock()
        service.users().messages().list().execute.side_effect = pages
        failures = failures or {}
        attempts = {}

        def batch(callback):
            result = MagicMock()
            items = []
            result.add.side_effect = lambda req, request_id: items.append(request_id)
            def execute():
                for key in items:
                    attempts[key] = attempts.get(key, 0) + 1
                    if key == 'deleted':
                        callback(key, None, HttpError(Response({'status':404}), b'{}'))
                    elif key in failures and attempts[key] <= failures[key]:
                        callback(key, None, HttpError(Response({'status':429}), b'{}'))
                    else:
                        callback(key, message(['SENT'] if key == 'sent' else []), None)
            result.execute.side_effect = execute
            return result
        service.new_batch_http_request.side_effect = batch
        return service, attempts

    @patch('app.gmail.full_scan.time.sleep')
    def test_pagination_dedup_retries_gaps_and_normalized_activity(self, sleep):
        service, attempts = self.service([
            {'messages':[{'id':'1'},{'id':'sent'},{'id':'deleted'}], 'nextPageToken':'next'},
            {'messages':[{'id':'1'},{'id':'retry'}]}], {'retry':1})
        scanner = GmailScanner.__new__(GmailScanner)
        scanner.service = service
        records, coverage = scanner.scan_activity_emails(0)
        self.assertEqual([r['message_id'] for r in records], ['1', 'retry'])
        self.assertEqual(attempts['retry'], 2)
        self.assertEqual(coverage['message_fetches'], 4)
        self.assertEqual(coverage['pages_scanned'], 2)
        self.assertEqual(coverage['excluded_sent_or_draft'], 1)
        self.assertEqual(coverage['unavailable_messages'], 1)
        self.assertFalse(coverage['scan_complete'])
        payload = main.activity_payload(records, coverage)
        self.assertEqual(records, [])
        self.assertEqual(payload['services_found'], 1)
        self.assertNotIn('New login detected', str(payload))
        for call in service.users().messages().get.call_args_list:
            self.assertEqual(call.kwargs['format'], 'metadata')
            self.assertEqual(call.kwargs['fields'], 'internalDate,labelIds,payload/headers')

    @patch('app.gmail.full_scan.time.sleep')
    def test_empty_complete_and_loop_rejected(self, sleep):
        service, _ = self.service([{}])
        self.assertTrue(scan_full_mailbox(service, str)[1]['scan_complete'])
        service, _ = self.service([{'nextPageToken':'same'}, {'nextPageToken':'same'}])
        with self.assertRaises(ValueError):
            scan_full_mailbox(service, str)

    @patch('app.gmail.full_scan.time.sleep')
    def test_batches_cancel_and_exhausted_retry(self, sleep):
        service, _ = self.service([{'messages':[{'id':str(n)} for n in range(51)]}])
        records, coverage = scan_full_mailbox(service, str)
        self.assertEqual(len(records), 51)
        self.assertEqual(service.new_batch_http_request.call_count, 2)
        service, _ = self.service([{'messages':[{'id':'retry'}]}], {'retry':99})
        with self.assertRaises(HttpError):
            scan_full_mailbox(service, str)
        service, _ = self.service([{'messages':[{'id':'1'}]}])
        def cancel(progress):
            if progress['message_fetches']:
                raise ScanCancelled()
        with self.assertRaises(ScanCancelled):
            scan_full_mailbox(service, str, cancel)


class MergedEndpointTests(unittest.TestCase):
    def test_registration_mixed_timezones(self):
        accounts = AccountDiscoveryService().discover_accounts([
            {'sender_domain':'example.com', 'date':'Mon, 12 Oct 2026 10:00:00 +0000'},
            {'sender_domain':'example.com', 'date':'Sun, 11 Oct 2026 10:00:00'}])
        self.assertEqual(accounts[0]['first_seen'], '2026-10-11')

    def test_email_breach_lookup_only_uses_connected_address(self):
        with patch.object(main, 'gmail_credentials', None):
            self.assertEqual(request('/accounts/email-breaches', method='POST')[0], 401)
        with patch.object(main, 'gmail_credentials', object()), patch.dict('os.environ', {'HIBP_API_KEY':'test'}), patch.object(main, 'GmailScanner') as scanner, patch.object(main.BreachChecker, 'check_email', return_value={'email':'owner@example.com', 'breaches':[], 'breached':False}) as lookup:
            scanner.return_value.get_email_address.return_value = 'owner@example.com'
            status, body = request('/accounts/email-breaches', method='POST', payload={'email':'someoneelse@example.com'})
            self.assertEqual(status, 200)
            lookup.assert_called_once_with('owner@example.com', 'test')
            self.assertEqual(body['status'], 'checked')
            self.assertEqual(request('/accounts/email-breaches', method='POST', headers=[(b'origin', b'https://outside.example')])[0], 403)

    def test_explicit_revocation_and_default_local_disconnect(self):
        with patch.object(main, 'gmail_credentials', object()), patch.object(main, 'revoke_credentials') as revoke:
            self.assertEqual(request('/gmail/disconnect', 'revoke=true', method='POST')[0], 200)
            revoke.assert_called_once()
            self.assertIsNone(main.gmail_credentials)

    def test_full_scan_background_endpoint(self):
        manager = ScanJobManager()
        try:
            with patch.object(main, 'scan_jobs', manager), patch.object(main, 'gmail_credentials', object()), patch.object(main, 'GmailScanner') as scanner:
                scanner.return_value.scan_activity_emails.return_value = ([], {'messages_scanned':0, 'scan_complete':True})
                status, body = request('/accounts/activity/scans', 'max_messages=0', method='POST')
                self.assertEqual(status, 202)
        finally:
            manager.shutdown()
