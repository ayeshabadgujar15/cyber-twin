"""Offline tests for researched Gmail reliability and evidence semantics."""
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from httplib2 import Response, HttpLib2Error
from googleapiclient.errors import HttpError
from app.services.activity_reconstruction import ActivityReconstructionService
import app.main as main
from tests import test_activity_integration as integration
from tests.test_activity_integration import request


def provider_error(status, reason='notFound'):
    return HttpError(Response({'status': str(status)}),
                     json.dumps({'error': {'errors': [{'reason': reason}],
                                          'message': 'private-provider-detail'}}).encode())


class ReliabilityTests(unittest.TestCase):
    def test_deleted_message_does_not_abort_or_escape_bound(self):
        scanner, api = integration.ScannerTests().scanner([
            {'messages': [{'id': '1'}, {'id': '2'}], 'nextPageToken': 'next'}])
        api.get.return_value.execute.side_effect = [provider_error(404),
            {'internalDate': '1767225600000', 'payload': {'headers': []}}]
        emails, coverage = scanner.scan_activity_emails(2)
        self.assertEqual(len(emails), 1)
        self.assertEqual(coverage['message_fetches'], 2)
        self.assertEqual(coverage['unavailable_messages'], 1)
        self.assertFalse(coverage['scan_complete'])
        self.assertEqual(coverage['stop_reason'], 'message_limit')
        self.assertEqual(api.list.call_count, 1)
        api.list.return_value.execute.assert_called_with(num_retries=2)
        api.get.return_value.execute.assert_called_with(num_retries=2)

    def test_deleted_last_message_marks_gap(self):
        scanner, api = integration.ScannerTests().scanner([{'messages': [{'id': '1'}]}])
        api.get.return_value.execute.side_effect = provider_error(404)
        emails, coverage = scanner.scan_activity_emails(1)
        self.assertEqual(emails, [])
        self.assertEqual(coverage['stop_reason'], 'mailbox_end')
        self.assertFalse(coverage['scan_complete'])

    def test_sent_drafts_excluded_spam_trash_included(self):
        scanner, api = integration.ScannerTests().scanner([
            {'messages': [{'id': str(i)} for i in range(4)]}])
        api.get.return_value.execute.side_effect = [
            {'labelIds': [label], 'payload': {'headers': []}}
            for label in ['SENT', 'DRAFT', 'SPAM', 'TRASH']]
        emails, coverage = scanner.scan_activity_emails(4)
        self.assertEqual(len(emails), 2)
        self.assertEqual(coverage['excluded_sent_or_draft'], 2)
        self.assertTrue(coverage['scan_complete'])
        self.assertEqual(coverage['message_fetches'], 4)
        self.assertIn('labelIds', api.get.call_args.kwargs['fields'])
        self.assertNotIn('snippet', api.get.call_args.kwargs['fields'])

    def test_non_404_failure_still_propagates(self):
        scanner, api = integration.ScannerTests().scanner([{'messages': [{'id': '1'}]}])
        api.get.return_value.execute.side_effect = provider_error(403, 'forbidden')
        with self.assertRaises(HttpError):
            scanner.scan_activity_emails(1)

    def test_weak_welcome_does_not_establish_use_and_explanations_are_private(self):
        now = datetime(2026, 10, 12, tzinfo=timezone.utc)
        service = ActivityReconstructionService().reconstruct([
            {'sender_domain': 'example.com', 'subject': 'Welcome to Private Newsletter',
             'date': '1 Oct 2026 10:00:00 +0000'}], now)[0]
        self.assertEqual(service.activity_status, 'unknown')
        self.assertIsNone(service.last_confirmed_login)
        self.assertIn('weak', service.timeline[0].classification_explanation)
        self.assertIn('generic welcomes', service.activity_status_explanation)
        self.assertNotIn('Private Newsletter', service.model_dump_json())

    def test_quota_and_policy_failures_are_distinguished(self):
        for reason in ['rateLimitExceeded', 'userRateLimitExceeded', 'dailyLimitExceeded']:
            error = main.gmail_scan_error(provider_error(403, reason))
            self.assertEqual(error.status_code, 429)
            self.assertEqual(error.headers['Retry-After'], '60')
            self.assertNotIn('private-provider-detail', error.detail)
        self.assertIn('administrator', main.gmail_scan_error(provider_error(403, 'domainPolicy')).detail)
        self.assertEqual(main.gmail_scan_error(provider_error(403, 'forbidden')).status_code, 403)

    def test_scan_coverage_endpoint_and_transport_failure(self):
        messages = [dict(sender_domain='example.com', subject='New login detected',
                         date='1 Jan 2026 10:00:00 +0000'),
                    dict(sender_domain='example.com', subject='Sale today',
                         date='1 Oct 2026 10:00:00 +0000')]
        with patch.object(main, 'gmail_credentials', object()), patch('app.gmail.scanner.build'), patch.object(main.GmailScanner, 'scan_activity_emails', return_value=(messages, {'scan_complete': True, 'messages_scanned': 2})):
            status, body = request('/accounts/activity')
        self.assertEqual(status, 200)
        self.assertEqual(body['coverage']['classified_messages'], 1)
        self.assertIn('2026-10-01', body['coverage']['newest_scanned_evidence'])
        self.assertIn('2026-01-01', body['coverage']['oldest_scanned_evidence'])
        self.assertEqual(messages, [])
        self.assertNotIn('Sale today', json.dumps(body))
        with patch.object(main, 'gmail_credentials', object()), patch('app.gmail.scanner.build'), patch.object(main.GmailScanner, 'scan_activity_emails', side_effect=HttpLib2Error('private')):
            status, body = request('/accounts/activity')
        self.assertEqual(status, 502)
        self.assertNotIn('private', json.dumps(body))


if __name__ == '__main__':
    unittest.main()
