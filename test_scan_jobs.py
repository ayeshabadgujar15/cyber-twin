import time
import unittest
from threading import Event
from unittest.mock import patch
from app.services.scan_jobs import ScanJobManager, ScanCancelled, ScanFailure
from app.gmail.scanner import GmailScanner
import app.main as main
from test_activity_integration import request


class ScanJobsTests(unittest.TestCase):
    def setUp(self):
        self.manager = ScanJobManager(ttl=600)

    def tearDown(self):
        self.manager.shutdown()

    def terminal(self, key, owner=1):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = self.manager.snapshot(key, owner)
            if result and result['status'] in {'completed', 'cancelled', 'failed'}:
                return result
            time.sleep(.01)
        self.fail('Worker did not reach a terminal state')

    def test_progress_and_normalized_completion(self):
        def task(report):
            report({'message_fetches': 2, 'messages_scanned': 1, 'message_limit': 5})
            return {'services': [], 'coverage': {'scan_complete': True}}
        key = self.manager.start(1, task, 5)
        result = self.terminal(key)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['progress']['message_fetches'], 2)
        self.assertEqual(result['result']['services'], [])
        self.assertIsNone(self.manager.snapshot(key, 2))

    def test_cancellation_busy_guard_and_no_partial_result(self):
        started, release = Event(), Event()
        def task(report):
            started.set()
            release.wait(2)
            report({'message_fetches': 1})
            return {'private': 'must not survive'}
        key = self.manager.start(1, task, 5)
        self.assertTrue(started.wait(1))
        with self.assertRaises(RuntimeError):
            self.manager.start(1, task, 5)
        self.assertFalse(self.manager.cancel(key, 2))
        self.assertTrue(self.manager.cancel(key, 1))
        release.set()
        result = self.terminal(key)
        self.assertEqual(result['status'], 'cancelled')
        self.assertIsNone(result['result'])

    def test_failure_is_sanitized_and_expiry_does_not_refresh_on_poll(self):
        def task(report):
            raise ValueError('private-email-secret')
        key = self.manager.start(1, task, 1)
        result = self.terminal(key)
        self.assertNotIn('private-email-secret', str(result))
        self.assertEqual(result['status'], 'failed')
        self.manager.jobs[key]['touched'] = time.monotonic() - 601
        self.assertIsNone(self.manager.snapshot(key, 1))

    def test_known_error_and_clear(self):
        def task(report):
            raise ScanFailure(429, 'Wait before retrying.')
        key = self.manager.start(1, task, 1)
        self.assertEqual(self.terminal(key)['error']['status'], 429)
        self.manager.clear()
        self.assertIsNone(self.manager.snapshot(key, 1))

    def test_background_routes_auth_validation_and_normalized_results(self):
        with patch.object(main, 'scan_jobs', self.manager), patch.object(main, 'gmail_credentials', None):
            self.assertEqual(request('/accounts/activity/scans', method='POST')[0], 401)
        messages = [dict(sender_domain='example.com', subject='New login detected', internal_date='1767225600000')]
        def scan(scanner, limit, progress_callback=None):
            progress_callback({'message_fetches': 1, 'messages_scanned': 1, 'message_limit': limit})
            return messages, {'messages_scanned': 1, 'scan_complete': True}
        with patch.object(main, 'scan_jobs', self.manager), patch.object(main, 'gmail_credentials', object()), patch('app.gmail.scanner.build'), patch.object(GmailScanner, 'scan_activity_emails', scan):
            self.assertEqual(request('/accounts/activity/scans', 'max_messages=-1', method='POST')[0], 422)
            self.assertEqual(request('/accounts/activity/scans', method='POST', headers=[(b'origin', b'https://outside.example')])[0], 403)
            code, body = request('/accounts/activity/scans', 'max_messages=1', method='POST')
            self.assertEqual(code, 202)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                code, state = request('/accounts/activity/scans/' + body['scan_id'])
                if state['status'] == 'completed':
                    break
                time.sleep(.01)
            self.assertEqual(state['status'], 'completed')
            self.assertEqual(state['result']['services_found'], 1)
            self.assertNotIn('New login detected', str(state))
            self.assertEqual(messages, [])
            self.assertEqual(request('/accounts/activity/scans/missing')[0], 404)

    def test_completed_result_can_be_cleared_and_cache_is_bounded(self):
        keys = []
        for i in range(4):
            key = self.manager.start(1, lambda report: {'normalized': True}, 1)
            self.terminal(key)
            keys.append(key)
        self.assertIsNone(self.manager.snapshot(keys[0], 1))
        self.assertEqual(len(self.manager.jobs), 3)
        self.assertTrue(self.manager.cancel(keys[-1], 1))
        self.assertIsNone(self.manager.snapshot(keys[-1], 1)['result'])

    def test_expiry_runs_without_polling(self):
        manager = ScanJobManager(ttl=.05)
        try:
            key = manager.start(1, lambda report: {'normalized': True}, 1)
            time.sleep(.16)
            with manager.lock:
                self.assertNotIn(key, manager.jobs)
        finally:
            manager.shutdown()

    def test_scanner_has_bounded_transport_timeout(self):
        with patch('app.gmail.scanner.build') as build:
            GmailScanner(object())
        self.assertEqual(build.call_args.kwargs['http'].http.timeout, 30)


if __name__ == '__main__':
    unittest.main()
