import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from google.auth.exceptions import RefreshError
import app.main as main
from app.gmail.oauth import setup_status
from test_activity_integration import request


class GmailConnectionTests(unittest.TestCase):
    def setUp(self):
        self.old = (main.oauth_state, main.oauth_started_at, main.oauth_return_to_dashboard, main.gmail_credentials)
        main.oauth_state = 'attempt'
        main.oauth_started_at = time.monotonic()
        main.oauth_return_to_dashboard = False
        main.gmail_credentials = None

    def tearDown(self):
        main.oauth_state, main.oauth_started_at, main.oauth_return_to_dashboard, main.gmail_credentials = self.old

    def callback(self, query='code=code&state=attempt', cookie='attempt'):
        return request('/gmail/callback', query, headers=[(b'cookie', ('cybertwin_oauth_state=' + cookie).encode())])

    def test_invalid_expired_and_replayed_callbacks(self):
        with patch.object(main, 'fetch_credentials', return_value=object()) as fetch:
            self.assertEqual(self.callback(cookie='other')[0], 400)
            self.assertEqual(self.callback('code=code&state=other')[0], 400)
            self.assertEqual(request('/gmail/callback', 'code=code&state=attempt')[0], 400)
            main.oauth_started_at = time.monotonic() - 601
            self.assertEqual(self.callback()[0], 400)
            fetch.assert_not_called()
            main.oauth_started_at = time.monotonic()
            self.assertEqual(self.callback()[0], 200)
            self.assertEqual(self.callback()[0], 400)
            fetch.assert_called_once()

    def test_denial_and_exchange_failure_are_safe(self):
        with patch.object(main, 'fetch_credentials') as fetch:
            code, body = self.callback('error=private-provider-message&state=attempt')
            self.assertEqual(code, 403)
            self.assertIn('Test users', body['detail'])
            self.assertNotIn('private-provider-message', json.dumps(body))
            fetch.assert_not_called()
        main.oauth_state, main.oauth_started_at = 'attempt', time.monotonic()
        main.oauth_return_to_dashboard = True
        with patch.object(main, 'fetch_credentials', side_effect=ValueError('secret')):
            code, body, headers = request('/gmail/callback', 'code=code&state=attempt', headers=[(b'cookie', b'cybertwin_oauth_state=attempt')], return_headers=True)
        self.assertEqual(code, 303)
        self.assertEqual(headers[b'location'], b'/?gmail_error=token_exchange')
        self.assertIn(b'Max-Age=0', headers[b'set-cookie'])

    def test_login_cookie_and_canonical_callback_host(self):
        with patch.object(main, 'setup_status', return_value={'configured': True, 'dashboard_url': 'http://localhost:8000/'}), patch.object(main, 'get_authorization_url', return_value=('https://accounts.google.com/oauth', 'attempt')) as auth:
            code, _, headers = request('/gmail/login', return_headers=True)
            self.assertEqual(code, 307)
            self.assertIn(b'HttpOnly', headers[b'set-cookie'])
            self.assertIn(b'SameSite=lax', headers[b'set-cookie'])
            _, _, headers = request('/gmail/login', headers=[(b'host', b'127.0.0.1:8000')], return_headers=True)
            self.assertEqual(headers[b'location'], b'http://localhost:8000/gmail/login?return_to_dashboard=false')
            self.assertEqual(auth.call_count, 1)

    def test_config_diagnostics_do_not_expose_secrets(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertFalse(setup_status()['configured'])
            self.assertEqual(request('/gmail/login')[0], 503)
        with patch.dict('os.environ', {'GOOGLE_CLIENT_ID': '12345-example.apps.googleusercontent.com', 'GOOGLE_CLIENT_SECRET': 'never-show-me', 'GOOGLE_REDIRECT_URI': 'http://localhost:8000/gmail/callback'}, clear=True):
            result = setup_status()
            self.assertTrue(result['configured'])
            self.assertEqual(result['test_user_access'], 'not_checked')
            self.assertNotIn('never-show-me', json.dumps(result))
            self.assertIn('project=12345', result['audience_url'])
        for url in ['https://example.com/gmail/callback', 'http://user:secret@localhost:8000/gmail/callback', 'http://localhost:8000/wrong']:
            with patch.dict('os.environ', {'GOOGLE_REDIRECT_URI': url}):
                self.assertFalse(setup_status()['configured'])

    def test_expired_gmail_clears_connection_for_both_scans(self):
        for endpoint, method in [('/accounts/activity', 'scan_activity_emails'), ('/accounts/discover', 'scan_registration_emails')]:
            main.gmail_credentials = object()
            with patch('app.gmail.scanner.build'), patch.object(main.GmailScanner, method, side_effect=RefreshError('private token')):
                status, body = request(endpoint)
            self.assertEqual(status, 401)
            self.assertIn('expired', body['detail'])
            self.assertNotIn('private token', json.dumps(body))
            self.assertIsNone(main.gmail_credentials)


if __name__ == '__main__':
    unittest.main()
