import base64
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, PropertyMock, patch
from urllib.parse import parse_qs, urlsplit

import app.gmail.oauth as oauth
from app.gmail.client_setup import import_desktop_client
import app.main as main
import run
from test_activity_integration import request

DESKTOP = {'GOOGLE_CLIENT_TYPE':'desktop', 'GOOGLE_CLIENT_ID':'123-test.apps.googleusercontent.com',
           'GOOGLE_CLIENT_SECRET':'test-secret', 'CYBERTWIN_APP_URL':'http://localhost:18765/'}


class DesktopOAuthTests(unittest.TestCase):
    def tearDown(self):
        oauth.clear_pending_flow()

    def test_runtime_port_no_web_redirect_setting_and_pkce(self):
        with patch.dict(os.environ, DESKTOP, clear=True):
            status = oauth.setup_status()
            self.assertTrue(status['configured'])
            self.assertEqual(status['callback_url'], 'http://localhost:18765/')
            url, state = oauth.get_authorization_url()
            query = parse_qs(urlsplit(url).query)
            flow = oauth.pending_desktop_flow[2]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(flow.code_verifier.encode()).digest()).rstrip(b'=').decode()
            self.assertEqual(query['code_challenge'], [challenge])
            self.assertEqual(query['code_challenge_method'], ['S256'])
            self.assertEqual(query['redirect_uri'], ['http://localhost:18765/'])
            credential = object()
            with patch.object(flow, 'fetch_token') as fetch, patch.object(type(flow), 'credentials', new_callable=PropertyMock, return_value=credential):
                self.assertIs(oauth.fetch_credentials('code', state), credential)
                fetch.assert_called_once_with(code='code')
            self.assertIsNone(oauth.pending_desktop_flow)
            with self.assertRaises(oauth.OAuthConfigurationError):
                oauth.fetch_credentials('code', state)

    def test_web_port_mismatch_requires_setup(self):
        with patch.dict(os.environ, {**DESKTOP, 'GOOGLE_CLIENT_TYPE':'web', 'GOOGLE_REDIRECT_URI':'http://localhost:8000/gmail/callback'}, clear=True):
            status = oauth.setup_status()
            self.assertFalse(status['configured'])
            self.assertTrue(status['port_mismatch'])

    def test_desktop_root_callback_keeps_browser_state_check(self):
        with patch.dict(os.environ, DESKTOP, clear=True), patch.object(main, 'oauth_state', 'attempt'), patch.object(main, 'oauth_started_at', time.monotonic()), patch.object(main, 'oauth_return_to_dashboard', True), patch.object(main, 'gmail_credentials', None), patch.object(main, 'fetch_credentials', return_value=object()) as fetch:
            self.assertEqual(request('/', 'code=test&state=attempt')[0], 400)
            status, _, headers = request('/', 'code=test&state=attempt', headers=[(b'cookie', b'cybertwin_oauth_state=attempt')], return_headers=True)
            self.assertEqual(status, 303)
            self.assertEqual(headers[b'location'], b'/?gmail=connected')
            self.assertIn(b'Path=/', headers[b'set-cookie'])
            fetch.assert_called_once_with('test', 'attempt')


class DesktopSetupTests(unittest.TestCase):
    def test_import_keeps_existing_settings_private_and_backs_up(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory, patch.dict(os.environ, {}, clear=True):
            self.assertTrue(Path(directory).resolve().is_relative_to(Path(__file__).parent.resolve()))
            env = Path(directory) / '.env'
            env.write_text('HIBP_API_KEY=keep-existing\nGOOGLE_CLIENT_ID=previous\n')
            import_desktop_client({'installed':{'client_id':DESKTOP['GOOGLE_CLIENT_ID'], 'client_secret':'test-secret', 'auth_uri':'https://untrusted.example'}}, env)
            self.assertEqual(os.environ['GOOGLE_CLIENT_TYPE'], 'desktop')
            self.assertIn('HIBP_API_KEY=keep-existing', env.read_text())
            self.assertIn('GOOGLE_CLIENT_ID=previous', (Path(directory) / '.env.before-desktop').read_text())
            self.assertNotIn('untrusted.example', env.read_text())
            self.assertFalse(list(Path(directory).glob('*.tmp')))

    def test_import_rejects_web_and_invalid_ids_before_writing(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            self.assertTrue(Path(directory).resolve().is_relative_to(Path(__file__).parent.resolve()))
            env = Path(directory) / '.env'
            for payload in [{'web':{}}, {'installed':{'client_id':'not-google', 'client_secret':'test'}}]:
                with self.assertRaises(ValueError):
                    import_desktop_client(payload, env)
            self.assertFalse(env.exists())

    def test_setup_route_size_origin_and_connected_guards(self):
        with patch.object(main, 'gmail_credentials', None), patch('app.gmail.client_setup.import_desktop_client') as save:
            self.assertEqual(request('/gmail/setup-client', method='POST', payload={'installed':{}}, headers=[(b'origin', b'https://outside.example')])[0], 403)
            self.assertEqual(request('/gmail/setup-client', method='POST', payload={'large':'x'*100001})[0], 413)
            save.assert_not_called()
            status, body = request('/gmail/setup-client', method='POST', payload={'installed':{'client_secret':'not-to-be-returned'}})
            self.assertEqual(status, 200)
            self.assertNotIn('not-to-be-returned', str(body))
        with patch.object(main, 'gmail_credentials', object()):
            self.assertEqual(request('/gmail/setup-client', method='POST', payload={})[0], 409)


class LauncherTests(unittest.TestCase):
    def test_blocked_port_fallback_preserves_bound_socket(self):
        first, second = MagicMock(), MagicMock()
        first.bind.side_effect = OSError('blocked')
        with patch.object(run.socket, 'socket', side_effect=[first, second]):
            self.assertIs(run.bind_local(8000), second)
            first.bind.assert_called_once_with(('127.0.0.1',8000))
            first.close.assert_called_once()
            second.bind.assert_called_once_with(('127.0.0.1',8765))
            second.listen.assert_called_once()
            second.close.assert_not_called()
