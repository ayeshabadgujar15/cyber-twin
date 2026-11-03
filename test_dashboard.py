import asyncio
import time
import unittest
from unittest.mock import patch
import app.main as main
from test_activity_integration import request


class DashboardTests(unittest.TestCase):
    def test_page_and_assets_served(self):
        async def get(path):
            output = []
            async def receive():
                return {'type': 'http.request', 'body': b'', 'more_body': False}
            async def send(message):
                output.append(message)
            await main.app({'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
                            'method': 'GET', 'scheme': 'http', 'path': path, 'raw_path': path.encode(),
                            'query_string': b'', 'root_path': '', 'headers': [],
                            'server': ('localhost', 8000), 'client': ('localhost', 1234)}, receive, send)
            return output[0]['status'], b''.join(item.get('body', b'') for item in output).decode()
        for path, marker in [('/', 'public-form'), ('/static/app.js', 'renderRecords'), ('/static/style.css', '.sidebar')]:
            status, body = asyncio.run(get(path))
            self.assertEqual(status, 200)
            self.assertIn(marker, body)

    def test_status_does_not_expose_credentials(self):
        with patch.object(main, 'gmail_credentials', object()), patch.dict('os.environ', {'INTELBASE_API_KEY': 'secret'}):
            status, body = request('/api/status')
        self.assertEqual(status, 200)
        self.assertEqual(body, {'gmail_connected': True, 'intelbase_configured': True})
        self.assertEqual(request('/health')[0], 200)

    def test_dashboard_oauth_returns_to_page(self):
        with patch.object(main, 'gmail_credentials', None), patch.object(main, 'oauth_return_to_dashboard', True), patch.object(main, 'oauth_state', 'test'), patch.object(main, 'oauth_started_at', time.monotonic()), patch.object(main, 'fetch_credentials', return_value=object()):
            status, body = request('/gmail/callback', 'code=test&state=test', headers=[(b'cookie', b'cybertwin_oauth_state=test')])
        self.assertEqual(status, 303)
        self.assertIsNone(body)
