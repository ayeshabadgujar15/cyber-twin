import unittest
from unittest.mock import patch

import app.main as main
from test_activity_integration import request


class MigrationIdentityTests(unittest.TestCase):
    def test_requires_gmail_connection(self):
        with patch.object(main, 'gmail_credentials', None):
            self.assertEqual(request('/gmail/identity')[0], 401)

    def test_verified_identity_and_generation_without_credentials(self):
        with patch.object(main, 'gmail_credentials', object()), patch.object(main, 'gmail_connection_generation', 17), patch.object(main, 'GmailScanner') as scanner:
            scanner.return_value.get_email_address.return_value = 'old@example.com'
            status, body = request('/gmail/identity')
            self.assertEqual(status, 200)
            self.assertEqual(body, {'email':'old@example.com', 'connection_generation':17})
            self.assertNotIn('credentials', str(body))

    def test_reconnection_during_identity_lookup_rejected(self):
        with patch.object(main, 'gmail_credentials', object()), patch.object(main, 'GmailScanner') as scanner:
            def change_connection():
                main.gmail_credentials = object()
                return 'wrong@example.com'
            scanner.return_value.get_email_address.side_effect = change_connection
            self.assertEqual(request('/gmail/identity')[0], 409)

    def test_invalid_provider_identity_is_not_used(self):
        with patch.object(main, 'gmail_credentials', object()), patch.object(main, 'GmailScanner') as scanner:
            scanner.return_value.get_email_address.return_value = 'invalid'
            self.assertEqual(request('/gmail/identity')[0], 502)
