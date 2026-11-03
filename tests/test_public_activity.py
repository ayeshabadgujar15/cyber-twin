import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.error import HTTPError

from app.services.public_activity import PublicActivityService, IntelBaseActivityService, SourceError, fetch_json, parse_time
from tests.test_activity_integration import request


class PublicActivityTests(unittest.TestCase):
    def test_github_dates_location_and_no_fake_login(self):
        with patch('app.services.public_activity.fetch_json', side_effect=[
            {'login': 'example', 'created_at': '2020-01-01T00:00:00Z',
             'updated_at': '2026-10-01T00:00:00Z', 'location': 'Delhi', 'bio': 'discard'},
            [{'id': '1', 'public': True, 'created_at': '2026-01-01T00:00:00Z'},
             {'id': '2', 'public': False, 'created_at': '2026-02-01T00:00:00Z'}]]):
            result = PublicActivityService().lookup('github', 'example')
        self.assertEqual(result.service.first_seen.year, 2020)
        self.assertEqual(result.service.last_seen.month, 1)
        self.assertEqual(result.service.last_seen.year, 2026)
        self.assertIsNone(result.service.last_confirmed_login)
        self.assertEqual(result.locations[0].kind, 'profile_declared')
        self.assertFalse(result.ownership_verified)
        self.assertNotIn('discard', result.model_dump_json())
        self.assertTrue(result.coverage['events_retrieved'])

    def test_github_pagination_and_partial_failure(self):
        page = [{'id': str(i), 'public': True, 'created_at': '2020-01-02T00:00:00Z'} for i in range(100)]
        with patch('app.services.public_activity.fetch_json', side_effect=[{'login': 'example'}, page, page, []]) as fetch:
            result = PublicActivityService().lookup('github', 'example')
            self.assertEqual(fetch.call_count, 4)
            self.assertEqual(len(result.service.timeline), 100)
            self.assertFalse(result.coverage['history_complete'])
        with patch('app.services.public_activity.fetch_json', side_effect=[
            {'login': 'example', 'location': 'Delhi'}, SourceError(503, 'Rate limited')]):
            result = PublicActivityService().lookup('github', 'example')
        self.assertFalse(result.coverage['events_retrieved'])
        self.assertEqual(result.locations[0].value, 'Delhi')
        self.assertIsNone(result.service.last_seen)

    def test_chess_and_validation(self):
        with patch('app.services.public_activity.fetch_json', return_value={
            'username': 'example', 'joined': 1577836800, 'last_online': 1767225600, 'location': 'Delhi'}):
            result = PublicActivityService().lookup('chess.com', 'example')
        self.assertEqual(result.last_seen_basis, 'provider_last_online')
        self.assertIsNone(result.service.last_confirmed_login)
        with patch('app.services.public_activity.fetch_json') as fetch:
            for username in ('../secret', 'a?x=1', 'https://localhost'):
                with self.assertRaises(SourceError):
                    PublicActivityService().lookup('github', username)
            fetch.assert_not_called()

    def test_dates(self):
        now = datetime(2026, 10, 8, tzinfo=timezone.utc)
        for value in (True, 'bad', 10**30, '2100-01-01', -1):
            self.assertIsNone(parse_time(value, now))
        self.assertEqual(parse_time('2020-01-01', now).year, 2020)

    def test_intelbase_allowlist_and_disabled_sensitive_sources(self):
        payload = {'identifier': {'accounts': [{'module': {'domain': 'example.com'}, 'data': {
            'username': 'example', 'creation_date': '2020-01-01', 'last_seen': '2026-01-01',
            'location': 'Delhi', 'password': 'secret', 'bio': 'discard'}}]},
            'stealer_logs': {'password': 'secret'}}
        with patch.dict('os.environ', {'INTELBASE_API_KEY': 'test'}), patch('app.services.public_activity.fetch_json', return_value=payload) as fetch:
            result = IntelBaseActivityService().lookup_email('example@example.com')
            body = fetch.call_args.args[1]
        self.assertFalse(body['include_data_breaches'])
        self.assertFalse(body['include_stealer_logs'])
        self.assertNotIn('secret', json.dumps(result, default=lambda x: x.model_dump(mode='json')))
        self.assertEqual(result['accounts'][0].locations[0].kind, 'provider_reported')
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaises(SourceError) as error:
                IntelBaseActivityService().lookup_email('example@example.com')
        self.assertEqual(error.exception.status, 503)

    def test_routes(self):
        with patch('app.services.public_activity.fetch_json', side_effect=[{'login': 'example', 'location': 'Delhi'}, []]):
            status, body = request('/accounts/public-activity', method='POST', payload={'provider': 'github', 'username': 'example'})
        self.assertEqual(status, 200)
        self.assertEqual(body['locations'][0]['value'], 'Delhi')
        for payload in ({'provider': 'google', 'username': 'example'}, {'provider': 'github', 'username': '../secret'}):
            self.assertEqual(request('/accounts/public-activity', method='POST', payload=payload)[0], 422)
        self.assertEqual(request('/accounts/enrich-email', method='POST', payload={'email': 'invalid'})[0], 422)
        with patch.dict('os.environ', {}, clear=True):
            self.assertEqual(request('/accounts/enrich-email', method='POST', payload={'email': 'example@example.com'})[0], 503)

    def test_network_errors_are_sanitized(self):
        with patch('app.services.public_activity.build_opener') as opener:
            opener.return_value.open.side_effect = HTTPError('https://example.com', 429, 'secret', {}, None)
            with self.assertRaises(SourceError) as error:
                fetch_json('https://api.github.com/users/example')
        self.assertEqual(error.exception.status, 503)
        self.assertNotIn('secret', error.exception.detail)


if __name__ == '__main__':
    unittest.main()
