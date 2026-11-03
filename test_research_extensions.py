import hashlib
import unittest
from unittest.mock import patch
from urllib.error import URLError

from app.services.gravatar import GravatarService
from app.services.public_activity import SourceError, fetch_json
from app.services.public_activity import IntelBaseActivityService
from test_activity_integration import request


class ResearchExtensionTests(unittest.TestCase):
    def test_intelbase_registration_only_and_incomplete_coverage(self):
        payload = {'identifier': {'accounts': []}, 'validator': {
            'registered': [{'domain': 'example.com'}], 'unregistered': [{'domain': 'absent.com'}]}}
        with patch.dict('os.environ', {'INTELBASE_API_KEY': 'test'}), patch('app.services.public_activity.fetch_json', return_value=payload):
            result = IntelBaseActivityService().lookup_email('you@example.com')
        self.assertEqual(result['accounts_found'], 1)
        self.assertIsNone(result['accounts'][0].service.last_seen)
        self.assertEqual(result['accounts'][0].service.confidence_score, 0)
        self.assertEqual([x['outcome'] for x in result['source_outcomes']], ['found', 'absent'])
        self.assertEqual(result['coverage']['unlisted_modules_outcome'], 'unknown')
        for malformed in [{'identifier': {}}, {'identifier': {'accounts': []}, 'validator': {'registered': {}}}]:
            with patch.dict('os.environ', {'INTELBASE_API_KEY': 'test'}), patch('app.services.public_activity.fetch_json', return_value=malformed):
                with self.assertRaises(SourceError):
                    IntelBaseActivityService().lookup_email('you@example.com')

    def test_gravatar_hash_dates_privacy_and_links(self):
        profile = {'hash': 'abc', 'registration_date': '2020-01-01T00:00:00Z',
                   'last_profile_edit': '2026-01-01T00:00:00Z', 'location': 'Delhi',
                   'description': 'discard', 'contact_info': {'email': 'private'},
                   'verified_accounts': [{'url': 'https://github.com/example'},
                                         {'url': 'javascript:alert(1)'},
                                         {'url': 'https://example.com/hidden', 'is_hidden': True},
                                         {'url': 'https://[bad'}]}
        with patch.dict('os.environ', {'GRAVATAR_API_KEY': 'secret'}), patch('app.services.gravatar.fetch_json', return_value=profile) as fetch:
            result = GravatarService().lookup_email(' Example@Example.com ')
        expected = hashlib.sha256(b'example@example.com').hexdigest()
        self.assertTrue(fetch.call_args.args[0].endswith(expected))
        self.assertEqual(fetch.call_args.kwargs['headers']['Authorization'], 'Bearer secret')
        account = result['accounts'][0]
        self.assertEqual(account.service.last_seen.year, 2020)
        self.assertIsNone(account.last_public_activity)
        self.assertIsNone(account.service.last_confirmed_login)
        self.assertEqual(account.profile_updated_at.year, 2026)
        self.assertEqual(account.linked_profiles, ['https://github.com/example'])
        self.assertNotIn('private', account.model_dump_json())
        self.assertNotIn('discard', account.model_dump_json())

    def test_gravatar_outcomes_and_missing_dates(self):
        for status, outcome in [(404, 'absent'), (503, 'blocked'), (502, 'unknown'), (504, 'timed_out')]:
            with patch('app.services.gravatar.fetch_json', side_effect=SourceError(status, 'sanitized', outcome)):
                code, body = request('/accounts/gravatar', method='POST', payload={'email': 'you@example.com'})
            self.assertEqual(code, 200)
            self.assertEqual(body['source_outcomes'][0]['outcome'], outcome)
            self.assertEqual(body['accounts_found'], 0)
        with patch('app.services.gravatar.fetch_json', return_value={'hash': 'abc'}):
            result = GravatarService().lookup_email('you@example.com')
        self.assertEqual(result['source_outcomes'][0]['outcome'], 'found')
        self.assertIsNone(result['accounts'][0].service.last_seen)
        with patch('app.services.gravatar.fetch_json', return_value=[]):
            code, body = request('/accounts/gravatar', method='POST', payload={'email': 'you@example.com'})
        self.assertEqual(code, 502)
        self.assertEqual(body['source_outcome'], 'unknown')

    def test_timeout_and_existing_source_outcomes(self):
        for error in [TimeoutError(), URLError(TimeoutError())]:
            with patch('app.services.public_activity.build_opener') as opener:
                opener.return_value.open.side_effect = error
                with self.assertRaises(SourceError) as caught:
                    fetch_json('https://api.github.com/users/example')
            self.assertEqual(caught.exception.outcome, 'timed_out')
        with patch('app.services.public_activity.fetch_json', side_effect=SourceError(404, 'No profile')):
            code, body = request('/accounts/public-activity', method='POST', payload={'provider': 'github', 'username': 'example'})
        self.assertEqual(code, 404)
        self.assertEqual(body['source_outcome'], 'absent')

    def places(self, coordinates):
        return [{'latitude': lat, 'longitude': lon, 'source': 'fixture',
                 'source_url': 'https://example.com/observation', 'observed_at': '2025-01-01T00:00:00Z'} for lat, lon in coordinates]

    def test_location_antimeridian_dedup_and_opposing_points(self):
        code, body = request('/accounts/location-estimate', method='POST', payload={'observations': self.places([(0, 179), (0, -179), (0, 179)])})
        self.assertEqual(code, 200)
        self.assertEqual(body['unique_places'], 2)
        self.assertAlmostEqual(abs(body['center']['longitude']), 180)
        self.assertAlmostEqual(body['maximum_spread_km'], 111.195, places=2)
        self.assertFalse(body['live_location'])
        code, body = request('/accounts/location-estimate', method='POST', payload={'observations': self.places([(0, 0), (0, 180)])})
        self.assertIsNone(body['center'])
        self.assertIsNone(body['maximum_spread_km'])

    def test_location_validation(self):
        for coordinates in [[], [(91, 0)], [(0, 181)], [(0, 0)] * 501]:
            self.assertEqual(request('/accounts/location-estimate', method='POST', payload={'observations': self.places(coordinates)})[0], 422)
        for field, value in [('source_url', 'javascript:alert(1)'), ('source_url', 'https://user:password@example.com'), ('observed_at', '2025-01-01'), ('observed_at', '2100-01-01T00:00:00Z')]:
            places = self.places([(0, 0)])
            places[0][field] = value
            self.assertEqual(request('/accounts/location-estimate', method='POST', payload={'observations': places})[0], 422)


if __name__ == '__main__':
    unittest.main()
