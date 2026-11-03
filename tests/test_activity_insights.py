import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from app.models import ActivityEvidence
from app.services.activity_reconstruction import ActivityReconstructionService
from app.services.activity_insights import build_insights
from app.services.activity_demo import activity_demo
import app.main as main
from tests.test_activity_integration import request


class InsightsTests(unittest.TestCase):
    now = datetime(2026, 10, 12, tzinfo=timezone.utc)

    def service(self, records):
        evidence = [('example.com', ActivityEvidence(source='test', source_id=str(i), event_type=kind,
                    observed_at=self.now - timedelta(days=days), confidence_score=score))
                    for i, (kind, days, score) in enumerate(records)]
        return ActivityReconstructionService().reconstruct_evidence(evidence, self.now)

    def test_codes_are_not_security_review_alerts(self):
        insights = build_insights(self.service([('security', 1, 60)]), self.now)
        self.assertEqual(insights['security_services'], 0)
        self.assertEqual(insights['review_queue'][0]['category'], 'identity')
        self.assertEqual(insights['monthly_activity'][-1]['evidence_count'], 1)
        self.assertEqual(len(insights['monthly_activity']), 12)

    def test_review_priorities_and_billing_without_invented_spend(self):
        insights = build_insights(self.service([('security', 1, 85), ('password', 2, 80), ('transaction', 3, 70), ('login', 200, 90)]), self.now)
        self.assertEqual([item['category'] for item in insights['review_queue']], ['security', 'password', 'billing', 'forgotten'])
        self.assertEqual(insights['billing_services'], 1)
        self.assertEqual(insights['possibly_dormant_services'], 1)
        self.assertIn('not verified', insights['review_queue'][2]['explanation'])
        self.assertEqual(insights['evidence_count'], 4)

    def test_empty_insights_and_year_boundary(self):
        insights = build_insights([], datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(insights['review_queue'], [])
        self.assertEqual(insights['monthly_activity'][0]['month'], '2025-02')
        self.assertEqual(insights['monthly_activity'][-1]['month'], '2026-01')

    def test_demo_does_not_need_or_read_gmail(self):
        with patch.object(main, 'gmail_credentials', None), patch.object(main, 'GmailScanner') as scanner:
            code, result = request('/accounts/activity-demo')
        scanner.assert_not_called()
        self.assertEqual(code, 200)
        self.assertTrue(result['is_demo'])
        self.assertEqual(result['services_found'], 6)
        self.assertTrue(all(service['domain'].endswith('.example') for service in result['services']))
        self.assertTrue(all(event['source'] == 'demo' for service in result['services'] for event in service['timeline']))

    def test_demo_all_dates_are_relative_and_nonfuture(self):
        result = activity_demo(self.now)
        self.assertTrue(all(event.observed_at <= self.now for service in result['services'] for event in service.timeline))
        self.assertEqual(result['insights']['service_count'], 6)

    def test_disconnect_clears_local_state_without_provider_calls(self):
        with patch.object(main, 'gmail_credentials', object()), patch.object(main, 'oauth_state', 'old'), patch.object(main, 'GmailScanner') as scanner:
            code, body = request('/gmail/disconnect', method='POST')
            self.assertEqual(code, 200)
            self.assertIsNone(main.gmail_credentials)
            self.assertIsNone(main.oauth_state)
            self.assertIn('unchanged', body['message'])
        scanner.assert_not_called()

    def test_disconnect_rejects_external_origin(self):
        credentials = object()
        with patch.object(main, 'gmail_credentials', credentials):
            code, _ = request('/gmail/disconnect', method='POST', headers=[(b'origin', b'https://elsewhere.example')])
            self.assertEqual(code, 403)
            self.assertIs(main.gmail_credentials, credentials)


if __name__ == '__main__':
    unittest.main()
