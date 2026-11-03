import unittest
from datetime import datetime, timezone
from app.services.activity_reconstruction import ActivityReconstructionService, classify


class ReconstructionTests(unittest.TestCase):
    def test_attempts_and_codes_are_not_confirmed_logins(self):
        for subject in ['Unusual login attempt', 'Failed login', 'Your login code', 'New login attempt',
                        'New login detected: OTP', 'New login detected: verification code',
                        'New login detected but blocked', 'Sign-in unsuccessful']:
            self.assertEqual(classify(subject)[0], 'security')

    def test_pending_and_negated_logins(self):
        subjects = ['New login detected: not successful',
                    'New login detected: two-factor authentication required',
                    'New login detected: verification required',
                    'New login detected: pending approval']
        messages = [dict(sender_domain='example.com', message_id=str(i),
                         subject=subject, date='1 Oct 2026 10:00:00 +0000')
                    for i, subject in enumerate(subjects)]
        service = ActivityReconstructionService().reconstruct(
            messages, datetime(2026, 10, 12, tzinfo=timezone.utc))[0]
        self.assertIsNone(service.last_confirmed_login)
        self.assertEqual(service.activity_status, 'unknown')
        self.assertTrue(all(event.event_type == 'security' for event in service.timeline))

    def test_common_completed_event_wording(self):
        self.assertEqual(classify('Your account was created'), ('account_creation', 85))
        self.assertEqual(classify('Your account has been created'), ('account_creation', 85))
        self.assertEqual(classify('Your password has been changed'), ('password', 80))

    def test_failed_success_wording_and_security_codes(self):
        for subject in ['Successfully signed in but denied',
                        'Successfully logged in: failed',
                        'New login detected: security code',
                        'New login detected: authentication code',
                        'New login detected: rejected']:
            with self.subTest(subject=subject):
                self.assertEqual(classify(subject)[0], 'security')

    def test_timestamp_basis_confidence_and_exact_dormancy_boundary(self):
        from datetime import timedelta
        now = datetime(2026, 10, 12, tzinfo=timezone.utc)
        message = dict(sender_domain='example.com', subject='New login detected',
                       date=(now - timedelta(days=90, seconds=1)).strftime('%a, %d %b %Y %H:%M:%S %z'))
        service = ActivityReconstructionService().reconstruct([message], now)[0]
        self.assertEqual(service.timeline[0].timestamp_basis, 'email_date_header')
        self.assertEqual(service.activity_status, 'possibly_dormant')
        self.assertIn('90/100 from login', service.confidence_explanation)
        message['internal_date'] = str(int(now.timestamp() * 1000))
        service = ActivityReconstructionService().reconstruct([message], now)[0]
        self.assertEqual(service.timeline[0].timestamp_basis, 'email_receipt')
        self.assertEqual(service.activity_status, 'recent_evidence')

    def test_summary_and_privacy(self):
        emails = [dict(sender_domain='example.com', message_id=str(i), subject=subject, date=date)
                  for i, (subject, date) in enumerate([
                      ('Account created', '1 Jan 2020 10:00:00 +0000'),
                      ('New login detected', '1 Jan 2026 10:00:00 +0000'),
                      ('Suspicious activity', '1 Oct 2026 10:00:00 +0000'),
                      ('Your receipt', '2 Oct 2026 10:00:00 +0000')])]
        emails += [emails[1], dict(sender_domain='example.com', subject='New login detected', date='bad')]
        result = ActivityReconstructionService().reconstruct(emails, datetime(2026, 10, 8, tzinfo=timezone.utc))[0]
        self.assertEqual(len(result.timeline), 4)
        self.assertEqual(result.last_confirmed_login.month, 1)
        self.assertEqual(result.last_security_event.month, 10)
        self.assertEqual(result.last_seen.day, 2)
        self.assertEqual(result.activity_status, 'possibly_dormant')
        self.assertNotIn('subject', result.model_dump_json())

    def test_unclassified_and_invalid_dates(self):
        self.assertIsNone(classify('Sale ends today'))
        self.assertEqual(ActivityReconstructionService().reconstruct([
            dict(sender_domain='example.com', subject='Account created', date='invalid')]), [])

    def test_categories_status_and_password_security_time(self):
        for subject, kind in [('Verify your account', 'account_verification'),
                              ('Password changed', 'password'), ('Your receipt', 'transaction'),
                              ('Usage summary', 'activity'), ('Thanks for signing up', 'account_creation')]:
            self.assertEqual(classify(subject)[0], kind)
        now = datetime(2026, 10, 8, tzinfo=timezone.utc)
        emails = [dict(sender_domain='example.com', subject='Password changed',
                       date='1 Oct 2026 10:00:00 +0000')]
        service = ActivityReconstructionService().reconstruct(emails, now)[0]
        self.assertEqual(service.activity_status, 'unknown')
        self.assertEqual(service.last_security_event.month, 10)
        emails.append(dict(sender_domain='example.com', subject='Successfully signed in',
                           date='2 Oct 2026 10:00:00 +0000'))
        self.assertEqual(ActivityReconstructionService().reconstruct(emails, now)[0].activity_status, 'recent_evidence')

    def test_future_adapter(self):
        from app.models import ActivityEvidence
        now = datetime(2026, 10, 8, tzinfo=timezone.utc)
        evidence = ActivityEvidence(source='future_adapter', source_id='1', event_type='activity',
                                    observed_at=now, confidence_score=55)
        services = ActivityReconstructionService().reconstruct_evidence([
            ('example.com', evidence), ('example.com', evidence)], now)
        self.assertEqual(len(services[0].timeline), 1)
        self.assertEqual(services[0].timeline[0].source, 'future_adapter')


if __name__ == '__main__':
    unittest.main()
