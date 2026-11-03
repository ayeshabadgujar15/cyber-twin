from html.parser import HTMLParser
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import URLError

import app.main as main
from app.security.breach_history import BreachChecker, normalize_breach
from app.security.security_plan import security_plan
from test_activity_integration import request


def incident(**fields):
    return {'Name':'ExampleIncident', 'Title':'Example incident', 'Domain':'example.com',
            'BreachDate':'2023-04-17', 'AddedDate':'2023-05-01T00:00:00Z',
            'ModifiedDate':'2024-01-01T00:00:00Z', 'PwnCount':1234,
            'Description':'<p>Account <strong>details</strong> &amp; passwords exposed.</p><script>bad()</script>',
            'DataClasses':['Email addresses','Passwords'], 'IsVerified':True, **fields}


class BreachModuleTests(unittest.TestCase):
    def test_date_description_and_record_details(self):
        data = normalize_breach(incident())
        self.assertEqual(data['breach_year'],2023)
        self.assertEqual(data['breach_date'],'2023-04-17')
        self.assertEqual(data['description'],'Account details & passwords exposed.')
        self.assertEqual(data['affected_records'],1234)
        self.assertTrue(data['verified'])
        self.assertEqual(data['data_exposed'],['Email addresses','Passwords'])
        self.assertIn('/breach/ExampleIncident',data['source_url'])

    def test_parent_domain_boundary_unverified_and_filtered_datasets(self):
        catalogue = [incident(),incident(Name='Unverified',IsVerified=False),
                     incident(Name='Fake',IsFabricated=True),incident(Name='Spam',IsSpamList=True),
                     incident(Name='Malware',IsMalware=True)]
        with patch.object(BreachChecker,'_get_json',return_value=catalogue) as fetch:
            checks = BreachChecker().check_breaches(['mail.example.com','notexample.com','example.com.evil.test'])
        self.assertEqual(len(checks[0]['breaches']),2)
        self.assertEqual(checks[0]['breaches'][0]['match_type'],'sender_subdomain')
        self.assertTrue(any(not entry['verified'] for entry in checks[0]['breaches']))
        self.assertFalse(checks[1]['known_breach'])
        self.assertFalse(checks[2]['known_breach'])
        self.assertEqual(fetch.call_args.args[0].full_url,'https://haveibeenpwned.com/api/v3/breaches')
        fetch.assert_called_once()

    def test_real_endpoint_joins_scan_services_to_details_and_actions(self):
        with patch.object(BreachChecker,'_get_json',return_value=[incident()]):
            status, body = request('/accounts/service-breaches',method='POST',payload={'services':[{'domain':'example.com','service_name':'Example'}]})
        self.assertEqual(status,200)
        self.assertEqual(body['checks'][0]['status'],'checked')
        self.assertEqual(body['checks'][0]['breaches'][0]['description'],'Account details & passwords exposed.')
        self.assertEqual(body['security_plan'][0]['priority'],'review_first')
        self.assertIn('not established',body['security_plan'][0]['reason'])
        self.assertIn('phishing',[step['id'] for step in body['security_plan'][0]['steps']])

    def test_unavailable_is_not_a_clean_result(self):
        with patch.object(BreachChecker,'check_breaches',side_effect=URLError('private diagnostic')):
            status, body = request('/accounts/service-breaches',method='POST',payload={'services':[{'domain':'example.com'}]})
        self.assertEqual(status,200)
        self.assertIsNone(body['checks'][0]['known_breach'])
        self.assertEqual(body['checks'][0]['status'],'unavailable')
        self.assertIn('not completed',body['security_plan'][0]['reason'])
        self.assertNotIn('private diagnostic',str(body))

    def test_demo_does_not_query_provider_or_accept_real_targets(self):
        with patch.object(BreachChecker,'check_breaches') as check:
            status, body = request('/accounts/service-breaches',method='POST',payload={'is_demo':True,'services':[{'domain':'cloudfolio.example'}]})
            self.assertEqual(status,200)
            self.assertTrue(body['is_demo'])
            self.assertIn('Fictional',body['checks'][0]['breaches'][0]['description'])
            self.assertEqual(request('/accounts/service-breaches',method='POST',payload={'is_demo':True,'services':[{'domain':'example.com'}]})[0],422)
            check.assert_not_called()

    def test_origin_input_validation_and_empty_data(self):
        payload = {'services':[{'domain':'example.com'}]}
        self.assertEqual(request('/accounts/service-breaches',method='POST',payload=payload,headers=[(b'origin',b'https://outside.example')])[0],403)
        for body in [{'services':[]},{'services':[{'domain':'someone@example.com'}]}]:
            self.assertEqual(request('/accounts/service-breaches',method='POST',payload=body)[0],422)

    def test_partial_provider_result_does_not_silently_drop_services(self):
        with patch.object(BreachChecker,'check_breaches',return_value=[]):
            _, body = request('/accounts/service-breaches',method='POST',payload={'services':[{'domain':'example.com'}]})
        self.assertEqual(len(body['checks']),1)
        self.assertEqual(body['checks'][0]['status'],'unavailable')

    def test_security_without_breach_proof_remains_conditional(self):
        plan = security_plan([{'domain':'example.com','security_alert':True}],[])[0]
        self.assertEqual(plan['priority'],'review_first')
        self.assertIn('not proof',plan['reason'])
        self.assertIn('If the current password',plan['steps'][1]['detail'])


class ModuleMarkupTests(unittest.TestCase):
    def test_unique_ids_and_all_three_modules_and_support_tools(self):
        class IDs(HTMLParser):
            def __init__(self):
                super().__init__(); self.ids=[]
            def handle_starttag(self,tag,attrs):
                for key,value in attrs:
                    if key=='id': self.ids.append(value)
        parser = IDs(); parser.feed((Path(__file__).parent/'app/static/index.html').read_text(encoding='utf-8'))
        self.assertEqual(len(parser.ids),len(set(parser.ids)))
        for value in ['gmail-panel','breaches-panel','secure-panel','connection-email','public-form','migration-panel','review-area']:
            self.assertIn(value,parser.ids)
