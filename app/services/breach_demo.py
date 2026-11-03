"""Fictional three-module walkthrough. No provider requests."""
from app.security.security_plan import security_plan


def demo_breaches(services):
    checks = []
    for service in services:
        domain = service['domain']
        breached = domain == 'cloudfolio.example'
        checks.append({'domain':domain, 'service_name':service.get('service_name') or domain,
                       'status':'checked', 'known_breach':breached, 'is_demo':True,
                       'note':'Fictional demo result, not a provider finding.',
                       'breaches':[{'id':'FictionalCloudfolio', 'name':'Cloudfolio — fictional example',
                                    'domain':domain, 'breach_date':'2025-06-12', 'breach_year':2025,
                                    'description':'Fictional demonstration: an example incident exposed account email addresses and password hashes. This is not a real breach.',
                                    'data_exposed':['Email addresses','Passwords'], 'affected_records':12000,
                                    'verified':False, 'added_date':'2025-07-01T00:00:00Z',
                                    'modified_date':'2025-07-01T00:00:00Z', 'source_url':None,
                                    'match_type':'exact', 'is_demo':True}] if breached else []})
    return {'checks':checks, 'security_plan':security_plan(services, checks), 'is_demo':True,
            'checked_at':None, 'note':'All incidents and services are fictional. No mailbox or breach provider was queried.'}
