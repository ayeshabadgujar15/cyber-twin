"""Fictional, clock-relative demo. Never reads a mailbox or stores personal data."""
from datetime import datetime, timedelta, timezone
from app.models import ActivityEvidence
from app.services.activity_reconstruction import ActivityReconstructionService
from app.services.activity_insights import build_insights


def activity_demo(now=None):
    now = now or datetime.now(timezone.utc)
    records = []
    samples = [
        ('streamnest.example', 'Streamnest', [(210, 'account_creation', 85), (28, 'transaction', 70), (2, 'transaction', 70)]),
        ('cloudfolio.example', 'Cloudfolio', [(330, 'account_creation', 85), (90, 'activity', 55), (3, 'login', 90), (1, 'security', 85)]),
        ('trailclub.example', 'Trail Club', [(620, 'account_creation', 85), (420, 'login', 90)]),
        ('shoplane.example', 'Shoplane', [(280, 'account_creation', 85), (45, 'transaction', 70), (5, 'password', 80)]),
        ('codegarden.example', 'Code Garden', [(190, 'account_creation', 85), (60, 'activity', 55), (8, 'activity', 55)]),
        ('welcome.example', 'Welcome Weekly', [(12, 'account_creation', 50)]),
    ]
    names = {}
    for domain, name, events in samples:
        names[domain] = name
        for index, (days, kind, score) in enumerate(events):
            records.append((domain, ActivityEvidence(source='demo', source_id=f'{domain}-{index}',
                event_type=kind, observed_at=now - timedelta(days=days), confidence_score=score,
                timestamp_basis='fictional_sample_time',
                classification_explanation='Fictional example used to demonstrate this kind of evidence.')))
    services = ActivityReconstructionService().reconstruct_evidence(records, now)
    for service in services:
        service.service_name = names[service.domain]
    return {'is_demo': True, 'services_found': len(services), 'services': services,
            'insights': build_insights(services, now),
            'coverage': {'messages_scanned': len(records), 'scan_complete': False,
                         'scanned_at': now.isoformat(), 'note': 'Fictional sample data. No Gmail connection or mailbox scan was used.'},
            'limitations': 'Demo only. These fictional accounts and events are not yours.'}
