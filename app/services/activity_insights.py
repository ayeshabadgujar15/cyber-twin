"""Explain mailbox evidence without claims of compromise, spend or current ownership."""
from collections import Counter
from datetime import datetime, timezone


def build_insights(services, now=None):
    now = now or datetime.now(timezone.utc)
    counts = Counter()
    months = {}
    for offset in range(11, -1, -1):
        index = now.year * 12 + now.month - 1 - offset
        year, month = divmod(index, 12)
        months[f'{year:04d}-{month + 1:02d}'] = 0
    queue = []
    for service in services:
        events = service.timeline
        counts.update(event.event_type for event in events)
        for event in events:
            key = event.observed_at.astimezone(timezone.utc).strftime('%Y-%m')
            if key in months:
                months[key] += 1
        alerts = [event for event in events if event.event_type == 'security' and event.confidence_score >= 85]
        passwords = [event for event in events if event.event_type == 'password']
        billing = [event for event in events if event.event_type == 'transaction']
        def add(category, title, explanation, suggestion, event, priority):
            queue.append({'id': f'{category}:{service.domain}', 'domain': service.domain,
                          'service_name': service.service_name, 'category': category,
                          'title': title, 'explanation': explanation,
                          'suggested_action': suggestion, 'observed_at': event.observed_at,
                          'priority': priority})
        if alerts:
            latest = max(alerts, key=lambda event: event.observed_at)
            recent = (now - latest.observed_at).total_seconds() <= 30 * 86400
            add('security', 'Recognize this security notification?',
                'A subject matched an alert or unsuccessful-access rule. It does not establish that someone got in.',
                'Open the service using its app or a saved bookmark. Review its security activity and devices; avoid links in an unfamiliar alert.',
                latest, 1 if recent else 3)
        if passwords:
            latest = max(passwords, key=lambda event: event.observed_at)
            add('password', 'Check this password event',
                'A reset request or password notification appeared. A request alone does not mean the password changed.',
                'If you did not request or make the change, check the service directly. Review recovery details and enable two-step verification where available.',
                latest, 2)
        if billing:
            latest = max(billing, key=lambda event: event.observed_at)
            add('billing', 'Still recognize this billing activity?',
                'Receipts, invoices or renewal wording were found. Amounts, recurring charges and an active subscription are not verified.',
                'Review purchase or subscription settings in the service app. Confirm what you still use; Cyber Twin does not cancel anything.',
                latest, 4)
        if service.activity_status == 'possibly_dormant':
            latest = max((event for event in events if event.event_type in {'login', 'activity'} or
                          (event.event_type == 'account_creation' and event.confidence_score >= 85)),
                         key=lambda event: event.observed_at)
            add('forgotten', 'An account you may have forgotten',
                'The latest qualifying evidence in this scan is over 90 days old. Missing messages may hide more recent use.',
                'Decide whether you still need the account. Check saved files, purchases and sign-in dependencies before changing or closing it yourself.',
                latest, 5)
        if events and all(event.confidence_score <= 65 and event.event_type in {'account_creation', 'account_verification', 'security'} for event in events):
            add('identity', 'Confirm whether this is your account',
                'Only welcome, verification or code evidence was found. Completed registration and ownership are not established.',
                'Check whether you recognize the service. Treat this as a clue, not a confirmed account.',
                events[-1], 6)
    queue.sort(key=lambda item: (item['priority'], -item['observed_at'].timestamp(), item['domain'], item['category']))
    return {
        'service_count': len(services),
        'evidence_count': sum(counts.values()),
        'recent_services': sum(service.activity_status == 'recent_evidence' for service in services),
        'possibly_dormant_services': sum(service.activity_status == 'possibly_dormant' for service in services),
        'security_services': sum(any(event.event_type == 'security' and event.confidence_score >= 85 for event in service.timeline) for service in services),
        'billing_services': sum(any(event.event_type == 'transaction' for event in service.timeline) for service in services),
        'event_counts': dict(counts),
        'monthly_activity': [{'month': month, 'evidence_count': value} for month, value in months.items()],
        'review_queue': queue[:1000], 'review_queue_total': len(queue),
        'review_queue_truncated': len(queue) > 1000,
        'explanation': 'Review prompts are derived from scanned mailbox evidence, not verified threats, subscriptions or inactivity. OTP/code notifications alone are not security alerts.',
    }
