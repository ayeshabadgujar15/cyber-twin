"""Metadata-only reconstruction. Scores are heuristic evidence strength, not probabilities."""
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from app.models import ActivityEvidence, DiscoveredService


RULES = [
    ('security', r'suspicious|unusual|unauthorized|failed (?:login|sign.in)|(?:login|sign.in) attempt|security alert', 85),
    ('password', r'password (?:(?:has been|was) )?(?:changed|reset|updated)|reset your password', 80),
    ('login', r'new (?:login|sign.in)(?: detected| from| to| on|$)|successfully (?:logged|signed) in|new device (?:logged|signed) in', 90),
    ('security', r'verification code|one.time (?:password|code)|login code|sign.in code', 60),
    ('account_creation', r'account (?:(?:has been|was) )?created|registration successful|thanks for signing up', 85),
    ('account_verification', r'verify your (?:email|account)|confirm your (?:email|account)|activate your account', 65),
    ('transaction', r'payment (?:confirmation|received)|order confirmed|your (?:receipt|order)|subscription renewed|invoice', 70),
    ('activity', r'account activity|usage summary', 55),
    ('account_creation', r'welcome to', 50),
]


RULE_EXPLANATIONS = {
    'account_creation': 'Subject indicates account creation or registration; not proof of ownership.',
    'account_verification': 'Subject requests verification; completed verification is not established.',
    'login': 'Subject indicates a successful login notification; no independent session verification.',
    'security': 'Subject contains an alert, attempt, code, or authentication challenge; not a confirmed login.',
    'password': 'Subject indicates a password event or reset request; completion is not independently verified.',
    'transaction': 'Subject indicates billing or transaction evidence; not proof of active account use.',
    'activity': 'Subject indicates an activity or usage summary; may describe automated or past activity.',
}


def classify(subject):
    # Attempts and OTPs must never count as successful logins. No body is fetched.
    if re.search(r'login|log.in|sign.in|signed in|logged in', subject, re.I):
        if re.search(r'not (?:successful|completed)|(?:two.factor|2fa|multi.factor|mfa|authentication|verification) (?:is )?required|pending|not you|not (?:signed|logged) in|could not|cannot|can.t|cancelled|canceled|rejected', subject, re.I):
            return 'security', 60
    if re.search(r'\b(?:otp|verification code|security code|authentication code|one.time (?:password|code)|login code|sign.in code)\b', subject, re.I):
        return 'security', 60
    if re.search(r'\b(?:failed|unsuccessful|blocked|denied|attempt|attempted|suspicious|unusual|unauthorized)\b', subject, re.I):
        if re.search(r'login|log.in|sign.in|signed in|logged in|security|activity|access', subject, re.I):
            return 'security', 85
    for kind, pattern, score in RULES:
        if re.search(pattern, subject, re.I):
            return kind, score
    return None


def timestamp(message):
    try:
        if message.get('internal_date'):
            value = datetime.fromtimestamp(int(message['internal_date']) / 1000, timezone.utc)
        else:
            value = parsedate_to_datetime(message.get('date', ''))
            value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return value
    except (ValueError, TypeError, OverflowError, OSError, AttributeError):
        return None


class ActivityReconstructionService:
    def reconstruct(self, emails, now=None):
        now = now or datetime.now(timezone.utc)
        normalized = []
        for message in emails:
            domain = message.get('sender_domain', '').strip().lower()
            match = classify(message.get('subject', ''))
            date = timestamp(message)
            if not domain or not match or date is None or date > now:
                continue
            # Exact sender domains intentionally avoid unsafe brand/subdomain merging.
            normalized.append((domain, ActivityEvidence(
                source='gmail', source_id=message.get('message_id'),
                timestamp_basis='email_receipt' if message.get('internal_date') else 'email_date_header',
                classification_explanation=(
                    'Generic welcome wording is weak evidence and does not establish account creation or recent use.'
                    if match == ('account_creation', 50) else RULE_EXPLANATIONS[match[0]]
                ),
                event_type=match[0], observed_at=date, confidence_score=match[1],
            )))
        return self.reconstruct_evidence(normalized, now)

    def reconstruct_evidence(self, records, now=None):
        """Future adapters supply (service domain, ActivityEvidence) pairs."""
        now = now or datetime.now(timezone.utc)
        services, seen = {}, set()
        for domain, evidence in records:
            domain = domain.strip().lower()
            if not domain or evidence.observed_at.tzinfo is None or evidence.observed_at > now:
                continue
            identity = (domain, evidence.source, evidence.source_id or (evidence.observed_at.isoformat(), evidence.event_type))
            if identity in seen:
                continue
            seen.add(identity)
            service = services.setdefault(domain, DiscoveredService(service_name=domain, domain=domain))
            service.timeline.append(evidence)
        for service in services.values():
            service.timeline.sort(key=lambda event: (event.observed_at, event.source_id or ''))
            service.first_seen = service.timeline[0].observed_at
            service.last_seen = service.timeline[-1].observed_at
            service.last_confirmed_login = max((e.observed_at for e in service.timeline if e.event_type == 'login'), default=None)
            service.last_security_event = max((e.observed_at for e in service.timeline if e.event_type in {'security', 'password'}), default=None)
            # Passive billing and security alerts don't establish actual account use.
            active = [e.observed_at for e in service.timeline if e.event_type in {'login', 'activity'} or (e.event_type == 'account_creation' and e.confidence_score >= 85)]
            age = (now - max(active)).total_seconds() if active else None
            service.activity_status = 'unknown' if age is None else ('recent_evidence' if age <= 90 * 86400 else 'possibly_dormant')
            service.activity_status_explanation = (
                'No qualifying login, activity, or explicit creation evidence; alerts, billing and generic welcomes do not establish use.'
                if age is None else
                'Qualifying evidence exists within the last 90 days; this does not establish current use.'
                if age <= 90 * 86400 else
                'Latest qualifying evidence is older than 90 days within this scan; missing mail can hide newer activity. Dormancy is not confirmed.'
            )
            service.confidence_score = max(e.confidence_score for e in service.timeline)
            strongest = sorted({e.event_type for e in service.timeline if e.confidence_score == service.confidence_score})
            service.confidence_explanation = (
                f'Maximum evidence score {service.confidence_score}/100 from {", ".join(strongest)}; '
                'additional messages do not increase the score. Heuristic evidence strength, '
                'not a probability or proof of ownership or a successful session.'
            )
        return sorted(services.values(), key=lambda service: service.domain)
