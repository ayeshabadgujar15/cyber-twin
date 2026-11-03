"""Read documented public APIs. Only normalized dates and location metadata escape."""
import json
import os
import re
import socket
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

from app.models import ActivityEvidence, DiscoveredService, LocationEvidence, PublicAccountReconstruction
from app.services.activity_reconstruction import ActivityReconstructionService


class SourceError(Exception):
    def __init__(self, status, detail, outcome=None):
        self.status, self.detail = status, detail
        self.outcome = outcome or ('absent' if status == 404 else 'blocked' if status in (401, 403, 503) else 'unknown')
        super().__init__(detail)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_json(url, body=None, headers=None):
    """Fixed provider URLs only, bounded response and timeout, no credential redirects."""
    request_headers = {'User-Agent': 'CyberTwin/1.0', 'Accept': 'application/json'}
    request_headers.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request_headers['Content-Type'] = 'application/json'
    try:
        with build_opener(NoRedirect()).open(Request(url, data=data, headers=request_headers), timeout=25) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise SourceError(502, 'Provider response exceeded the metadata limit.')
        return json.loads(raw)
    except HTTPError as error:
        error.close()
        if error.code == 404:
            raise SourceError(404, 'Public account not found.') from None
        if error.code in (403, 429):
            raise SourceError(503, 'Provider denied access or rate limited the request.') from None
        if error.code == 401:
            raise SourceError(502, 'Provider authentication failed; check API access and IP whitelist.', 'blocked') from None
        raise SourceError(502, 'Provider request failed.') from None
    except (TimeoutError, socket.timeout):
        raise SourceError(504, 'Provider request timed out.', 'timed_out') from None
    except URLError as error:
        if isinstance(error.reason, TimeoutError):
            raise SourceError(504, 'Provider request timed out.', 'timed_out') from None
        raise SourceError(502, 'Provider response was unavailable.', 'unknown') from None
    except (OSError, ValueError):
        raise SourceError(502, 'Provider response was unavailable or invalid.') from None


def parse_time(value, now):
    if isinstance(value, bool) or value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            result = datetime.fromtimestamp(value, timezone.utc)
        elif isinstance(value, str):
            result = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if result.tzinfo is None:
                result = result.replace(tzinfo=timezone.utc)
        else:
            return None
        result = result.astimezone(timezone.utc)
        return result if datetime(1970, 1, 1, tzinfo=timezone.utc) <= result <= now else None
    except (ValueError, OverflowError, OSError):
        return None


def username_for(provider, username):
    patterns = {'github': r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?',
                'chess.com': r'[A-Za-z0-9][A-Za-z0-9_-]{0,49}'}
    if provider not in patterns or not re.fullmatch(patterns[provider], username):
        raise SourceError(422, 'Unsupported provider or invalid username.')
    return username


def make_result(provider, domain, username, url, dates, location, coverage, now):
    records = []
    for field, kind, value in dates:
        date = parse_time(value, now)
        if date is not None:
            records.append((domain, ActivityEvidence(
                source=provider, source_id=field, event_type=kind, observed_at=date,
                confidence_score=85, source_url=url, timestamp_basis=field)))
    services = ActivityReconstructionService().reconstruct_evidence(records, now)
    service = services[0] if services else DiscoveredService(domain=domain, service_name=domain)
    service.confidence_explanation = 'Maximum of 85 per dated public provider record, or 0 without dated records; heuristic source strength, not proof of ownership, location accuracy, or a successful login.'
    locations = []
    if isinstance(location, str) and location.strip():
        locations.append(LocationEvidence(value=location.strip()[:200], kind='profile_declared',
                                          source=provider, source_url=url, retrieved_at=now))
    latest = max(service.timeline, key=lambda event: event.observed_at, default=None)
    return PublicAccountReconstruction(provider=provider, username=username, profile_url=url,
        retrieved_at=now, service=service, locations=locations,
        last_public_activity=max((event.observed_at for event in service.timeline if event.event_type == 'activity'), default=None),
        last_seen_basis=latest.timestamp_basis if latest else None, coverage=coverage)


class PublicActivityService:
    def lookup(self, provider, username):
        username_for(provider, username)
        now = datetime.now(timezone.utc)
        if provider == 'github':
            url = f'https://api.github.com/users/{username}'
            profile = fetch_json(url)
            if not isinstance(profile, dict) or not profile.get('login'):
                raise SourceError(502, 'Invalid public profile response.')
            dates = [('account_created', 'account_creation', profile.get('created_at'))]
            coverage = {'profile_retrieved': True, 'events_retrieved': False,
                        'history_complete': False,
                        'note': 'At most 300 recent public events; private activity and logins are unavailable. Events may be delayed.'}
            # Profile metadata remains useful even when the activity feed fails.
            try:
                for page in range(1, 4):
                    events = fetch_json(f'{url}/events/public?per_page=100&page={page}')
                    if not isinstance(events, list):
                        raise SourceError(502, 'Invalid public event response.')
                    for event in events:
                        if isinstance(event, dict) and event.get('public') is True:
                            dates.append((f"public_event:{event.get('id', '')}", 'activity', event.get('created_at')))
                    if len(events) < 100:
                        break
                coverage['events_retrieved'] = True
            except SourceError as error:
                coverage['activity_error'] = error.detail
                coverage['activity_outcome'] = error.outcome
            result = make_result(provider, 'github.com', profile['login'], f"https://github.com/{username}",
                               dates, profile.get('location'), coverage, now)
            result.profile_updated_at = parse_time(profile.get('updated_at'), now)
            return result
        url = f'https://api.chess.com/pub/player/{username}'
        profile = fetch_json(url)
        if not isinstance(profile, dict) or not profile.get('username'):
            raise SourceError(502, 'Invalid public profile response.')
        return make_result(provider, 'chess.com', profile['username'], f'https://www.chess.com/member/{username}',
                           [('account_created', 'account_creation', profile.get('joined')),
                            ('provider_last_online', 'activity', profile.get('last_online'))],
                           profile.get('location'), {'profile_retrieved': True, 'history_complete': False,
                           'note': 'Provider last_online is not independently verified login evidence. Public data may be cached up to 12 hours.'}, now)


class IntelBaseActivityService:
    """Optional paid wider coverage, with breaches and stealer data disabled."""
    def lookup_email(self, email):
        key = os.getenv('INTELBASE_API_KEY')
        if not key:
            raise SourceError(503, 'Set INTELBASE_API_KEY for optional IntelBase email coverage.')
        payload = fetch_json('https://api.intelbase.is/lookup/email', {
            'email': email, 'timeout_ms': 10000,
            'include_data_breaches': False, 'include_stealer_logs': False}, {'x-api-key': key})
        if not isinstance(payload, dict) or not isinstance(payload.get('identifier'), dict):
            raise SourceError(502, 'Invalid IntelBase account response.')
        now = datetime.now(timezone.utc)
        results = []
        accounts = payload['identifier'].get('accounts')
        if not isinstance(accounts, list):
            raise SourceError(502, 'Invalid IntelBase account list.')
        for account in accounts:
            if not isinstance(account, dict):
                continue
            module, data = account.get('module', {}), account.get('data', {})
            if not isinstance(module, dict) or not isinstance(data, dict):
                continue
            domain = module.get('domain')
            if not isinstance(domain, str) or not re.fullmatch(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', domain):
                continue
            # Allowlist only. Unknown fields and all raw provider responses are discarded.
            dates = [('provider_creation_date', 'account_creation', data.get('creation_date'))]
            for field in ('last_seen', 'last_login', 'last_online', 'last_activity'):
                if field in data:
                    dates.append((f'provider_{field}', 'activity', data[field]))
            username = data.get('username') if isinstance(data.get('username'), str) else None
            result = make_result('intelbase', domain.lower(), username, None, dates,
                                 data.get('location'), {'history_complete': False,
                                 'note': 'Fields vary by module; unrecognized date/location fields are omitted. No ownership or login verification.'}, now)
            for location in result.locations:
                location.kind = 'provider_reported'
            result.profile_updated_at = parse_time(data.get('last_profile_edit', data.get('profile_updated_at')), now)
            results.append(result)
        outcomes = [{'source': 'intelbase', 'domain': result.service.domain,
                     'outcome': 'found', 'checked_at': now.isoformat(),
                     'note': 'Provider profile returned; ownership unverified.'} for result in results]
        validator = payload.get('validator', {})
        if not isinstance(validator, dict):
            raise SourceError(502, 'Invalid IntelBase registration response.')
        known = {result.service.domain for result in results}
        for field, outcome in [('registered', 'found'), ('unregistered', 'absent')]:
            modules = validator.get(field, [])
            if not isinstance(modules, list):
                raise SourceError(502, 'Invalid IntelBase registration list.')
            for module in modules:
                domain = module.get('domain') if isinstance(module, dict) else None
                if not isinstance(domain, str) or not re.fullmatch(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', domain):
                    continue
                domain = domain.lower()
                if domain in known:
                    continue
                known.add(domain)
                outcomes.append({'source': 'intelbase', 'domain': domain, 'outcome': outcome,
                                 'checked_at': now.isoformat(), 'note': 'Provider registration check; not independently verified. No dated activity supplied.'})
                if outcome == 'found':
                    results.append(make_result('intelbase', domain, None, None, [], None,
                                   {'history_complete': False, 'note': 'Registration-only match; no profile, dates, location, or ownership verification.'}, now))
        return {'accounts': results, 'accounts_found': len(results),
                'source_outcomes': outcomes,
                'coverage': {'history_complete': False, 'unlisted_modules_outcome': 'unknown',
                             'note': 'Provider profiles and registration checks only. Omitted modules may be filtered, unavailable, or timed out; they remain unknown. No breaches or stealer data requested.'}}
