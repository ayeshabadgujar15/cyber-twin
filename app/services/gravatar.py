"""Documented Gravatar profile API; discard the response after normalization."""
import hashlib
import os
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.services.public_activity import fetch_json, make_result, parse_time, SourceError


class GravatarService:
    def lookup_email(self, email):
        digest = hashlib.sha256(email.strip().lower().encode('utf-8')).hexdigest()
        key = os.getenv('GRAVATAR_API_KEY')
        now = datetime.now(timezone.utc)
        coverage = {'history_complete': False, 'note': 'Only the primary profile email may resolve. An absent profile does not prove an absent account. Registration and profile-edit dates may require an API key; edits are not logins.'}
        try:
            profile = fetch_json(f'https://api.gravatar.com/v3/profiles/{digest}',
                                 headers={'Authorization': f'Bearer {key}'} if key else None)
        except SourceError as error:
            return {'accounts': [], 'accounts_found': 0, 'source_outcomes': [
                {'source': 'gravatar', 'outcome': error.outcome, 'checked_at': now.isoformat(), 'note': error.detail}], 'coverage': coverage}
        if not isinstance(profile, dict) or not isinstance(profile.get('hash'), str):
            raise SourceError(502, 'Invalid Gravatar profile response.')
        url = f'https://gravatar.com/{digest}'
        result = make_result('gravatar', 'gravatar.com', None, url,
                             [('registration_date', 'account_creation', profile.get('registration_date'))],
                             profile.get('location'), coverage, now)
        result.profile_updated_at = parse_time(profile.get('last_profile_edit'), now)
        # Provider-linked accounts are leads, not additional independently checked accounts.
        accounts = profile.get('verified_accounts', [])
        if isinstance(accounts, list):
            for account in accounts[:50]:
                if isinstance(account, dict) and account.get('is_hidden') is True:
                    continue
                link = account.get('url') if isinstance(account, dict) else None
                if isinstance(link, str) and len(link) <= 2048:
                    try:
                        parsed = urlsplit(link)
                    except ValueError:
                        continue
                    if parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password:
                        result.linked_profiles.append(link)
        return {'accounts': [result], 'accounts_found': 1, 'source_outcomes': [
            {'source': 'gravatar', 'outcome': 'found', 'checked_at': now.isoformat(), 'note': 'Public profile returned; ownership unverified.'}], 'coverage': coverage}
