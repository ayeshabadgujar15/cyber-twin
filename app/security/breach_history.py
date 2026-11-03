"""HIBP service history and optional email lookup; descriptions are plain text."""
import json
import time
from datetime import date
from html.parser import HTMLParser
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

HIBP_API = 'https://haveibeenpwned.com/api/v3'
USER_AGENT = 'Cyber-Twin'


class PlainDescription(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.ignored = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {'script','style'}:
            self.ignored += 1
        elif tag in {'p','br','li','div'}:
            self.parts.append(' ')

    def handle_endtag(self, tag):
        if tag in {'script','style'}:
            self.ignored = max(0, self.ignored - 1)
        elif tag in {'p','li','div'}:
            self.parts.append(' ')

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)


def normalize_breach(breach):
    parser = PlainDescription()
    parser.feed(str(breach.get('Description') or 'No description supplied.'))
    try:
        when = date.fromisoformat(breach.get('BreachDate'))
    except (ValueError, TypeError):
        when = None
    name = str(breach.get('Name') or breach.get('Title') or 'Unknown')
    count = breach.get('PwnCount')
    classes = breach.get('DataClasses') or []
    return {'id':name, 'name':str(breach.get('Title') or name),
            'domain':str(breach.get('Domain') or '').lower().rstrip('.'),
            'breach_date':when.isoformat() if when else None, 'breach_year':when.year if when else None,
            'description':' '.join(''.join(parser.parts).split()),
            'data_exposed':[value for value in classes if isinstance(value, str)] if isinstance(classes, list) else [],
            'affected_records':count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
            'added_date':breach.get('AddedDate'), 'modified_date':breach.get('ModifiedDate'),
            'verified':breach.get('IsVerified') is True, 'sensitive':breach.get('IsSensitive') is True,
            'retired':breach.get('IsRetired') is True,
            'source_url':f'{HIBP_API}/breach/{quote(name, safe="")}',
            'attribution':str(breach.get('Attribution') or '')}


class BreachChecker:
    def check_breaches(self, domains):
        """One public catalogue request; exact or parent-domain matches locally.

        Exclude fabricated/spam/malware datasets from service incident history.
        Label unverified reports. Sender authenticity and personal exposure
        cannot be established by this catalogue lookup.
        """
        domains = [domain.strip().lower().rstrip('.') for domain in domains]
        if any(not domain or '@' in domain for domain in domains):
            raise ValueError('Provide service domains, not email addresses.')
        if not domains:
            return []
        catalogue = self._get_json(Request(f'{HIBP_API}/breaches', headers={'User-Agent':USER_AGENT}))
        if not isinstance(catalogue, list):
            raise ValueError('Invalid breach catalogue')
        index = {}
        for raw in catalogue:
            if not isinstance(raw, dict) or any(raw.get(flag) for flag in ('IsFabricated','IsSpamList','IsMalware','IsStealerLog')):
                continue
            entry = normalize_breach(raw)
            if '.' in entry['domain']:
                index.setdefault(entry['domain'], []).append(entry)
        results = []
        for domain in domains:
            labels, breaches = domain.split('.'), []
            for start in range(len(labels) - 1):
                match = '.'.join(labels[start:])
                breaches.extend({**breach, 'match_type':'exact' if match == domain else 'sender_subdomain'} for breach in index.get(match, []))
            breaches.sort(key=lambda item:item['breach_date'] or '', reverse=True)
            results.append({'domain':domain, 'known_breach':bool(breaches), 'breaches':breaches,
                            'source':'https://haveibeenpwned.com/',
                            'note':'Service history matched by sender or parent domain. Sender identity and personal exposure remain unverified. No match does not establish safety.'})
        return results

    def check_email(self, email, api_key):
        email = email.strip()
        if '@' not in email:
            raise ValueError('Provide an email address.')
        request = Request(f'{HIBP_API}/breachedaccount/{quote(email, safe="")}?truncateResponse=false',
                          headers={'User-Agent':USER_AGENT, 'hibp-api-key':api_key})
        try:
            raw = self._get_json(request)
        except HTTPError as error:
            if error.code != 404:
                raise
            raw = []
        if not isinstance(raw, list):
            raise ValueError('Invalid email breach result')
        breaches = [normalize_breach(item) for item in raw if isinstance(item, dict) and not item.get('IsFabricated')]
        return {'email':email, 'breached':bool(breaches), 'breaches':sorted(breaches, key=lambda item:item['breach_date'] or '', reverse=True),
                'source':'https://haveibeenpwned.com/'}

    def _get_json(self, request):
        for attempt in range(2):
            try:
                with urlopen(request, timeout=15) as response:
                    raw = response.read(20_000_001)
                if len(raw) > 20_000_000:
                    raise ValueError('Breach catalogue exceeded response limit')
                return json.loads(raw)
            except HTTPError as error:
                if error.code != 429 or attempt:
                    raise
                try:
                    wait = min(max(int(error.headers.get('Retry-After','2')),0),10)
                except (ValueError, TypeError):
                    wait = 2
                error.close()
                time.sleep(wait)
