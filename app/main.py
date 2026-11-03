from urllib.error import URLError, HTTPError
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request, Cookie
from app.services.activity_reconstruction import ActivityReconstructionService, timestamp
from app.services.activity_insights import build_insights
from app.services.activity_demo import activity_demo
from app.services.scan_jobs import ScanJobManager, ScanCancelled, ScanFailure
from googleapiclient.errors import HttpError
from google.auth.exceptions import GoogleAuthError
from fastapi.responses import RedirectResponse
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import os
import secrets
import time
import json
import re
from datetime import datetime, timezone
from httplib2 import HttpLib2Error
from urllib.parse import urlsplit
from oauthlib.oauth2 import OAuth2Error
from requests.exceptions import RequestException

from app.gmail.oauth import get_authorization_url, fetch_credentials, setup_status, OAuthConfigurationError, revoke_credentials
from app.gmail.scanner import GmailScanner
from app.services.account_discovery import AccountDiscoveryService
from app.security.breach_checker import BreachChecker
from typing import Literal
from pydantic import BaseModel, Field
from app.models import PublicAccountReconstruction
from app.services.public_activity import PublicActivityService, IntelBaseActivityService, SourceError
from app.services.gravatar import GravatarService
from app.services.location_analysis import LocationAnalysisRequest, summarize_places

@asynccontextmanager
async def app_lifespan(application):
    try:
        yield
    finally:
        scan_jobs.shutdown()


app = FastAPI(lifespan=app_lifespan)
STATIC_DIR = Path(__file__).parent / 'static'
app.mount('/static', StaticFiles(directory=STATIC_DIR), name='static')

oauth_state = None
oauth_started_at = 0
gmail_credentials = None
oauth_return_to_dashboard = False
gmail_connection_generation = 0
scan_jobs = ScanJobManager()


class PublicActivityRequest(BaseModel):
    provider: Literal['github', 'chess.com']
    username: str = Field(min_length=1, max_length=50)


class EmailEnrichmentRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r'^[^\s@]+@[^\s@]+\.[^\s@]+$')


@app.post('/accounts/gravatar')
def gravatar_profile(body: EmailEnrichmentRequest):
    try:
        return GravatarService().lookup_email(body.email)
    except SourceError as error:
        return JSONResponse(status_code=error.status, content={'detail': error.detail, 'source_outcome': error.outcome})


@app.post('/accounts/location-estimate')
def location_estimate(body: LocationAnalysisRequest):
    return summarize_places(body.observations)


@app.post('/accounts/public-activity', response_model=PublicAccountReconstruction)
def public_activity(body: PublicActivityRequest):
    try:
        return PublicActivityService().lookup(body.provider, body.username)
    except SourceError as error:
        return JSONResponse(status_code=error.status, content={'detail': error.detail, 'source_outcome': error.outcome})


@app.post('/accounts/enrich-email')
def enrich_email(body: EmailEnrichmentRequest):
    try:
        return IntelBaseActivityService().lookup_email(body.email)
    except SourceError as error:
        return JSONResponse(status_code=error.status, content={'detail': error.detail, 'source_outcome': error.outcome})


@app.get('/accounts/activity-demo')
def demo_activity():
    return activity_demo()


@app.post('/gmail/disconnect')
def disconnect_gmail(request: Request, revoke: bool = False):
    """Clear the local connection only; does not revoke Google's permission."""
    global gmail_credentials, oauth_state, oauth_started_at, oauth_return_to_dashboard
    origin = request.headers.get('origin')
    if origin and urlsplit(origin).netloc != request.url.netloc:
        raise HTTPException(403, 'Disconnect must be requested from this local dashboard.')
    if revoke and gmail_credentials is not None:
        try:
            revoke_credentials(gmail_credentials)
        except (URLError, OSError):
            raise HTTPException(502, 'Google permission could not be revoked. Retry, or disconnect locally.') from None
    gmail_credentials = None
    scan_jobs.clear()
    oauth_state, oauth_started_at, oauth_return_to_dashboard = None, 0, False
    response = JSONResponse({'gmail_connected': False, 'message': 'Google permission revoked and local connection cleared.' if revoke else 'Local Gmail connection cleared. Google account permission is unchanged.'})
    response.delete_cookie('cybertwin_oauth_state', path='/gmail')
    return response


def require_local_request(request):
    origin = request.headers.get('origin')
    if origin and urlsplit(origin).netloc != request.url.netloc:
        raise HTTPException(403, 'Use the local Cyber Twin dashboard for this action.')


def scan_owner():
    if gmail_credentials is None:
        raise HTTPException(401, 'Connect Gmail at /gmail/login first.')
    return gmail_connection_generation, id(gmail_credentials)


@app.post('/accounts/activity/scans', status_code=202)
def start_activity_scan(request: Request, max_messages: int = Query(default=500, ge=0, le=10000)):
    require_local_request(request)
    owner = scan_owner()
    credentials = gmail_credentials
    def task(report):
        emails = []
        def progress(values):
            if gmail_credentials is not credentials:
                raise ScanCancelled()
            report(values)
        try:
            emails, coverage = GmailScanner(credentials).scan_activity_emails(max_messages, progress_callback=progress)
            progress({**coverage, 'message_fetches': coverage.get('message_fetches', coverage['messages_scanned']), 'message_limit': max_messages})
            return activity_payload(emails, coverage)
        except ScanCancelled:
            raise
        except (HttpError, GoogleAuthError, HttpLib2Error, OSError, ValueError) as error:
            if gmail_credentials is not credentials:
                raise ScanCancelled() from None
            mapped = gmail_scan_error(error)
            raise ScanFailure(mapped.status_code, mapped.detail) from None
        finally:
            emails.clear()
    try:
        key = scan_jobs.start(owner, task, max_messages)
    except RuntimeError as error:
        raise HTTPException(409, str(error)) from None
    return {'scan_id': key, 'status': 'queued', 'result_retention_seconds': scan_jobs.ttl, 'connection_generation': gmail_connection_generation}


@app.get('/accounts/activity/scans/{scan_id}')
def activity_scan_status(scan_id: str):
    snapshot = scan_jobs.snapshot(scan_id, scan_owner())
    if snapshot is None:
        raise HTTPException(404, 'This scan is unavailable, expired, or belongs to an earlier Gmail connection.')
    return snapshot


@app.delete('/accounts/activity/scans/{scan_id}', status_code=202)
def cancel_activity_scan(scan_id: str, request: Request):
    require_local_request(request)
    if not scan_jobs.cancel(scan_id, scan_owner()):
        raise HTTPException(404, 'This scan is unavailable or expired.')
    return {'scan_id': scan_id, 'status': 'cancelling', 'message': 'Cancellation requested. The current network request may finish first. Partial results will not be kept.'}


@app.get('/accounts/activity')
def reconstruct_activity(max_messages: int = Query(default=5000, ge=1, le=10000)):
    """Local single-user endpoint; reuses existing read-only Gmail credentials."""
    if gmail_credentials is None:
        raise HTTPException(status_code=401, detail='Connect Gmail at /gmail/login first.')
    try:
        emails, coverage = GmailScanner(gmail_credentials).scan_activity_emails(max_messages)
    except (HttpError, GoogleAuthError, HttpLib2Error, OSError, ValueError) as error:
        raise gmail_scan_error(error) from None
    return activity_payload(emails, coverage)


def activity_payload(emails, coverage):
    try:
        scan_time = datetime.now(timezone.utc)
        services = ActivityReconstructionService().reconstruct(emails, scan_time)
        dates = [value for email in emails if (value := timestamp(email)) is not None and value <= scan_time]
        coverage = {**coverage,
                    'scanned_at': scan_time.isoformat(),
                    'oldest_scanned_evidence': min(dates).isoformat() if dates else None,
                    'newest_scanned_evidence': max(dates).isoformat() if dates else None,
                    'classified_messages': sum(len(service.timeline) for service in services),
                    'note': 'Scan bounds describe inspected messages, not account lifetime. Sent mail and drafts are excluded; Spam and Trash are included.'}
    finally:
        emails.clear()  # No subjects, bodies, or sender addresses retained.
    return {
        'services_found': len(services), 'services': services, 'coverage': coverage,
        'insights': build_insights(services, scan_time), 'is_demo': False,
        'limitations': 'Subject-based mailbox evidence; timestamps use Gmail receipt times or a labelled sender Date-header fallback. Not complete login history. Sender domains are unverified. Scores are heuristic evidence strength.',
    }


def gmail_scan_error(error):
    global gmail_credentials
    status = getattr(getattr(error, 'resp', None), 'status', None)
    if isinstance(error, GoogleAuthError) or status == 401:
        gmail_credentials = None
        scan_jobs.clear()
        return HTTPException(401, 'Your Google connection expired or was revoked. Click Connect Gmail again. Testing-mode permissions may expire after seven days.')
    reasons = set()
    if isinstance(error, HttpError):
        try:
            payload = json.loads(error.content)
            reasons = {item.get('reason') for item in payload.get('error', {}).get('errors', []) if isinstance(item, dict)}
        except (ValueError, TypeError, AttributeError):
            pass
    if status == 403 and reasons.intersection({'rateLimitExceeded', 'userRateLimitExceeded', 'dailyLimitExceeded', 'quotaExceeded'}):
        return HTTPException(429, 'Google Gmail quota or request limit was reached. Wait before retrying; reconnecting will not reset quota.', headers={'Retry-After': '60'})
    if status == 403 and 'domainPolicy' in reasons:
        return HTTPException(403, 'Your Google Workspace administrator has disabled Gmail access for this app. Ask the administrator to allow access.')
    if status == 403:
        return HTTPException(403, 'Google refused the Gmail scan. Check that Gmail API is enabled in the same Cloud project and that your account granted read-only Gmail access. Then reconnect.')
    if status == 429:
        return HTTPException(429, 'Google is limiting requests. Wait briefly, then try a smaller scan.', headers={'Retry-After': '60'})
    return HTTPException(502, 'Gmail scan failed. Check your connection and try again. If it persists, reconnect Gmail.')


@app.get('/accounts/activity/{domain}')
def service_activity(domain: str, max_messages: int = Query(default=5000, ge=1, le=10000)):
    """Reconstruct one exact sender domain using the same bounded mailbox scan."""
    result = reconstruct_activity(max_messages)
    for service in result['services']:
        if service.domain == domain.strip().lower():
            return {'service': service, 'coverage': result['coverage'], 'limitations': result['limitations']}
    raise HTTPException(status_code=404, detail='No classified evidence for this domain within the scanned messages.')


@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / 'index.html')


@app.get('/api/status')
def connection_status():
    return {'gmail_connected': gmail_credentials is not None,
            'intelbase_configured': bool(os.getenv('INTELBASE_API_KEY'))}


@app.get('/gmail/setup')
def gmail_setup():
    return setup_status()


@app.get('/health')
def read_root():
    return {
        "project": "Cyber Twin",
        "module": "Digital Footprint Scanner",
        "status": "running",
    }


@app.get("/gmail/login")
def gmail_login(request: Request, return_to_dashboard: bool = False, email: str = ''):
    global oauth_state, oauth_return_to_dashboard, oauth_started_at

    if email and (len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email)):
        raise HTTPException(422, 'Enter a valid Gmail address.')
    setup = setup_status()
    if not setup['configured']:
        if return_to_dashboard:
            return RedirectResponse('/?gmail_error=configuration', status_code=303)
        raise HTTPException(503, 'Google configuration is incomplete. Open /gmail/setup for the missing settings.')
    # Keep the state cookie on the same host as the configured Google callback.
    canonical = urlsplit(setup['dashboard_url'])
    if request.url.netloc != canonical.netloc:
        return RedirectResponse(setup['dashboard_url'] + 'gmail/login?return_to_dashboard=' + str(return_to_dashboard).lower(), status_code=307)

    oauth_return_to_dashboard = return_to_dashboard
    try:
        authorization_url, oauth_state = get_authorization_url(login_hint=email) if email else get_authorization_url()
    except (OAuthConfigurationError, ValueError):
        raise HTTPException(503, 'Google configuration could not be loaded. Check the Gmail setup guide.') from None
    oauth_started_at = time.monotonic()
    response = RedirectResponse(authorization_url)
    response.set_cookie('cybertwin_oauth_state', oauth_state, httponly=True, samesite='lax', max_age=600, path='/gmail')
    return response


@app.get("/gmail/callback")
def gmail_callback(code: str | None = None, state: str | None = None, error: str | None = None,
                   cybertwin_oauth_state: str | None = Cookie(default=None)):
    global gmail_credentials, oauth_state, oauth_started_at, oauth_return_to_dashboard, gmail_connection_generation
    if (not state or not oauth_state or not cybertwin_oauth_state
            or not secrets.compare_digest(state, oauth_state)
            or not secrets.compare_digest(state, cybertwin_oauth_state)
            or time.monotonic() - oauth_started_at > 600):
        raise HTTPException(400, 'This Google connection attempt is invalid or expired. Start again with Connect Gmail in the same browser.')
    dashboard = oauth_return_to_dashboard
    oauth_state, oauth_started_at, oauth_return_to_dashboard = None, 0, False
    if error or not code:
        response = (RedirectResponse('/?gmail_error=access_denied', status_code=303) if dashboard else
                    JSONResponse(status_code=403, content={'detail': 'Google did not grant access. If the app is in Testing, add this Gmail account under Google Auth Platform → Audience → Test users, then reconnect.'}))
    else:
        try:
            new_credentials = fetch_credentials(code, state)
            scan_jobs.clear()
            gmail_connection_generation += 1
            gmail_credentials = new_credentials
        except (OAuth2Error, GoogleAuthError, RequestException, OSError, ValueError):
            response = (RedirectResponse('/?gmail_error=token_exchange', status_code=303) if dashboard else
                        JSONResponse(status_code=502, content={'detail': 'Google connection could not be completed. Check the callback URL and reconnect.'}))
        else:
            response = (RedirectResponse('/?gmail=connected', status_code=303) if dashboard else
                        JSONResponse({'message': 'Gmail connected successfully'}))
    response.delete_cookie('cybertwin_oauth_state', path='/gmail')
    return response


@app.get("/accounts/discover")
def discover_accounts():
    if gmail_credentials is None:
        return {
            "error": "Gmail is not connected. Visit /gmail/login first."
        }

    try:
        scanner = GmailScanner(gmail_credentials)
        emails = scanner.scan_registration_emails()
    except (HttpError, GoogleAuthError, HttpLib2Error, OSError, ValueError) as error:
        raise gmail_scan_error(error) from None

    discovery = AccountDiscoveryService()
    accounts = discovery.discover_accounts(emails)

    try:
        checks = BreachChecker().check_breaches(
            [account["domain"] for account in accounts]
        )
    except (URLError, OSError, ValueError, KeyError, TypeError):
        for account in accounts:
            account["breach_check"] = {
                "status": "unavailable",
                "known_breach": None,
                "breaches": None,
                "note": "Breach history could not be checked. Try again later.",
            }
    else:
        for account, check in zip(accounts, checks):
            account["breach_check"] = {"status": "checked", **check}

    return {
        "accounts_found": len(accounts),
        "accounts": accounts
    }


@app.get('/app', include_in_schema=False)
def original_dashboard_url():
    return RedirectResponse('/', status_code=307)


@app.post('/accounts/email-breaches')
def connected_email_breaches(request: Request):
    """Explicit opt-in: only query the address returned by the connected Gmail API."""
    require_local_request(request)
    scan_owner()
    key = os.getenv('HIBP_API_KEY', '').strip()
    if not key:
        return {'status': 'unavailable', 'note': 'Set HIBP_API_KEY in .env to enable this optional check.'}
    try:
        email = GmailScanner(gmail_credentials).get_email_address()
    except (HttpError, GoogleAuthError, HttpLib2Error, OSError, ValueError) as error:
        raise gmail_scan_error(error) from None
    try:
        result = BreachChecker().check_email(email, key)
    except (URLError, OSError, ValueError, KeyError, TypeError):
        raise HTTPException(502, 'HIBP lookup was unavailable. Check your API key and try later.') from None
    return {'status': 'checked', **result,
            'note': 'Only breaches returned by HIBP; no match does not establish that your account is safe.'}


@app.get('/gmail/identity')
def gmail_identity():
    scan_owner()
    credentials, generation = gmail_credentials, gmail_connection_generation
    try:
        email = GmailScanner(credentials).get_email_address()
    except (HttpError, GoogleAuthError, HttpLib2Error, OSError, ValueError) as error:
        raise gmail_scan_error(error) from None
    if credentials is not gmail_credentials or generation != gmail_connection_generation:
        raise HTTPException(409, 'Gmail connection changed. Start the scan again.')
    if not isinstance(email, str) or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        raise HTTPException(502, 'Gmail did not return a valid mailbox identity.')
    return {'email': email, 'connection_generation': generation}
