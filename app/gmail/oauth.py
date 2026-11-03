import os
import re
import time
import secrets
from pathlib import Path
from urllib.parse import urlsplit, urlencode
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow

load_dotenv(Path(__file__).resolve().parents[2] / '.env')

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]


class OAuthConfigurationError(ValueError):
    pass


pending_desktop_flow = None


def clear_pending_flow():
    global pending_desktop_flow
    pending_desktop_flow = None


def cookie_path():
    return '/' if os.getenv('GOOGLE_CLIENT_TYPE', 'web') == 'desktop' else '/gmail'


def setup_status():
    desktop = os.getenv('GOOGLE_CLIENT_TYPE', 'web') == 'desktop'
    required = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'] + ([] if desktop else ['GOOGLE_REDIRECT_URI'])
    missing = [name for name in required if not os.getenv(name, '').strip()]
    redirect = os.getenv('GOOGLE_REDIRECT_URI', '').strip()
    if desktop:
        redirect = os.getenv('CYBERTWIN_APP_URL', 'http://localhost:8765/').rstrip('/') + '/'
    valid_redirect = False
    dashboard_url = None
    try:
        parsed = urlsplit(redirect)
        valid_redirect = (parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1'}
                          and parsed.path == ('/' if desktop else '/gmail/callback') and not parsed.query and not parsed.fragment
                          and not parsed.username and not parsed.password and parsed.port is not None)
        if valid_redirect:
            dashboard_url = f'{parsed.scheme}://{parsed.netloc}/'
    except ValueError:
        pass
    project = re.match(r'^(\d+)-', os.getenv('GOOGLE_CLIENT_ID', ''))
    runtime = os.getenv('CYBERTWIN_APP_URL')
    port_mismatch = bool(not desktop and runtime and valid_redirect and urlsplit(runtime).port != parsed.port)
    return {'configured': not missing and valid_redirect and not port_mismatch, 'missing': missing,
            'client_type': 'desktop' if desktop else 'web', 'port_mismatch': port_mismatch,
            'callback_url': redirect if valid_redirect else None, 'dashboard_url': dashboard_url,
            'redirect_valid': valid_redirect, 'test_user_access': 'not_checked',
            'audience_url': 'https://console.cloud.google.com/auth/audience' +
                            (f'?project={project.group(1)}' if project else ''),
            'note': 'Local credentials do not verify Google Cloud settings. In Testing mode, add your Gmail address under Audience → Test users. Enable the Gmail API and register the exact callback URL on the OAuth client.'}


def create_flow(state=None):
    if not setup_status()['configured']:
        raise OAuthConfigurationError('Google setup is incomplete. Check the Gmail setup guide on the dashboard.')
    desktop = os.getenv('GOOGLE_CLIENT_TYPE', 'web') == 'desktop'
    redirect = setup_status()['callback_url']
    client_config = {
        ('installed' if desktop else 'web'): {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [
                redirect
            ],
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        state=state,
        redirect_uri=redirect,
        autogenerate_code_verifier=desktop,
    )

    return flow


def get_authorization_url(login_hint=None):
    global pending_desktop_flow
    clear_pending_flow()
    flow = create_flow()

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        **({"login_hint": login_hint} if login_hint else {}),
    )

    if os.getenv('GOOGLE_CLIENT_TYPE', 'web') == 'desktop':
        pending_desktop_flow = (state, time.monotonic(), flow)
    return authorization_url, state


def fetch_credentials(code, state):
    global pending_desktop_flow
    if os.getenv('GOOGLE_CLIENT_TYPE', 'web') == 'desktop':
        pending = pending_desktop_flow
        clear_pending_flow()
        if not pending or not secrets.compare_digest(state, pending[0]) or time.monotonic() - pending[1] > 600:
            raise OAuthConfigurationError('Google connection expired. Click Connect Gmail again.')
        flow = pending[2]  # Reuse this attempt's PKCE verifier for the code exchange.
    else:
        flow = create_flow(state)

    flow.fetch_token(code=code)

    return flow.credentials


def revoke_credentials(credentials):
    token = credentials.refresh_token or credentials.token
    request = Request('https://oauth2.googleapis.com/revoke',
                      data=urlencode({'token': token}).encode(),
                      headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urlopen(request, timeout=10):
        pass
