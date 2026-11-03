import os
import re
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


def setup_status():
    required = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI']
    missing = [name for name in required if not os.getenv(name, '').strip()]
    redirect = os.getenv('GOOGLE_REDIRECT_URI', '').strip()
    valid_redirect = False
    dashboard_url = None
    try:
        parsed = urlsplit(redirect)
        valid_redirect = (parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1'}
                          and parsed.path == '/gmail/callback' and not parsed.query and not parsed.fragment
                          and not parsed.username and not parsed.password and parsed.port is not None)
        if valid_redirect:
            dashboard_url = f'{parsed.scheme}://{parsed.netloc}/'
    except ValueError:
        pass
    project = re.match(r'^(\d+)-', os.getenv('GOOGLE_CLIENT_ID', ''))
    return {'configured': not missing and valid_redirect, 'missing': missing,
            'callback_url': redirect if valid_redirect else None, 'dashboard_url': dashboard_url,
            'redirect_valid': valid_redirect, 'test_user_access': 'not_checked',
            'audience_url': 'https://console.cloud.google.com/auth/audience' +
                            (f'?project={project.group(1)}' if project else ''),
            'note': 'Local credentials do not verify Google Cloud settings. In Testing mode, add your Gmail address under Audience → Test users. Enable the Gmail API and register the exact callback URL on the OAuth client.'}


def create_flow(state=None):
    if not setup_status()['configured']:
        raise OAuthConfigurationError('Google setup is incomplete. Check the Gmail setup guide on the dashboard.')
    client_config = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [
                os.getenv("GOOGLE_REDIRECT_URI")
            ],
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        state=state,
        redirect_uri=os.getenv("GOOGLE_REDIRECT_URI"),
        autogenerate_code_verifier=False,
    )

    return flow


def get_authorization_url(login_hint=None):
    flow = create_flow()

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        **({"login_hint": login_hint} if login_hint else {}),
    )

    return authorization_url, state


def fetch_credentials(code, state):
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
