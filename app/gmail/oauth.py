import os
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow

load_dotenv()

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]


def create_flow(state=None):
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
        login_hint=login_hint,
    )

    return authorization_url, state


def fetch_credentials(code, state):
    flow = create_flow(state)

    flow.fetch_token(code=code)

    return flow.credentials


def revoke_credentials(credentials):
    token = credentials.refresh_token or credentials.token
    request = Request(
        "https://oauth2.googleapis.com/revoke",
        data=urlencode({"token": token}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urlopen(request, timeout=10):
        pass
