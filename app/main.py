from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.gmail.oauth import get_authorization_url, fetch_credentials
from app.gmail.scanner import GmailScanner
from app.services.account_discovery import AccountDiscoveryService

app = FastAPI()

oauth_state = None
gmail_credentials = None


@app.get("/")
def read_root():
    return {
        "project": "Cyber Twin",
        "module": "Digital Footprint Scanner",
        "status": "running",
    }


@app.get("/gmail/login")
def gmail_login():
    global oauth_state

    authorization_url, oauth_state = get_authorization_url()
    return RedirectResponse(authorization_url)


@app.get("/gmail/callback")
def gmail_callback(code: str, state: str):
    global gmail_credentials

    gmail_credentials = fetch_credentials(code, state)

    return {
        "message": "Gmail connected successfully"
    }


@app.get("/accounts/discover")
def discover_accounts():
    if gmail_credentials is None:
        return {
            "error": "Gmail is not connected. Visit /gmail/login first."
        }

    scanner = GmailScanner(gmail_credentials)
    emails = scanner.scan_registration_emails()

    discovery = AccountDiscoveryService()
    accounts = discovery.discover_accounts(emails)

    return {
        "accounts_found": len(accounts),
        "accounts": accounts
    }