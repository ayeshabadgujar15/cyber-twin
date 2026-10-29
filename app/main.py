import os
import re
import secrets
import threading
from pathlib import Path
from urllib.error import HTTPError, URLError

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from googleapiclient.errors import HttpError

from app.gmail.oauth import (
    fetch_credentials,
    get_authorization_url,
    revoke_credentials,
)
from app.gmail.scanner import GmailScanner
from app.services.account_discovery import AccountDiscoveryService
from app.security.breach_checker import BreachChecker

STATIC_DIR = Path(__file__).parent / "static"
SESSION_COOKIE = "cyber_twin_session"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# One entry per browser, kept in memory: a restart signs everyone out.
sessions = {}


@app.get("/")
def read_root():
    return {
        "project": "Cyber Twin",
        "module": "Digital Footprint Scanner",
        "status": "running",
    }


@app.get("/app")
def ui():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/gmail/login")
def gmail_login(request: Request, email: str = ""):
    email = email.strip()
    if email and not EMAIL_PATTERN.match(email):
        return RedirectResponse("/app?error=invalid_email", status_code=303)

    session_id, session = _get_or_create_session(request)
    authorization_url, session["oauth_state"] = get_authorization_url(
        login_hint=email or None
    )
    session["requested_email"] = email

    response = RedirectResponse(authorization_url, status_code=303)
    response.set_cookie(
        SESSION_COOKIE, session_id, httponly=True, samesite="lax"
    )
    return response


@app.get("/gmail/callback")
def gmail_callback(
    request: Request, code: str = "", state: str = "", error: str = ""
):
    session = _get_session(request)

    if session is None:
        return RedirectResponse("/app?error=session_expired", status_code=303)
    if error or not code:
        return RedirectResponse("/app?error=access_denied", status_code=303)

    expected_state = session.pop("oauth_state", None)
    if not expected_state or not secrets.compare_digest(state, expected_state):
        return RedirectResponse("/app?error=state_mismatch", status_code=303)

    try:
        session["credentials"] = fetch_credentials(code, state)
    except Exception:
        return RedirectResponse("/app?error=oauth_failed", status_code=303)

    _start_scan(session)
    return RedirectResponse("/app", status_code=303)


@app.get("/accounts/discover")
def discover_accounts(request: Request):
    session = _get_session(request)

    if session is None or "credentials" not in session:
        return {
            "error": "Gmail is not connected. Visit /gmail/login first."
        }

    scanner = GmailScanner(session["credentials"])
    emails = scanner.scan_registration_emails()

    discovery = AccountDiscoveryService()
    accounts = discovery.discover_accounts(emails)
    _attach_domain_breaches(accounts)

    return {
        "accounts_found": len(accounts),
        "accounts": accounts
    }


@app.get("/api/session")
def session_status(request: Request):
    session = _get_session(request)

    if session is None or "credentials" not in session:
        return {"connected": False}

    with session["lock"]:
        return {
            "connected": True,
            "requested_email": session.get("requested_email"),
            "scan": dict(session["scan"]),
        }


@app.post("/api/scan")
def rescan(request: Request):
    session = _get_session(request)

    if session is None or "credentials" not in session:
        return JSONResponse(
            {"error": "Gmail is not connected."}, status_code=401
        )
    if session["scan"]["status"] == "running":
        return JSONResponse(
            {"error": "A scan is already running."}, status_code=409
        )

    _start_scan(session)
    return {"started": True}


@app.post("/api/disconnect")
def disconnect(request: Request):
    session = sessions.pop(request.cookies.get(SESSION_COOKIE), None)

    if session and "credentials" in session:
        try:
            revoke_credentials(session["credentials"])
        except (URLError, OSError):
            pass  # The session is gone either way; Google expires the token.

    response = JSONResponse({"disconnected": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


def _get_session(request):
    return sessions.get(request.cookies.get(SESSION_COOKIE))


def _get_or_create_session(request):
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id not in sessions:
        session_id = secrets.token_urlsafe(32)
        sessions[session_id] = {"lock": threading.Lock()}
    return session_id, sessions[session_id]


def _start_scan(session):
    with session["lock"]:
        session["scan"] = {
            "status": "running",
            "phase": "starting",
            "done": 0,
            "total": None,
        }
    threading.Thread(target=_run_scan, args=(session,), daemon=True).start()


def _run_scan(session):
    def update(**fields):
        with session["lock"]:
            session["scan"].update(fields)

    try:
        scanner = GmailScanner(session["credentials"])
        email = scanner.get_email_address()
        update(email=email)

        emails = scanner.scan_inbox(
            on_progress=lambda phase, done, total: update(
                phase=phase, done=done, total=total
            )
        )

        update(phase="discovering")
        accounts = AccountDiscoveryService().discover_accounts(emails)

        update(phase="checking_breaches")
        _attach_domain_breaches(accounts)
        email_breaches = _check_email_breaches(email)

        update(
            status="done",
            phase="done",
            messages_scanned=len(emails),
            accounts=accounts,
            email_breaches=email_breaches,
        )
    except HttpError as error:
        update(
            status="error",
            error=f"Gmail returned an error ({error.resp.status}). "
            "Try scanning again.",
        )
    except Exception:
        update(
            status="error",
            error="The scan failed unexpectedly. Try scanning again.",
        )


def _attach_domain_breaches(accounts):
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


def _check_email_breaches(email):
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "unavailable",
            "note": "Email lookup needs an HIBP API key. "
            "Set HIBP_API_KEY in .env to enable it.",
        }

    try:
        result = BreachChecker().check_email(email, api_key)
    except HTTPError as error:
        if error.code in (401, 403):
            note = "Have I Been Pwned rejected the API key."
        else:
            note = "Have I Been Pwned is unavailable. Try again later."
        return {"status": "unavailable", "note": note}
    except (URLError, OSError, ValueError, KeyError, TypeError):
        return {
            "status": "unavailable",
            "note": "Have I Been Pwned is unavailable. Try again later.",
        }

    return {"status": "checked", **result}
