# Cyber Twin: local user guide

## Start and open

From `D:\cyber-twin`, install requirements once and start the server:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://localhost:8000/**. This matches the current configured callback
`http://localhost:8000/gmail/callback`. After code changes, stop the old server
with Ctrl+C and restart it, then refresh the page. Keep the terminal open.

## Fix Google's Access blocked / 403 access_denied screen

The screenshot reports that the Google app is in Testing and this account is
not an approved tester. Local source-code changes cannot add Google test users.

1. Sign in to Google Cloud Console as the owner/editor of the project that owns
   the OAuth client used in the root `.env`.
2. Open **Google Auth Platform → Audience → Test users → Add users**.
3. Add the exact Gmail address you are trying to connect and save.
4. Ensure **Gmail API** is enabled under APIs & Services in that same project.
5. Under **Google Auth Platform → Clients**, open the web client and register
   the exact `GOOGLE_REDIRECT_URI` value as an authorized redirect URI.
6. Return to Cyber Twin and click **Connect Gmail** again in your normal browser.

The dashboard's **Help & setup** page links to the correct project using the
project number in your configured client ID. It shows the callback URL and any
missing local settings, without displaying your client secret. It cannot check
Google's test-user list. Keep Testing mode for local use; no paid lookup service
is needed. Test-user authorization and refresh tokens can expire after seven days.

Required `.env` settings: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
`GOOGLE_REDIRECT_URI`. Only `gmail.readonly` is requested. The callback must be
an HTTP localhost/127.0.0.1 URL with an explicit port and `/gmail/callback` path.
Login automatically moves to the callback's host before setting the state cookie.

Reference: https://support.google.com/cloud/answer/15549945?hl=en

## What to use

**My accounts** is the home page. Connect Gmail, then click **Find accounts &
activity**. Start with 500 messages and increase the limit (maximum 10,000) to
include older mail. Results are based on services present in your mailbox, not
on a fixed list of platforms. Filter results by service domain. Expand a service
for its dated evidence. **Registration scan** preserves the earlier registration
search and adds public service-level breach history; it does not establish that
your personal account was breached.

**GitHub profile** is a secondary, explicitly GitHub-only lookup. It retrieves
public profile creation, profile edits, and up to 300 recent public events.
It does not discover accounts on other platforms. The octocat example exercises
the actual public API.

Chess.com, IntelBase, Gravatar and manual place analysis are removed from the
user dashboard. No paid API key is needed for the main workflow. Their existing
API endpoints remain for compatibility; they are not invoked by the dashboard.
Gravatar is a public profile/avatar directory, not a universal email-account
search. IntelBase remains optional and requires a paid provider account if
explicitly invoked through its legacy endpoint.

## Understand results and privacy

- First/last seen: earliest/latest evidence among scanned messages, not exact
  account creation or login times. Gmail internal timestamps are receipt times. If absent, the sender-supplied Date
  header is used and labelled `email_date_header` in each evidence record.
- Login: subject wording indicating a successful login; not independent session
  verification. OTPs, failed attempts, pending authentication, explicitly unsuccessful
  notifications and security alerts are not successful logins.
- Activity status: qualifying login/activity/creation evidence in the last 90 days
  gives recent evidence. Older evidence is possibly dormant, not confirmed inactive.
- Confidence: strongest matching rule, not a calibrated accuracy percentage. Each
  service explains the score and the event types contributing its maximum;
  repeated messages do not inflate it.
- Coverage: includes Spam and Trash; a bounded scan can miss older messages.
  Message fetches and list-page requests are both bounded by the requested limit.
  `pages_scanned` reports list requests; `scan_complete` is false if a limit cuts
  scanning short. Completion is not a guarantee of a stable mailbox snapshot.
  Exact sender domains are not authenticated service identities and subdomains
  are not merged. Subject rules are mainly English and can miss unfamiliar wording.
- The activity scan fetches only From, Subject, Date and receipt timestamps. Bodies
  and snippets are not fetched. Subjects are discarded after reconstruction.
  Legacy registration discovery still returns its existing evidence subject for
  compatibility. Results and credentials are kept in memory, not a database.
- Restart clears Gmail connection. This remains a local single-user prototype.
  The connection flow validates state, a browser cookie, and a ten-minute deadline;
  consumed attempts cannot be replayed. OAuth errors are sanitized. Connection
  expiry clears the status and asks the user to reconnect.
- No complete cross-platform login history, automatic Maps collection, live GPS,
  or ownership verification is provided. Gmail access and Google Cloud settings
  still require authorization by the account/project owner.

## Endpoint checks

Interactive API docs: http://localhost:8000/docs

- `GET /gmail/setup`: local configuration diagnostics; Google test-user access is
  explicitly not checked.
- `GET /gmail/login`: start Google connection. Use `?return_to_dashboard=true`
  for a dashboard redirect after completion.
- `GET /accounts/activity?max_messages=500`: classify mailbox evidence.
- `GET /accounts/activity/{domain}?max_messages=500`: one exact sender domain.
- `GET /accounts/discover`: original registration/discovery flow.
- `POST /accounts/public-activity` with
  `{"provider":"github","username":"octocat"}`: public GitHub evidence.

Activity returns 401 when disconnected/expired, 403 when Gmail access is denied,
429 for rate limiting, 502 for other scan failures, and 422 for invalid limits.
The OAuth callback rejects invalid/missing browser state or expired/replayed
attempts with 400. Denials and token failures return to Help & setup when the
connection was initiated from the dashboard.

## Validation

```powershell
python -m unittest discover -v
```

61 offline tests cover metadata pagination, classification, privacy, API routes,
legacy discovery, source adapters, Google setup diagnostics, canonical-host login,
state cookie validation, replay/expiry rejection, denied callbacks, failed token
exchange, and reconnect behavior. Gmail scan tests use fixtures. A live mailbox
scan cannot be verified until the Google Cloud test-user restriction is resolved
and the account owner completes consent.


## Reliability and evidence improvements

Activity scanning retries transient API failures at most twice per request using
the Google client's randomized exponential backoff. A message deleted between
listing and fetching is counted as unavailable; other failures remain errors.
The configured message limit bounds unique metadata fetch attempts, including
unavailable and excluded messages. Retry attempts can add up to two HTTP calls
per logical list/get operation. Sent mail and drafts are inspected for labels
but excluded from reconstruction; Spam and Trash remain included.

Coverage now reports fetch attempts, unavailable/excluded messages, classified
messages, scan time, inspected date bounds, and the stop reason. Date bounds are
among received metadata with usable non-future timestamps, including
unclassified mail; they do not prove continuous historical coverage. When a
message becomes unavailable, scan_complete remains false even at mailbox end.

Each evidence record explains its classification without storing the subject.
Generic welcome wording remains weak discovery evidence and cannot alone imply
recent account use. Each service explains its activity state and score.
Dashboard timelines show latest evidence first; result filters include activity
state and security/password evidence. Google quota-related 403 responses become
429 with a retry hint; Workspace policy denials identify the admin restriction.

Research references:
- https://developers.google.com/workspace/gmail/api/guides/handle-errors
- https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages
- https://developers.google.com/workspace/gmail/api/guides/batch

Future candidates: metadata batches of at most 50 requests to reduce network
round trips and incremental Gmail history synchronization. These still need live
mailbox validation. Background progress/cancellation is now implemented below.

Dashboard interaction checks (no live Gmail required): `node test_activity_dashboard.cjs`.


## Personal workspace and background scans

The dashboard now uses a compact white/slate/blue layout with an overview,
interactive monthly evidence chart, review queue, and combined timeline. Review
prompts cover alerts, password events, billing clues, forgotten-account candidates
and weak identity evidence. No money amounts, subscription status, account
compromise, or inactivity are invented. Codes/OTPs alone do not enter the security
alert count. Marking a prompt reviewed is reversible and page-session only.

Explore demo uses six fictional .example services and clock-relative sample
events. It requires no Gmail connection. The demo remains prominently labelled
in all workspace views. It is served by GET /accounts/activity-demo.

The main scan button uses POST /accounts/activity/scans?max_messages=500,
polls GET /accounts/activity/scans/{scan_id}, and supports DELETE of that scan
to cancel. Counts reflect actual metadata requests and received messages; the
progress meter measures the selected limit, not a guaranteed mailbox size.
Cancellation takes effect between requests. Network requests have a 30-second
transport timeout and up to two retry attempts, so a request already underway
may take longer before cancellation is observed. Navigating away attempts to
cancel an active job; delivery of that final browser request is not guaranteed.

Only one background worker runs at a time, with at most three job records.
Completed normalized results expire after ten minutes, with automatic cleanup
at intervals no longer than 30 seconds. Polls do not extend retention. The
dashboard clears the server result after receiving it. Cancellation discards
partial results; raw bodies and snippets are never fetched. Transient subjects
are used only for classification and are cleared after reconstruction.

Disconnect locally calls POST /gmail/disconnect, clearing credentials, jobs,
and pending OAuth state. It does not revoke the Google account's permission.
Cross-origin browser requests to scan/cancel/disconnect are rejected. Job keys
are random and are tied to the current local Gmail connection. This remains a
single-user, single-process prototype; start with one Uvicorn worker and bind to
127.0.0.1. Existing synchronous activity endpoints and registration discovery
remain available for compatibility.

Browser QA checks include the desktop/mobile layouts, event/month filters,
review-category filtering, review/undo, keyboard focus after review actions,
navigation back to account evidence, and clear-results behaviour. The offline
suite covers background progress, cancellation, duplicate-scan rejection,
ownership separation, sanitised failures, expiry, cache bounds and timeouts.
Live Gmail timing, Google consent and provider-specific notification coverage
still require account-owner testing.

Review guidance sources:
- https://support.google.com/accounts/answer/140921
- https://support.google.com/accounts/answer/185839
- https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html
