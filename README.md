# Cyber Twin

A local personal digital-footprint assistant: discover account clues in Gmail,
review activity and security evidence, and inspect public profiles.

## Start

Requires Python 3.10+ and Node.js only for the JavaScript checks.

```powershell
python -m pip install -r requirements.txt
python run.py
```

Or double-click **Start Cyber Twin.cmd** after installing dependencies once.
The launcher opens the app on an available local port. Use **Help & setup** to
import a Google Desktop app client once. Existing `.env` web clients remain supported.
The older `/app` URL redirects to the unified dashboard.

## Functional modules

1. **Account discovery:** Gmail metadata and legacy registration search; public
   GitHub lookup. Optional Chess.com, IntelBase and Gravatar API adapters remain.
2. **Activity analysis:** dated evidence, recent/possibly dormant indicators,
   per-account and combined timelines, monthly evidence data.
3. **Security review:** security/password/billing review prompts, public service
   breach history, optional connected-email HIBP lookup.
4. **Personal workspace:** simple account list, filters, review marks, fictional
   demo, cancellable scans and connection controls. Review marks are page-only.

## Scan modes

Quick scans inspect at most 500 messages by default (custom limits up to 10,000).
Choose **Whole mailbox**, or set the limit to **0**, for paginated metadata
scanning without that limit. Full scans use batches of up to 50 with bounded
retries and pacing, and may take considerable time and memory on large mailboxes.
Both modes include Spam/Trash and exclude messages labelled Sent/Draft. Bodies
and attachments are never fetched. Missing/deleted messages are reported as
coverage gaps. A live changing mailbox is not an atomic snapshot.

The background endpoint is `POST /accounts/activity/scans?max_messages=0`.
The older synchronous activity endpoints keep their bounded 1–10,000 limits.
Legacy registration discovery still uses the first 100 matches per query.

## Privacy and limitations

This is a **single-user, single-process local app**; keep the loopback binding
and use one server worker. The unified version retains the local OAuth state,
browser-state-cookie and expiry checks rather than the other version's unbounded
browser-session dictionary. It does not provide multi-user hosting.

Credentials and on-demand scan results are memory-only. Opt-in Module 4 monitoring saves a normalized service inventory and alert history locally. Background results
expire ten minutes after completion; the dashboard clears them after fetching.
Full scans temporarily hold metadata in memory until normalization. Legacy
registration discovery returns subject evidence for compatibility.

The HIBP email lookup is an explicit button action, uses only the connected
Gmail address, sends it to HIBP, and needs `HIBP_API_KEY`. Service breach history
does not establish individual exposure; a missing breach match does not prove
safety. Other public lookups send the identifier to their named provider.

Disconnect clears local credentials; the separate **Revoke Google permission**
action also requests Google token revocation. Subject rules are heuristic and
mainly English. Sender domains, ownership and login sessions are not verified.
No automatic account closure, credential changes or subscription cancellation.

## Checks

```powershell
python -B -m unittest discover -v
node --check app/static/app.js
node --check app/static/workspace.js
node test_activity_dashboard.cjs
```

Tests use offline fixtures; live Google consent, provider quota and paid HIBP
access need separate account-owner validation. Earlier design/research notes
are historical; this README describes the merged behavior.

## Repository hygiene

`.env`, bytecode, databases, installers, generated reports and temporary files
are excluded. Existing local-only artifacts are preserved outside version
control. GitHub history preserves the earlier implementation; the working tree
contains one integrated app. `backend/` remains legacy scaffolding.


## Old-email migration checklist

Open **Move email**, enter the address you want to retire, and open a checklist.
For Gmail, connect that old address and run a scan under **My accounts**. Return
to **Move email** and add accounts from the loaded scan. Imports are enabled
only when the scan's verified Gmail identity matches the selected old address.
Demo/public-profile results cannot be imported. You can manually add services
for any email provider, including accounts absent from scan evidence.

Mark accounts **Essential** or **Other** and **Pending** or **Updated**. Reimport
adds newly found domains without resetting decisions. Updated is a user report,
not independently verified. Cyber Twin never changes service account settings.
Use official apps/bookmarks to change sign-in/recovery details and verify access.

Migration email addresses, domains and checklist decisions are stored in browser
localStorage for this origin/device, separately from transient mailbox results.
They survive reload/restart and Gmail disconnect, but clearing browser site data
removes them. Other browsers/ports do not share them. Export a JSON backup or
delete individual checklists in the UI. Exports contain the old email and service
list; keep them private. This feature does not add a general saved inventory or
account-closure tracker. No raw emails, credentials or timelines are persisted.

Additional checks: `node test_migration.cjs` and
`node --check app/static/migration.js`.


## Simple startup and Gmail connection

Double-click **Start Cyber Twin.cmd**, or run `python run.py`. The launcher binds
a working local port before starting the server and opens the browser after
the app is ready. If Windows blocks port 8000, it tries other local ports;
there is no need to run as administrator or disable firewall protections.

For port-independent Gmail connection, the Google Cloud project owner performs
one setup: enable Gmail API, create a **Desktop app** OAuth client, download its
JSON, then import it under **Help & setup → One-time setup**. If the consent app
is in Testing, the Gmail address must be a test user. Imported settings are
written only to the ignored local `.env`; prior settings are backed up in
`.env.before-desktop`. File-supplied network endpoints are ignored.

After that, use **Connect Gmail → choose account → Allow**. Desktop mode uses
the launcher's selected loopback URL and PKCE; no redirect URI editing is needed.
The existing web-client configuration remains supported when its registered
callback port is available. If the launcher selects a different port for a web
client, the UI asks for the one-time Desktop setup instead of starting a broken
Google login. The launcher sets `CYBERTWIN_APP_URL` for this process only.

Google registration, account consent and testing/verification rules still apply;
the app cannot create clients or approve test users on the owner's behalf.
Credentials remain memory-only, so a server restart still requires reconnecting.
Since migration checklists use browser origin storage, a different selected
port has separate checklist storage; export important checklists before moving.


## Three functional modules

1. **Inbox & services:** enter an email → authorize Gmail on Google's own page
   → scan mailbox metadata → list service clues. Whole-mailbox mode is the
   default (0); bounded scans remain available. Includes Spam/Trash and excludes
   Sent/Draft. Existing evidence timelines, activity indicators, fictional demo,
   progress/cancellation and registration-only search belong here. Public GitHub
   lookup is an optional discovery tool. Live mailbox connections support Gmail;
   entering an Outlook/Yahoo address does not add those providers.
2. **Breach lookup:** check the Module 1 list against HIBP's public catalogue.
   Show incident date/year, plain-text description, exposed data classes,
   affected record count, verification status, catalogue-added/updated dates and
   source. Exact and dot-delimited parent-domain matches are labelled; sender
   authenticity, ownership and personal exposure remain unverified. Fabricated,
   spam-list and malware/stealer records are excluded from service incidents;
   unverified reports are included and labelled. Optional connected-email HIBP
   lookup is here and still requires its own provider key and explicit action.
3. **Secure accounts:** prioritized, user-performed password, MFA/passkey,
   session, recovery and phishing-review steps based on service breach history
   and mailbox signals. If lookup failed or was not done, show general guidance
   without claiming a clean result. Existing review prompts and the saved
   old-email migration checklist are optional sections in this module.

Service checks download the public catalogue once and match domains locally;
they do not send the user's email to HIBP. Dates are reported incident dates,
not guaranteed discovery dates. Missing catalogue entries do not prove safety.
Fictional demo service checks never contact a provider. Security checkmarks are
page-only self-reports, not evidence that an account has been secured.

Remaining API-only discovery/research adapters: Chess.com, Gravatar, IntelBase
(Module 1 support) and manual place analysis (research helper, outside the main
three-stage workflow). They are not invoked automatically. Startup/OAuth setup,
disconnect and developer API docs are shared support features.


## Module 4: continuous detection and personal report

The optional **Monitor & report** module is a local Gmail connector, not a
browser extension or cloud service. After Gmail connection, explicitly start it
to save a mailbox-isolated service inventory, message-ID checkpoints and alert
history in ignored `data/monitor.sqlite3`. No raw subjects, bodies, passwords or
OAuth tokens are saved. The worker runs while the local Python server is alive,
including when the browser tab is closed. Restart/revocation stops monitoring;
reconnect and resume explicitly. Credentials are still memory-only.

Default checks: new Gmail history every 2 minutes; public service breach
catalogue every 30 minutes. Inbox interval is configurable from 1–60 minutes;
breach interval from 10 minutes–24 hours through the API. New service clues
trigger a breach refresh. Alerts deduplicate per signup domain and provider
incident/version; "newly detected" can describe an older incident newly loaded
by the provider. Browser notifications are optional and requested only by an
explicit button click; they require a supported browser and an open dashboard.
In-app alert history is persistent. Acknowledgement is not security remediation.

The first activation performs a recent 500-message baseline, merging a matching
loaded Gmail scan when supplied. History polling handles pagination and stores
checkpoints only after processed messages/records. It processes up to 1,000 new
messages per pass; pending backlogs remain labelled. An expired Gmail history
checkpoint generates a coverage-gap alert and uses a bounded recent rescan;
that is not a full historical recovery. Run a full Module 1 scan and restart
with that loaded scan to refresh the service inventory. Mainly English subject
rules can miss registrations. Sender domains and ownership are unverified.

Download a **Digital Footprint & Security Report** as PDF or self-contained HTML
from a loaded scan (including the clearly labelled fictional demo) or the full
saved monitoring inventory. Reports contain all discovered services in the
selected source, first/last evidence, review reasons, detailed breach findings,
recommended actions, coverage and recent alerts. Red means review needed;
amber means unchecked/unavailable; neutral means no flagged signals, never
"safe". Failed provider refreshes retain previous positive findings as stale.
Reports contain personal account metadata and should be kept private.

Install updated requirements for PDF support (`reportlab`). Delete saved data
from Module 4 privacy controls; this removes database records for the current
mailbox, not exported copies or Google account data. File/database deletion is
not a secure-erasure guarantee. The browser inventory displays at most 100
services and alerts; the downloaded report includes the full service inventory.
Processed message-ID markers expire after 30 days; signup/incident alert keys
still prevent repeated alert spam. Monitoring data remains until explicitly
deleted. Review other-user access to this local machine accordingly.


## Finding reviews and security action tracking

Service cards in Module 1 and the monitored inventory provide Confirm / Dismiss
and Undo. Decisions survive rescans and restarts in the local SQLite database,
isolated by the actual connected Gmail address. Confirmation is the user's
statement, not verified ownership. Dismissed findings are excluded from normal
breach lookup, future monitored signup/breach alerts and security-plan views;
existing related alerts are acknowledged, not deleted. Undo restores eligibility.

Module 3 saves each security step as Pending / Done and allows a reminder date.
Due/overdue pending actions appear in-app when opened; no email or background
desktop reminder delivery is promised. Done remains a self-report. These
features do not require enabling continuous monitoring, but do require a loaded
Gmail scan or a monitoring mailbox. Save controls themselves opt into local
decision storage. No subjects, passwords or tokens are persisted. Clear these
decisions with Module 3's privacy control; Module 4 data deletion also removes
them. Fictional demo decisions use separate browser storage and never seed the
real mailbox's decisions. Switching accounts never carries decisions across.
