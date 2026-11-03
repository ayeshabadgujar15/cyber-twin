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

Credentials and normalized scan results are memory-only. Background results
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
