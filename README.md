# Cyber Twin

A local personal digital-footprint assistant: discover account clues in Gmail,
review activity and security evidence, and inspect public profiles.

## Start

Requires Python 3.10+ and Node.js only for the JavaScript checks.

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env  # first setup only; do not overwrite existing credentials
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://localhost:8000/. Configure the Google OAuth client in `.env` and use
the exact localhost callback. Enable Gmail API and add your Google test user.
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
