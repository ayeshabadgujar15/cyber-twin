# Cyber Twin

A local Gmail digital-footprint assistant. This is a single-user, single-process
application. It identifies evidence of accounts; it does not verify ownership
or prove that a personal account was compromised.

## Start

Requires Python 3.10+; Node.js is needed only for JavaScript checks.

```powershell
python -m pip install -r requirements.txt
python start_server.py
```

Or double-click **Start Cyber Twin.cmd**. The launcher selects a working local
port and opens the dashboard. Keep its window open while using the app.

For Gmail, import a Google Desktop OAuth client JSON once under **Help & setup**.
The project owner must enable Gmail API and, in Google Testing mode, add the
Gmail address as a test user. Then enter the email and use **Connect & scan**.
Passwords are entered only on Google's page. Existing web-client `.env` settings
remain supported when their registered callback port is available.

## Functional modules

1. **Inbox & services:** connect Gmail, scan metadata and list service clues.
   Whole-mailbox mode is available; Scan options offers smaller limits. Includes
   Spam/Trash and excludes Sent/Draft. Timelines, evidence charts, registration
   search, Confirm/Dismiss findings and optional GitHub lookup belong here.
2. **Breach lookup:** compare service domains against HIBP's public catalogue.
   Display incident dates, descriptions, exposed data and source details. A match
   does not establish personal exposure. Optional connected-email lookup needs
   an HIBP key and sends that address only when explicitly requested.
3. **Secure accounts:** show password/MFA/session/recovery guidance. Pending/Done
   statuses and reminder dates are saved per mailbox; due reminders appear
   in-app. Dismissed clues are excluded. Email migration is an optional checklist.
4. **Monitor & report:** opt-in local polling for new signup clues and service
   breach updates, saved alerts and PDF/HTML exports. Default inbox checks are
   every 2 minutes and breach checks every 30 minutes. This is not a browser
   extension or cloud service; the server must keep running. Resume after a
   restart/reconnection. New findings are heuristic, not proof of registration.

## Privacy and persistence

- `.env` contains private Google/provider settings. Never commit it. Optional
  configuration keys are documented in `.env.example`.
- Credentials stay in memory. Subjects/bodies are not persisted by the monitor;
  bodies and attachments are not requested. Legacy registration discovery can
  return subject evidence in its response.
- On-demand background scan results expire after ten minutes. Browser review
  views operate on loaded snapshots.
- Saving reviews/actions or enabling monitoring writes normalized service data,
  decisions, message-ID checkpoints and alerts to `data/monitor.sqlite3`.
  Data is isolated by the connected Gmail identity and retained until deleted.
  Module 3 clears reviews/actions; Module 4 can delete its saved mailbox data.
  Deletion is not a secure-erasure guarantee.
- Email migration and fictional demo decisions use separate browser storage;
  changing browser/port or clearing site data affects those checklists.
- Reports contain private account metadata. Red means review needed, amber
  means unchecked, and neutral is not a safety guarantee.
- Monitoring handles Gmail history pagination and retries without skipping
  unfinished checkpoints. Expired history produces a coverage warning and a
  bounded recent recovery scan, not a claim of complete recovery.

## Checks

```powershell
python -B -m unittest discover -s tests -t . -q
node tests/test_dashboard_ui.cjs
node tests/test_workflow_ui.cjs
node tests/test_email_migration_model.cjs
```

Tests use offline fixtures. Live Google consent, mailbox behavior and optional
paid-provider access still need account-owner validation.

## Where files belong

- `app/`: backend and browser application source.
- `tests/`: Python and JavaScript checks.
- `docs/FILE_GUIDE.md`: purpose of every retained source/configuration file.
- `docs/research/`: historical integration research, not current product claims.
- `data/`: private runtime database; ignored by Git.
- `reports/`: locally retained project-report documents; ignored by Git.

Unused backend placeholders, superseded activity guides, cached bytecode and
unrelated forensic assets have been removed from the active project. Unrelated
assets and previous file versions are retained in the dated recovery archive
outside the project. Existing local source edits were preserved.
