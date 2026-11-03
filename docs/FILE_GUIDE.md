# Cyber Twin file guide

Every retained source/configuration file is listed below. Conventional Python names such as `main.py`, `models.py` and `__init__.py` are intentional. Application behavior and API URLs were preserved during cleanup.

## Startup and configuration

| File | Purpose |
|---|---|
| `.env.example` | Template showing supported Google/provider settings; contains no real credentials. |
| `.gitattributes` | Keeps text-file line endings consistent across Windows and Git. |
| `.gitignore` | Excludes credentials, saved private data, caches, generated files and local reports from Git. |
| `README.md` | Current startup instructions, four-module workflow, privacy rules and test commands. |
| `Start Cyber Twin.cmd` | Double-click Windows launcher; runs start_server.py from the correct folder. |
| `requirements.txt` | Python dependencies needed to run the application and export PDFs. |
| `start_server.py` | Chooses an available local port, starts FastAPI and opens the dashboard. |

## Backend source

| File | Purpose |
|---|---|
| `app/__init__.py` | Marks the application folder as a Python package. |
| `app/gmail/__init__.py` | Marks Gmail integration as a Python package. |
| `app/gmail/client_setup.py` | Validates an imported Google Desktop client and saves its settings privately to .env. |
| `app/gmail/full_mailbox_scanner.py` | Scans the whole mailbox in paced batches; retries transient errors and supports cancellation. |
| `app/gmail/oauth.py` | Builds Google consent flows, validates setup and manages Desktop PKCE and token revocation. |
| `app/gmail/scanner.py` | Fetches Gmail metadata for bounded scans, registration search and mailbox identity. |
| `app/main.py` | Creates FastAPI, serves the dashboard, handles Gmail login/scans and registers API routes. |
| `app/models.py` | Defines validated service, activity, public-profile and location evidence data structures. |
| `app/monitoring/__init__.py` | Marks the monitoring and saved-decision components as a Python package. |
| `app/monitoring/api_routes.py` | Exposes monitoring controls, alert acknowledgement, saved-data deletion and report downloads. |
| `app/monitoring/monitor_manager.py` | Runs opt-in Gmail-history polling and periodic service breach checks; handles stop/reconnect and gaps. |
| `app/monitoring/monitor_store.py` | Stores mailbox-isolated services, checkpoints, alerts, finding reviews and action statuses in SQLite. |
| `app/monitoring/report_export.py` | Builds the existing PDF/HTML export from normalized findings; red means review needed, not compromise. |
| `app/monitoring/review_actions_api.py` | Saves Confirm/Dismiss decisions and Pending/Done actions using the actual connected Gmail identity. |
| `app/security/breach_checker.py` | Retrieves HIBP breach metadata, sanitizes descriptions and matches exact/parent service domains. |
| `app/security/security_plan.py` | Generates conditional password, MFA, device, recovery and phishing-review guidance. |
| `app/services/account_discovery.py` | Groups registration-message clues into discovered services and earliest evidence dates. |
| `app/services/activity_demo.py` | Creates fictional mailbox/service/activity examples without contacting Gmail. |
| `app/services/activity_insights.py` | Builds overview counts, monthly evidence data and prioritized review prompts. |
| `app/services/activity_reconstruction.py` | Classifies email subjects and creates normalized per-service activity timelines. |
| `app/services/breach_demo.py` | Creates fictional breach findings and security plans for the demo workflow. |
| `app/services/gravatar.py` | Optional email-hash-based Gravatar profile lookup; returns normalized public clues. |
| `app/services/location_analysis.py` | Optional research API that summarizes explicitly supplied place coordinates; does not locate a person. |
| `app/services/public_activity.py` | Optional public GitHub/Chess.com and IntelBase lookup adapters with bounded provider requests. |
| `app/services/scan_jobs.py` | Runs cancellable background scans, reports progress and expires in-memory results. |

## Browser source

| File | Purpose |
|---|---|
| `app/static/activity_workspace.js` | Overview, activity chart/timelines, review queue, scan progress, cancellation and disconnect interactions. |
| `app/static/dashboard.js` | Shared browser helpers, connection/setup handling, service cards and primary form submissions. |
| `app/static/email_migration.js` | Browser-saved old-email migration checklists, scan imports, priorities, progress and export controls. |
| `app/static/email_migration_model.js` | Validates migration data, deduplicates services and prevents cross-mailbox/demo imports. |
| `app/static/index.html` | Dashboard structure, forms, navigation and the four functional module panels. |
| `app/static/module_workflow.js` | Connect-and-scan handoff, breach results, module navigation and per-service security guidance. |
| `app/static/monitoring.js` | Monitoring controls, alert display, optional browser notifications and report-download buttons. |
| `app/static/review_actions.js` | Confirm/Dismiss/Undo controls, saved Pending/Done actions and in-app due reminders. |
| `app/static/styles.css` | Page layout, responsive behavior, controls and status colors. |

## Documentation

| File | Purpose |
|---|---|
| `docs/FILE_GUIDE.md` | Explains every retained file, private runtime files, cleanup decisions and renamed paths. |
| `docs/research/email_enrichment_research.md` | Historical IntelBase/Epieos integration research; reference notes, not active application configuration. |

## Tests

| File | Purpose |
|---|---|
| `tests/__init__.py` | Makes tests importable so shared offline request fixtures work after moving them into tests/. |
| `tests/test_activity_insights.py` | Tests review priorities, billing/security summaries, demo generation and disconnect cleanup. |
| `tests/test_activity_integration.py` | Tests bounded metadata scanning and API integration; also supplies shared offline ASGI request helpers. |
| `tests/test_activity_reconstruction.py` | Tests subject classification, evidence timestamps, privacy and activity-status rules. |
| `tests/test_activity_reliability.py` | Tests deleted messages, folder exclusions, Gmail errors, quotas and coverage reporting. |
| `tests/test_dashboard.py` | Checks dashboard/static-file serving, status privacy and OAuth return navigation. |
| `tests/test_dashboard_ui.cjs` | Offline browser-DOM checks for service filters, timeline order and coverage/explanation rendering. |
| `tests/test_email_migration.py` | Tests verified Gmail identity and connection changes used for migration imports. |
| `tests/test_email_migration_model.cjs` | Tests migration validation, duplicate prevention, saved decisions and mailbox isolation. |
| `tests/test_full_scan_integration.py` | Tests whole-mailbox batching/retries, legacy dates, personal breach lookup and related integration routes. |
| `tests/test_gmail_connection.py` | Tests Google setup diagnostics, canonical-host redirects, state cookies, replay/expiry and reconnect behavior. |
| `tests/test_monitoring.py` | Tests history checkpoints, signup/incident deduplication, recovery gaps, mailbox isolation and export endpoints; supplies monitoring fixtures. |
| `tests/test_optional_enrichment.py` | Tests optional IntelBase/Gravatar enrichment, linked profiles and manual location-analysis validation. |
| `tests/test_public_activity.py` | Tests public-profile adapters, dates, provider errors, partial coverage and route validation. |
| `tests/test_review_actions.py` | Tests persisted finding decisions, alert suppression, Pending/Done reminders and mailbox isolation. |
| `tests/test_scan_jobs.py` | Tests scan-worker progress, cancellation, expiry, ownership and error sanitization. |
| `tests/test_startup_and_oauth.py` | Tests the launcher, blocked-port fallback, Desktop client import and PKCE callback handling. |
| `tests/test_workflow_api.py` | Tests breach details, domain matching, unavailable/demo cases, security plans and unique HTML element IDs. |
| `tests/test_workflow_ui.cjs` | Offline browser checks for module handoff, breach details, guidance and stale-response isolation. |

## Private/local files retained on this computer

| File/folder | Purpose |
|---|---|
| `.env` | Existing real Google/provider credentials. Preserved unchanged; never published. |
| `data/monitor.sqlite3` | Existing saved service inventory, alerts, decisions and monitoring checkpoints. Preserved unchanged. |
| `data/monitor.sqlite3-wal` / `-shm`, if present | SQLite-managed transaction files. Leave them with the database. |
| `reports/cyber_twin_project_report.docx` | Your existing editable project report, moved and renamed without editing its contents. Local-only. |
| `reports/cyber_twin_project_report.pdf` | Your existing exported project report, moved and renamed without editing its contents. Local-only. |
| `.git/` | Git history, branches and repository metadata. Managed by Git; not application source. |
| `.env.*` backups, if present | Private configuration backups made by setup. Keep private; ignored by Git. |

## Removed from the active project

- `backend/`: duplicate skeleton whose files contained only placeholder docstrings or were empty.
- Empty `app/config.py` and `app/database.py`: never imported; active configuration and storage already live in the Gmail/monitoring components.
- One-line breach-checker forwarding file: replaced by the real implementation in `app/security/breach_checker.py`.
- `ACTIVITY_README.md` and `ACTIVITY_IMPROVEMENTS.md`: superseded historical instructions; preserved in the recovery archive.
- `__pycache__/` and bytecode: disposable Python-generated caches; Python can recreate them.
- `practical-tools/`, `tmp/` and `output/`: unrelated forensic installers, report-building assets and generated course reports. Moved to the recovery archive instead of destroyed.

The dated recovery archive is outside the project at `D:/cyber-twin-archive/2026-11-04/`. It contains pre-cleanup versions of renamed/deleted files and the original local-change diff. The two existing project reports remain inside the project under `reports/`; no new report was created.

## Renamed/moved files

| Previous path | Current path |
|---|---|
| `INTELBASE_EPIEOS_RESEARCH.md` | `docs/research/email_enrichment_research.md` |
| `app/gmail/full_scan.py` | `app/gmail/full_mailbox_scanner.py` |
| `app/monitoring/manager.py` | `app/monitoring/monitor_manager.py` |
| `app/monitoring/preferences.py` | `app/monitoring/review_actions_api.py` |
| `app/monitoring/report.py` | `app/monitoring/report_export.py` |
| `app/monitoring/router.py` | `app/monitoring/api_routes.py` |
| `app/monitoring/store.py` | `app/monitoring/monitor_store.py` |
| `app/services/module_demo.py` | `app/services/breach_demo.py` |
| `app/static/app.js` | `app/static/dashboard.js` |
| `app/static/migration-model.js` | `app/static/email_migration_model.js` |
| `app/static/migration.js` | `app/static/email_migration.js` |
| `app/static/modules.js` | `app/static/module_workflow.js` |
| `app/static/monitor.js` | `app/static/monitoring.js` |
| `app/static/preferences.js` | `app/static/review_actions.js` |
| `app/static/style.css` | `app/static/styles.css` |
| `app/static/workspace.js` | `app/static/activity_workspace.js` |
| `run.py` | `start_server.py` |
| `test_activity.py` | `tests/test_activity_reconstruction.py` |
| `test_activity_dashboard.cjs` | `tests/test_dashboard_ui.cjs` |
| `test_activity_insights.py` | `tests/test_activity_insights.py` |
| `test_activity_integration.py` | `tests/test_activity_integration.py` |
| `test_activity_reliability.py` | `tests/test_activity_reliability.py` |
| `test_dashboard.py` | `tests/test_dashboard.py` |
| `test_gmail_connection.py` | `tests/test_gmail_connection.py` |
| `test_merged_features.py` | `tests/test_full_scan_integration.py` |
| `test_migration.cjs` | `tests/test_email_migration_model.cjs` |
| `test_migration.py` | `tests/test_email_migration.py` |
| `test_module_ui.cjs` | `tests/test_workflow_ui.cjs` |
| `test_modules.py` | `tests/test_workflow_api.py` |
| `test_monitoring.py` | `tests/test_monitoring.py` |
| `test_preferences.py` | `tests/test_review_actions.py` |
| `test_public_activity.py` | `tests/test_public_activity.py` |
| `test_research_extensions.py` | `tests/test_optional_enrichment.py` |
| `test_scan_jobs.py` | `tests/test_scan_jobs.py` |
| `test_simple_connect.py` | `tests/test_startup_and_oauth.py` |

## Tests after cleanup

Run `python -B -m unittest discover -s tests -t . -q` and the three Node commands in README.md.
