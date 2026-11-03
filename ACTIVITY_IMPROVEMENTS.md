# Cyber Twin improvement review — 12 October 2026

## Implemented during this session

- Compact white/slate/blue design; green palette and gradients removed.
- Personal overview: discovered services, recent evidence, alert evidence, billing clues.
- Monthly evidence chart with direct month filtering; counts are evidence, not time online.
- Review queue for security/password events, billing clues, forgotten-account candidates and weak identity clues.
- Reversible review marks in the current page session only; no persistent notes or tracking.
- Combined timeline with service, event-type and month filters, showing 100 records at a time.
- Fictional demo with .example domains and explicit demo labels; no mailbox access.
- Background scan progress, one worker, cancellation between requests, and a 30-second transport timeout.
- Maximum three in-memory jobs; normalized results expire after ten minutes, with cleanup within another 30 seconds.
- Local disconnect clears credentials/jobs/pending OAuth; no Google permission revocation.
- Original authentication, synchronous reconstruction endpoints and registration discovery preserved.

## Research conclusions

Google recommends metadata batches of no more than 50 requests. Batching reduces network connection overhead but each inner request still consumes quota. A future implementation should process small batches, match callbacks by message ID, preserve 404 gap counts, retry individual transient failures, and check cancellation between batches.
Source: https://developers.google.com/workspace/gmail/api/guides/batch

Incremental history synchronization can reduce repeated scanning. History IDs expire and can return 404, requiring full synchronization. This should use bounded, expiring normalized evidence per Gmail connection and clear state on disconnect. It is not enabled in this version.
Source: https://developers.google.com/workspace/gmail/api/guides/sync

Review prompts guide users to the service directly, to inspect unfamiliar security activity and recovery settings themselves. Mailbox notification wording does not establish compromise. The app does not change credentials or automatically follow alert links.
Sources: https://support.google.com/accounts/answer/140921 and https://support.google.com/accounts/answer/185839

Dynamic result counts and waiting messages are announced through status/live-region semantics. Review actions preserve keyboard focus after their content updates. This is an accessibility improvement, not a complete WCAG conformance audit.
Source: https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html

## Validation and performance

61 offline Python tests pass. JavaScript syntax and existing dashboard interaction checks pass. Browser checks covered desktop and phone layouts, review filters, review/undo, keyboard focus, navigation to account evidence, event/month filtering, clear results, and prominent fictional-data labelling. The phone layout showed equal document and viewport widths, indicating no horizontal overflow in the tested state.

A synthetic worst-case test reconstructed 10,000 messages across 10,000 fictional services and built insights in 2.25 seconds, with about 31.5 MB peak Python allocations measured by tracemalloc. The review queue was capped at 1,000 prompts with its full count and truncation flag retained. This is one local measurement with allocation tracing enabled, not a live Gmail throughput claim or a browser stress benchmark.

Highest-value follow-ups:
1. Validate Gmail consent and real notification samples with the account owner.
2. Add metadata batching and compare live latency/quota behaviour.
3. Paginate or virtualize account cards and long per-service timelines for unusually large scans.
4. Add incremental synchronization only after its privacy and expiry model is tested.

Live Gmail consent, provider latency and cancellation while an actual Google request is in flight remain unverified. No browser-history source, new provider integration, automatic cancellation/closure, raw email retention, or security export was added.
