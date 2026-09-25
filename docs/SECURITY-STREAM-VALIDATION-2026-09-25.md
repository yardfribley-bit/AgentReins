# Security stream validation — 2026-09-25

The local safety workers admit saved events independently of task snapshots.
Recent evidence receives a bounded admission window; historical evidence advances
through a persistent cursor. The source index is updated asynchronously so its
JSON extraction does not run in the collector's write transaction.

Validated cases include incomplete tasks without snapshots, late evidence,
restart recovery, partial coverage, per-slice failure isolation, and real-time
tool call/result matching without an AI model. Security findings preserve stable
identities across refreshes. The backlog update no longer aggregates the entire
security input table on every batch.

The targeted queue, event-stream, finding-feed and ingestion run passed 10 tests.
The 100,000-event ingestion benchmark measured 67.30 seconds against the existing
90-second budget. Earlier runs exceeded that budget while the installed old app
was consuming approximately 176% CPU; it was normally exited during validation.
Digest hexadecimal encoding was also simplified before the passing run, so the
improvement cannot be attributed solely to either change.

The audit server passed all 9 tests, including idempotent receipts, authentication,
block uploads and receiver backpressure. Tests used local fixtures and did not
send evidence to a cloud analysis model.

The final Swift run excluding the separately passed ingestion benchmark executed
295 tests with 6 opt-in tests skipped and zero failures (42.97 seconds).

Limitations: passing these checks does not establish full V3 architecture
completion, cross-task AI investigation quality, or a real-time latency SLA.
Single large events are still decoded as a unit. Asynchronous findings do not
provide proof of execution-time blocking or successful rollback.
