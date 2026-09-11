# Collection Foundation Acceptance Report

Date: 2026-09-11  
Build: AgentReins 1.1.0 (`20260911.0537`)  
Scope: short-term macOS acceptance; the 24-hour soak test was intentionally deferred.

## Result

The durable evidence foundation is ready for continued beta development, but it is not yet a complete forensic collector. Process recall, persistent file modification observation, WAL persistence, idempotent replay, recovery, integrity verification, semantic fixtures, and Universal packaging passed. Short-lived network connections and rapid intermediate filesystem mutations remain explicit blind spots.

## Acceptance matrix

| Gate | Result | Evidence |
|---|---|---|
| Full regression | Passed | 48 tests, 0 failures, including the real process, file, persistence, recovery, and burst workloads. |
| One-second process recall | Passed | 20/20 controlled marker processes observed; recall `1.0`; maximum snapshot duration `56.5 ms` in the final run. |
| 100,000-event burst | Passed with performance follow-up | 100,000 unique events written and read back; hash verification passed; ingestion `55.9 s` in the final run; database size about `89.3 MB`. |
| Persistent protected-file modification | Passed | A real file mutation persisting across the one-second polling window produced a modification event. |
| Rapid file create/write/delete/rename history | Not passed | The current collector polls explicitly protected paths. It cannot reconstruct multiple intermediate states or arbitrary create-delete/rename activity between polls. |
| Sub-second network recall | Not passed | The shipping network source runs `lsof` every 10 seconds. It observes sockets present during a snapshot and cannot guarantee short-lived connections. |
| WAL and idempotent replay | Passed | SQLite reports WAL mode; duplicate replay does not duplicate evidence. |
| Raw-evidence integrity | Passed | Payload digests and the raw evidence hash chain verify; deliberate database tampering is detected. |
| Corruption recovery | Passed | A deliberately modified record hash caused recovery from the last valid backup. |
| Partial JSONL safety | Passed | A trailing partial row is not acknowledged and remains available for replay. |
| Adapter compatibility | Passed for committed fixtures | Codex and WorkBuddy fixtures cover turn, tool, result, usage, context, and external-content influence paths. |
| Universal macOS package | Passed | Release binary contains `x86_64 arm64`; ad-hoc signature passes deep/strict verification. |
| Desktop launch smoke test | Passed | Latest packaged app launched successfully; ten one-second samples reported `0.0%` CPU and about `67.3 MB` RSS after startup. This is not a substitute for the deferred soak test. |
| 24-hour CPU/memory/database soak | Deferred | Deferred by product decision; no long-duration stability claim is permitted yet. |

## Defects found during acceptance

The filesystem workload exposed a crash when a collector tried to use `UNUserNotificationCenter` from XCTest or a command-line host. Notification delivery is now restricted to a real `.app` bundle. This prevents collector benchmarks and non-app hosts from triggering the framework assertion.

## Claims allowed after this run

- AgentReins durably records supported local Codex and WorkBuddy evidence in SQLite WAL storage.
- It detects one-second agent child processes in the controlled benchmark used here.
- It observes persistent changes to explicitly protected files.
- It records sampled agent network sockets and clearly identifies that evidence as sampled.
- Its current macOS package runs on Apple Silicon and Intel Macs.

## Claims still prohibited

- “Captures every process, network connection, or file mutation.”
- “Provides a complete forensic audit trail.”
- “Proves that an inferred OS event was caused by a specific turn or tool call.”
- “Has passed long-duration stability testing.”

## Required follow-up

1. Add a lower-loss network event source; retain `lsof` as reconciliation evidence.
2. Add FSEvents-based workspace change notification plus periodic reconciliation.
3. Make source fingerprint replacement/rotation handling an end-to-end adapter contract.
4. Commit accepted raw evidence and its source checkpoint in one database transaction.
5. Add periodic consistent backups rather than creating a backup only at startup.
6. Reduce 100,000-event ingestion time and database bytes per event.
7. Run the deferred 24-hour soak before making stability or always-on performance claims.
