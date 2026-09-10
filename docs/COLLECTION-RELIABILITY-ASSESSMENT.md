# Collection Reliability Assessment

Date: 2026-09-11  
Scope: AgentReins macOS collection foundation, not UI or higher-level security analysis

## Executive decision

**AgentReins is not yet a security-grade evidence collector.** It is useful as a beta observability prototype and can reconstruct meaningful parts of Codex and WorkBuddy activity, but it cannot currently guarantee completeness, causal attribution, crash-safe delivery, tamper-evident evidence, or low operational overhead.

Feature expansion should pause at the collection boundary until the P0 reliability gates in this document pass. Building more detection and explanation on the current foundation would create precise-looking conclusions from sampled and mostly inferred evidence.

## What was verified

- The Swift test suite passes: 38 tests, 0 failures.
- The live store was valid JSON and contained 500 events with no duplicate UUIDs.
- Process ancestry is collected with macOS `libproc`, with `ps` fallback.
- Agent TCP connections are sampled with `lsof` and tied to a socket-owning PID.
- Codex and WorkBuddy adapters can parse user, model, tool, result, usage, and context records when those records exist in their local JSONL formats.
- The attribution resolver refuses some ambiguous timestamp-only joins and labels compatibility evidence as inferred.
- Commands are redacted before EventStore persistence.

These are useful components. They do not yet establish end-to-end collection reliability.

## Live evidence snapshot

The current 500-event live window covered about 49 minutes.

| Metric | Observed |
|---|---:|
| Total events | 500 |
| Duplicate UUIDs | 0 |
| Inferred attribution | 489 (97.8%) |
| Unknown attribution | 11 (2.2%) |
| Confirmed attribution | 0 |
| Network events | 278 |
| Network events with PID | 278 (100%) |
| Network events with resolved domain | 57 (20.5%) |
| Network events linked to a session | 46 (16.5%) |
| Network events linked to a tool call | 21 (7.6%) |
| Model events | 117 |
| Model events with model prompt | 20 (17.1%) |
| Model events with model response | 34 (29.1%) |
| Model events with model identity | 78 (66.7%) |
| Model events with input-token data | 63 (53.8%) |
| Tool events | 86 |
| Tool events with tool name and call ID | 86 (100%) |

The numbers describe field coverage in the retained live window, not capture recall. There is currently no ground-truth source against which recall can be calculated.

## Reliability scorecard

| Layer | Current status | Assessment |
|---|---|---|
| WorkBuddy semantic records | Beta | Rich records can be parsed, but polling, tail limits, silent parse failures, and volatile dedup state can lose or replay evidence. |
| Codex semantic records | Beta | Useful compatibility parser; schema coupling and non-durable file cursors prevent a lossless guarantee. |
| Process activity | Sampled | PID/PPID ancestry is useful, but a two-second snapshot can miss short-lived commands. It is not an execution event stream. |
| Network activity | Sampled | PID ownership is useful for sockets visible during a snapshot. Short connections can be missed; domains are usually unavailable without tool/proxy evidence. |
| File activity | Partial | One-second polling covers configured paths only and can miss rapid create-delete or multiple writes between polls. It lacks reliable PID/tool causality. |
| Cross-layer attribution | Mostly inferred | Native session/call identifiers are strong where present. OS-to-turn joins remain temporal/workspace heuristics, not causal proof. |
| Persistence | Prototype | Whole-array JSON rewrites are atomic, but there is no WAL, durable source checkpoint, migration protocol, quarantine, or corruption recovery. |
| Evidence integrity | Insufficient | No immutable raw-evidence envelope, source offset, content hash, hash chain, signing, or independently verifiable export. |
| Performance | Failing | A 20-second live sample after 32 minutes showed periodic CPU spikes of 70.8%, 72.9%, and 55.4%, with quieter samples around 1%-3%. |
| Windows | Not assessed/not implemented | The present providers are macOS-specific and cannot support a Windows reliability claim. |

## Principal failure modes

### 1. Polling creates unknowable blind spots

Process/network collection runs every two seconds and file collection every second. Events that start and finish between snapshots can disappear completely. `lsof` reports current sockets, not a historical network event stream. A quiet dashboard therefore does not mean that no activity occurred.

### 2. Source progress is not durable

The Codex file-size cursor, adapter `seen` sets, process `seen` set, and connection deduplication state live in memory. A restart loses those checkpoints. Deterministic IDs reduce duplicate storage for some semantic records, but there is no durable per-source acknowledgement boundary proving exactly what was consumed.

### 3. Input truncation can drop context

Adapters use bounded tails (commonly 512 KiB; WorkBuddy also limits live parsing to the last 400 lines). This is appropriate for startup performance, but without a durable incremental cursor and rotation protocol it is not lossless. Large bursts, rotations, truncation, malformed lines, and writes during reads are not covered by an end-to-end stress matrix.

### 4. Failures are silent

Many read, decode, seek, and write operations use `try?` and return empty results. The product cannot currently distinguish “nothing happened” from “the collector failed.” There are no user-visible source health metrics for lag, parse errors, dropped rows, permission failures, last successful checkpoint, or backlog.

### 5. Persistence is not forensic storage

EventStore sorts and rewrites up to 500 live or 10,000 history events as one JSON array. A decode failure returns an empty store. There is no schema version on the event envelope, database migration, backup fallback, per-record transaction, evidence hash, or tamper detection. Atomic replacement reduces partial-write risk but does not provide an audit ledger.

### 6. Attribution is correlation, not causation

Process ancestry can identify that a process belongs under an agent. It does not prove which turn or tool call created it. Network-to-tool joins use bounded timing and uniqueness heuristics. This is correctly labeled inferred in code, but 97.8% of the current store is inferred and none is confirmed.

### 7. Collection itself exposes sensitive data

Real agent command lines can contain MCP endpoints, bearer credentials, workspace metadata, enabled tools, and model configuration. Commands are redacted at EventStore ingestion, but the raw snapshot exists before that boundary and other fields such as prompts, responses, tool arguments, and results do not share a single envelope-wide redaction policy. Collector logs, diagnostics, crash reports, and exports must be treated as sensitive attack surfaces.

### 8. Resource usage can interfere with the workload

Periodic high CPU was reproduced well after startup. A security observer that changes the performance characteristics of the agent can alter behavior, frustrate users, and create its own denial-of-service risk.

## Claims allowed today

AgentReins may honestly say:

- “Shows observed local activity from supported Codex and WorkBuddy data sources.”
- “Correlates available model, tool, process, network, and file evidence with explicit confidence labels.”
- “Runs locally and provides a best-effort recent activity trace.”

It must not yet say:

- “Captures every agent action or connection.”
- “Provides a complete audit trail.”
- “Proves which tool caused an OS action.”
- “Produces tamper-proof forensic evidence.”
- “Reliably detects or prevents all unsafe agent behavior.”

## P0 collection reliability milestone

### Durable evidence pipeline

1. Introduce a versioned immutable `EvidenceEnvelope` containing source ID, source-native record ID, source offset/checkpoint, observed time, source event time, payload hash, collector version, parse status, and confidence.
2. Separate immutable raw evidence from derived events, incidents, summaries, and UI projections.
3. Replace whole-array JSON persistence with SQLite in WAL mode, unique source keys, transactional batches, migrations, and recoverable backups.
4. Persist a checkpoint per source in the same transaction as accepted evidence. Reprocessing must be idempotent.
5. Hash raw records and build signed or checkpointed hash chains for verifiable exports.

### Observable collector health

Every provider must publish:

- running/degraded/failed state;
- last successful collection time;
- last durable checkpoint;
- source lag and backlog;
- bytes/records read and accepted;
- duplicate, malformed, truncated, and dropped counts;
- permission/schema/rotation errors;
- average and p95 collection duration.

### Source improvements

- Use FSEvents for workspace change notification plus periodic reconciliation; retain explicit limitations for file reads and PID causality.
- Treat `lsof` as sampled network evidence. Add a lower-loss macOS network event source when feasible; do not silently upgrade sampled evidence to complete evidence.
- Keep `libproc` snapshots for reconciliation, but add an execution event source when platform entitlement/distribution constraints allow it.
- Give Codex and WorkBuddy adapters versioned contracts, fixture corpora, rotation handling, partial-line buffering, and durable offsets.
- Prefer native session, turn, and tool-call IDs. Add opt-in agent adapters/hooks for causal tool-to-process linkage; otherwise keep attribution inferred.

## Acceptance gates before more security features

1. **Restart:** committed records have zero loss and zero duplication across forced termination and restart.
2. **Rotation/truncation:** adapters recover correctly from rename rotation, copy-truncate, partial final lines, and source-file replacement.
3. **Burst:** ingest at least 100,000 fixture events while preserving order, identity, and bounded memory.
4. **Concurrency:** correctly isolate multiple parallel sessions and refuse ambiguous cross-session attribution.
5. **Fault injection:** disk full, denied permission, malformed JSON, incompatible schema, corrupt database, and provider timeout become visible degraded states rather than empty results.
6. **Recall benchmark:** replay a known process/network/file/semantic workload and publish measured recall and false-attribution rates per source.
7. **Performance:** idle CPU below 1% p95; active collection below 5% p95 on the supported baseline Mac; no recurring >20% spikes; bounded memory over a 24-hour soak.
8. **Integrity:** exported evidence verifies hashes after restart and detects modification or deletion.
9. **Privacy:** secret corpus tests cover commands, environment-like arguments, prompts, tool inputs/results, URLs, headers, logs, exports, and crash diagnostics.
10. **Compatibility:** golden fixtures pass for every explicitly supported Codex and WorkBuddy format/version.

## Product decision

The collection foundation is valuable enough to continue, but not reliable enough to support broad security claims. The next product milestone should be **Reliable Evidence Foundation**, not another detector or dashboard panel. Once the acceptance gates pass, context security, supply-chain security, website safety, code scanning, requirement completion, verification, and recovery can be built on evidence whose limitations are measurable and visible.
