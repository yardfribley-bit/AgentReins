# Task Execution Model — Test Report

**Product:** AgentReins

**Date:** 2026-09-17

**Scope:** Task families, engine attempts, corrective retries, verification, and model-switch advisory threshold

**Result:** PASS WITH INTEGRATION WORK REMAINING

## 1. Executive Summary

The new task-execution data model passed all targeted tests and the complete AgentReins regression suite.

- 133 tests executed
- 133 tests passed
- 0 failures
- 0 unexpected failures
- Full suite duration: 77.688 seconds
- 100,000-event persistence benchmark: 42.524 seconds, 89.12 MB database
- One-second process recall: 100%
- Maximum observed process snapshot time: 110.33 ms

The model correctly treats three attempts as an advisory model-switch threshold, not a collection limit. AgentReins continues recording every subsequent attempt. An Agent's completion claim is not considered success until the final deliverable passes independent verification.

This report does **not** claim that live WorkBuddy/Codex evidence is already persisted into the new model. Adapter projection, SQLite persistence, live UI, and active orchestration remain separate integration work.

## 2. Acceptance Criteria

| ID | Requirement | Result |
|---|---|---|
| AC-01 | Represent one user task independently from sessions and turns | PASS |
| AC-02 | Represent multiple engine attempts under one task | PASS |
| AC-03 | Represent corrective retries inside one engine attempt | PASS |
| AC-04 | Default model-switch threshold is three attempts per engine identity | PASS |
| AC-05 | Attempt collection remains unlimited after the threshold | PASS |
| AC-06 | Attempts are counted separately after changing model/provider/relay | PASS |
| AC-07 | Do not request a model switch while the third attempt is still running | PASS |
| AC-08 | Agent-reported completion is not treated as verified success | PASS |
| AC-09 | Only the final independently verified attempt can complete the task | PASS |
| AC-10 | An earlier success cannot hide a failed final deliverable | PASS |
| AC-11 | Preserve the complete model through JSON encoding and decoding | PASS |
| AC-12 | Do not merge clearly unrelated historical tasks | PASS |

## 3. Data Model Under Test

```text
TaskExecution
├── AttemptBudgetPolicy
├── EngineAttempt[]
│   ├── EngineIdentity
│   ├── AttemptAcceptanceCriterion[]
│   ├── CorrectiveRetry[]
│   ├── tool / file / network / memory references
│   ├── failure signatures
│   ├── Agent-reported outcome
│   ├── IndependentVerification
│   └── AttemptDecision
└── final verification and decision
```

The engine budget key includes Agent, engine, model, provider, and relay. Changing any of these creates a separately observable execution route and a separate advisory attempt count.

## 4. Targeted Test Results

| Test | Expected behavior | Result |
|---|---|---|
| `testTaskExecutionRequiresModelSwitchAfterThreeFailedAttempts` | Third terminal failure recommends switching models | PASS |
| `testTaskExecutionContinuesRecordingBeyondSwitchThreshold` | Five real attempts remain five records; two are beyond threshold | PASS |
| `testTaskExecutionCountsAttemptsSeparatelyAfterModelSwitch` | New model starts its own attempt count | PASS |
| `testRunningThirdAttemptDoesNotSwitchBeforeOutcome` | No premature switch while attempt is active | PASS |
| `testAgentReportedCompletionDoesNotCountAsSuccess` | Agent claim remains unverified | PASS |
| `testVerifiedFinalAttemptCompletesTaskWithoutModelSwitch` | Independent final verification completes the task | PASS |
| `testTaskExecutionRoundTripsThroughJSON` | No data is lost during persistence serialization | PASS |
| `testTaskAttemptHistoryGroupsExactRepeatedRequirements` | Exact repeated requirements form one task family | PASS |
| `testTaskAttemptHistoryKeepsUnrelatedRequirementsSeparate` | Unrelated requirements remain separate | PASS |
| `testTaskAttemptHistoryUsesFinalAttemptAsTaskOutcome` | Final failure overrides an earlier verified attempt | PASS |

## 5. Real-World Forensic Validation: VMess Task

The historical WorkBuddy VMess deployment was used as a read-only forensic validation case.

Observed evidence included:

- multiple user turns;
- 51 tool calls and corresponding results;
- prerequisite diagnosis and disk recovery;
- a shared Caddy/Xray design;
- multiple permission, configuration, protocol, and certificate-pin corrections;
- a user-rejected architecture;
- a replacement standalone Xray design;
- a final external-connectivity blocker;
- an Agent claim that deployment was complete even though the delivered VMess configuration was not usable.

Expected representation:

```text
Task: Configure VMess on Tencent Cloud
├── Plan/engine attempts
├── Corrective retries inside each attempt
├── 51 linked tool executions
├── final independent verification: FAILED
└── task outcome: FAILED / NOT DELIVERED
```

The forensic case confirms why Agent output text cannot be the success authority. It also exposes a current adapter gap: many historical WorkBuddy tool events exist in its native JSONL but do not carry the turn identifier required for reliable automatic projection.

No credentials or connection secrets are reproduced in this report.

## 6. Full Regression Coverage

The complete suite also passed coverage for:

- Agent discovery and runtime profiles;
- Codex, WorkBuddy, Claude, Cursor, Qoder, and Web AI adapters;
- context growth and requirement-loss detection;
- file, process, network, SSH, memory, and model-route evidence;
- cross-project credential-read alerts;
- external-content and prompt-injection detection;
- independent verification and recovery;
- SQLite WAL, replay, integrity recovery, checkpoints, and collector health;
- project evolution and project-alignment semantics;
- high-volume persistence and short-process recall.

## 7. Performance Results

| Benchmark | Observed result | Status |
|---|---:|---|
| Persist 100,000 evidence events | 42.524 s | PASS |
| Database size after benchmark | 89.12 MB | Recorded |
| Recall of one-second processes | 1.0 | PASS |
| Maximum process snapshot latency | 110.33 ms | PASS |

These are test-environment measurements, not a universal hardware guarantee.

## 8. Known Gaps and Release Risk

### P0 — required before active pair-programming control

1. Persist `TaskExecution`, `EngineAttempt`, and `CorrectiveRetry` records in SQLite.
2. Project live Agent events into stable `task_id`, `attempt_id`, and `retry_id` values.
3. Repair WorkBuddy parent/logical-parent attribution so tool calls are linked to the correct attempt.
4. Generate or capture explicit acceptance criteria before evaluating success.
5. Run independent verification before changing the task to green.
6. Display the advisory threshold without stopping evidence collection.
7. Emit a model-switch recommendation after the third terminal failure.

### P1 — required before automated model switching

1. Detect duplicate failure signatures and prevent blind repetition.
2. Transfer only requirement, acceptance criteria, current state, and failure evidence to the replacement model.
3. Enforce overall task cost/time limits independently from per-engine thresholds.
4. Require user approval before switching providers when privacy or billing changes.

## 9. Release Decision

**Data model:** Accepted.

**Regression safety:** Accepted.

**Live observation integration:** Not yet accepted.

**Automated three-attempt model switching:** Not yet accepted.

The update is safe to merge as a data-model foundation. It must not yet be marketed as an active retry controller until the P0 integration items are completed and tested end to end with real Agent sessions.

## 10. Reproduction

```bash
swift test
```

Targeted model tests can be selected with:

```bash
swift test --filter 'TurnJournalTests.testTaskExecution|TurnJournalTests.testTaskAttemptHistory|TurnJournalTests.testAgentReportedCompletion|TurnJournalTests.testVerifiedFinalAttempt'
```
