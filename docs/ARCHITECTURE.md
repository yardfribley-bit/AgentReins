# AgentReins Architecture

## Purpose

AgentReins is a local-first macOS companion for personal coding agents. It turns fragmented agent telemetry into a user-readable account of one task:

```text
User request
  -> captured model exchange
  -> tool and MCP calls
  -> process and file effects
  -> independent verification
  -> user decision and recovery
```

The product direction is **Trace + Verify + Recover + Provider Trust**.

## Source map

All production code lives in `Sources/AgentReins`.

| Area | Primary files | Responsibility |
| --- | --- | --- |
| App shell | `AgentGuardApp.swift`, `ContentView.swift`, `UIHelpers.swift` | Menu bar app, navigation, and user-facing evidence views. |
| Session model | `AgentSession.swift`, `Rule.swift`, `SecurityIncident.swift` | Turns, model exchanges, tool activity, and readable incident summaries. |
| Development story | `DevelopmentTrace.swift` | Aggregates raw events into Understand, Plan, Build, Test, and Deliver stages with layered drill-down evidence. |
| Agent adapters | `WorkBuddySight.swift`, `CodexSight.swift` | Read supported WorkBuddy evidence and compatible local Codex rollout records, then map them into normalized events. |
| Event storage | `EventStore.swift` | Persists and publishes normalized security and activity events. |
| Evidence attribution | `EventAttributionResolver.swift` | Conservatively joins fallback process and file observations to recent turns and records the evidence method and confidence. |
| Process monitoring | `ProcessGuard.swift` | Observes relevant local processes. |
| File protection | `FileGuard.swift`, `RuleStore.swift`, `NLParser.swift` | Watches protected paths, applies rules, and maintains recovery evidence. |
| Code review | `CodeSecurityScanner.swift` | Scans agent-introduced lines for local security patterns. |
| Memory safety | `MemoryFile.swift`, `MemoryRule.swift`, `MemoryRuleStore.swift`, `MemoryScanManager.swift` | Discovers memory files and reports sensitive retrieval or persistence signals. |
| Optional AI analysis | `SemanticAnalyzer.swift` | Sends redacted evidence to the user-configured OpenRouter model. |
| Notifications | `AppNotifier.swift` | Delivers local user notifications. |

## Runtime flow

1. An adapter discovers supported agent sessions and emits normalized `GuardEvent` records.
2. `EventStore` persists evidence locally.
3. Session-building code groups events into sessions, turns, and model exchanges.
4. Process, file, code, and memory monitors add computer-side evidence.
5. The UI presents a concise outcome first and keeps raw evidence behind expandable details.
6. Optional semantic analysis runs only after local redaction and only when the user configures it.

Historical session reconstruction is opt-in. Startup restores only the active session window; the History view scans older local evidence in the background when the user requests it.

## Trust model

- Local evidence is preferred over an agent's self-reported success.
- Captured evidence is distinguished from inferred correlation.
- Missing information is displayed as unknown.
- AgentReins does not claim access to hidden model reasoning that the agent or provider did not record.
- Remote retention and model identity cannot be guaranteed without provider attestation.
- Recovery must preserve changes that existed before the monitored turn.

## Current boundaries

- WorkBuddy is the native session integration. Codex support is a defensive local compatibility adapter because its rollout JSONL layout is not a documented stable API.
- File and process monitoring are observational and do not provide universal pre-execution enforcement.
- Git-quality turn attribution, independent build/test verification, transactional undo, and Provider Trust are roadmap work.
- Endpoint Security integration requires Apple approval, entitlements, Developer ID signing, and notarization.

## Adding an agent integration

A new adapter should produce the same normalized lifecycle evidence:

- session start and end
- user prompt submission
- model request and response metadata
- pre-tool and post-tool events
- tool failure and permission decisions
- workspace and file mutations
- task completion, failure, cancellation, or stuck state

Every field must retain its evidence source and attribution confidence. Adapter-specific payloads should not leak into the primary user interface.

## Roadmaps

- [Trace, Verify, Recover](TRACE-VERIFY-RECOVER-ROADMAP.md)
- [Provider Trust](PROVIDER-TRUST-ROADMAP.md)
- [Product Hunt launch](PRODUCT-HUNT-LAUNCH.md)
