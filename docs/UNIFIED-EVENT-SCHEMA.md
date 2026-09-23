# AgentReins unified event schema

AgentReins normalizes adapter evidence before metrics, analysis, UI, or RAG
consume it:

```text
raw evidence -> AgentEventEnvelope -> derived finding -> RAG document
```

`AgentEventEnvelope` is the canonical record. `canonicalKind` provides a stable
cross-agent vocabulary, while the typed payload retains complete evidence.

## Correlation

- `id` identifies one normalized event.
- `sessionID` identifies an agent conversation or runtime session.
- `turnID` identifies one user/agent turn when the source exposes it.
- `correlation.taskID` groups events pursuing one user outcome.
- `traceID`, `spanID`, and `parentSpanID` represent causal structure.
- `requestID` pairs model request and response evidence.
- Tool payload `callID` pairs tool call and result evidence.
- `actionID` joins a tool call to command, file, or network actions.
- `sourceEventID` preserves the adapter's native identifier.

Timestamps order evidence but never establish identity by themselves. Adapters
must leave unavailable identifiers empty rather than inventing a confident
association.

## Metrics and RAG

`AgentEventMetrics` derives shared dashboard counters from canonical events.
Adapters do not own metric definitions. RAG documents should reference task,
session, turn, trace, event, and finding identifiers so vector retrieval finds
candidates while SQLite reconstructs the evidence chain.

## Outbound model requests

Task exports include `outboundRequests`. Each record preserves the captured
body, its SHA-256 digest, model, destination, trace/request identifiers, source,
confidence, and an explicit capture boundary:

- `completeHTTPSRequestBody`: the supported audit proxy captured and verified
  the request body at the HTTPS flow boundary.
- `preEncryptionRequestBody`: a native adapter recorded the provider request
  before encryption.
- `agentRecordedContext`: the Agent recorded context associated with a request,
  but the exact wire body is not proven.
- `contextFragment`: one contributing context layer, not a complete request.

Completeness is never inferred from content length alone. This distinction is
required before using outbound context as forensic or RAG evidence.

## Unified task snapshot

`AgentTaskSnapshot` is the single platform contract shared by JSON export,
frontend projections, analysis, and future RAG builders. Its modules are:

- `task`: stable task/session/turn identity and time boundary.
- `capture`: evidence health, sources, gaps, and missing capabilities.
- `conversation`: user input, model output, reasoning, models, and traces.
- `outboundRequests`: captured Agent-to-LLM request evidence.
- `activities`: tools, results, commands, files, network, and memory.
- `analysis`: economics, exposure, relay, egress, memory, code, verification.
- `metrics`: one agent-neutral definition of task counters.
- `events` and `sourceEvents`: normalized and source-level evidence.
- `evidenceReferences`: stable IDs used to reconstruct provenance.

The `revision` is a content-derived identifier over the evidence references.
Consumers can skip decoding or rendering an unchanged snapshot.
