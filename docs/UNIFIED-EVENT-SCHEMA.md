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
- `preEncryptionRequestProjection`: a native pre-encryption Model I/O record
  was reassembled into messages/tools/metadata, but byte-for-byte completeness
  of the provider body is not established.
- `agentRecordedContext`: the Agent recorded context associated with a request,
  but the exact wire body is not proven.
- `contextFragment`: one contributing context layer, not a complete request.

Completeness is never inferred from content length alone. This distinction is
required before using outbound context as forensic or RAG evidence.

## Unified task snapshot

`AgentTaskSnapshot` is the single platform contract shared by JSON export,
frontend projections, analysis, and future RAG builders. Its modules are:

Schema version 3 adds WorkBuddy trace request prefixes, structured model
responses, MCP call projections, and classified network flows. Trace matching
requires a unique nearby anchor trace at the start of the selected turn;
continuation traces must share its worker PID and remain within the turn's
time boundary. Ambiguous anchors are omitted. Trace inputs remain
`agentRecordedContext` and `partial`,
not verified HTTPS bodies. Network flows distinguish model endpoints, SSH,
agent web/API access, infrastructure, and unknown traffic. A socket merely
occurring in a model turn is not classified as model traffic.

Schema version 4 adds `journey.rounds`: ordered request evidence, parsed
request sections, a response (with exact trace-ID or temporal correlation
clearly identified), and subsequent tool calls with outputs, file activity,
and measured duration. Unassigned responses and tools remain explicit rather
than being forced into a nearby round. The task reader offers this chain next
to the raw JSON; captured reasoning is labeled as a recorded summary, not
assumed to be the model's complete private reasoning.

`analysis.memoryEvidence` separates memory usage
instructions (`contextSegments.kind=usageInstructions`) from candidate memory
content blocks, WorkBuddy `identity_context` file contents, and exact matches to
observed memory file contents. A reminder
that mentions `MEMORY.md` is preserved as evidence but does not establish a
memory read, memory change, or transfer of that file's contents. Each exact
match retains both source event IDs and the request capture boundary. Memory
file events also project to `activities.memory` when the file path is known.

- `task`: stable task/session/turn identity and time boundary.
- `capture`: evidence health, sources, gaps, and missing capabilities.
- `conversation`: user input, model output, reasoning, models, and traces.
- `outboundRequests`: captured Agent-to-LLM request evidence, including source
  locator and completeness boundary.
- `externalRequests`: content-bearing non-model requests, including WorkBuddy
  memory recall. A recall HTTP request is not counted as an LLM call merely
  because it uses the same host as chat completions.
- `modelResponses`: time-stamped model-to-Agent content with source event ID.
- `journey`: request-centered multi-round execution chain with unassigned
  evidence retained.
- `activities`: tools, MCP calls, results, commands, files, classified network
  flows, and memory.
- `analysis`: economics, exposure, relay, egress, memory, code, verification.
- `metrics`: one agent-neutral definition of task counters.
- `events` and `sourceEvents`: normalized and source-level evidence.
- `evidenceReferences`: stable IDs used to reconstruct provenance.

The `revision` is a content-derived identifier over the evidence references.
Consumers can skip decoding or rendering an unchanged snapshot.
