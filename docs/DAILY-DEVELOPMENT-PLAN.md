# Daily Development Plan — September 9, 2026

## Today's product objective

Turn AgentReins from an activity viewer into a credible local safety layer that explains whether a coding agent still follows the user's requirements after external content, tools, MCP servers, skills, and memory influence its context.

## Morning — completed

- Preserved provider-reported usage for every model request instead of collapsing a turn to one token maximum.
- Added live context growth, cumulative input, largest-step growth, cache reporting, and clear processed-versus-unique-context language.
- Fixed missing and cross-linked model context by associating exchanges with both turn and trace identity.
- Added a two-second live activity stream for prompts, model requests, tool calls, and results.
- Exposed tool names, arguments, outputs, model decisions, turn IDs, and trace IDs.
- Added initial Tool, MCP, and Skill capability classification with explicit evidence limitations.
- Added Context Integrity v1: requirement retention, repeated tool payload, tool-noise ratio, context health, and evidence confidence.
- Expanded automated coverage from 8 to 12 passing tests.
- Published every completed slice to GitHub with successful Universal 2 CI builds.

## Afternoon — P0 implementation

### 1. External Content Provenance

Identify and label content entering the agent from:

- Web pages and search results
- MCP responses
- Skills and their instruction files
- Local files and source code
- Terminal and build output
- Persistent memory retrieval

Acceptance criteria:

- Each supported external payload has a source type, source identity, trust state, timestamp, turn ID, and trace ID.
- Unknown provenance is displayed as unknown, never silently treated as trusted.
- The live stream shows the source before showing the security conclusion.

### 2. Injection Scanner v1

Detect high-value instruction patterns in untrusted content:

- Attempts to override user or system instructions
- Requests to read or exfiltrate secrets
- Instructions to execute or install untrusted code
- Privilege escalation and safeguard bypass
- Persistent-memory writes and future-turn manipulation
- System/developer/admin impersonation
- Obfuscated instructions, including suspicious encoded payloads and invisible characters

Acceptance criteria:

- Deterministic fixtures cover benign and malicious examples.
- Every finding contains evidence, source, category, severity, and confidence.
- Detection does not automatically claim that the model followed the instruction.

### 3. Influence Chain v1

Connect the evidence sequence:

`External content → suspicious instruction → next model decision → tool call → observed result`

Acceptance criteria:

- Exact links use shared turn, trace, call, and source identities.
- Timing-only links are labeled `Inferred`.
- The UI never presents temporal proximity as proven causation.

### 4. Real WorkBuddy acceptance run

Run a controlled fixture where WorkBuddy reads a document containing a harmless simulated injection and then continues the task.

Acceptance criteria:

- AgentReins identifies the external source and suspicious text.
- The event appears in the live stream within the polling window.
- The original user requirement remains visible throughout the turn.
- Any later tool activity is connected with the correct evidence confidence.
- Raw evidence remains available without exposing hidden model reasoning that the source did not record.

## Afternoon — quality gate

- Run all unit tests with zero failures and zero compiler warnings.
- Measure idle and active polling CPU impact after reducing the interval to two seconds.
- Confirm long tool results do not freeze scrolling or overwhelm the default view.
- Verify the app on the current Mac, then package and validate both Intel and Apple Silicon architectures.
- Publish one focused English commit per completed capability and require GitHub CI to pass.

## Defer unless P0 finishes early

- Full semantic Context Diff between every provider request body.
- Automatic execution blocking based on external-content findings.
- Cryptographic Skill and MCP publisher verification.
- Windows event and process adapters.
- Broad multi-agent integrations beyond WorkBuddy.
- Product Hunt screenshots, launch video, and final marketing copy.

## End-of-day demo

A user starts a WorkBuddy coding task. AgentReins shows the original requirement, watches context growth, identifies the tools and external sources involved, flags a simulated instruction inside untrusted content, and connects subsequent model and tool activity without overstating causation. The user can open the raw evidence and understand what happened without reading a JSON log.

## Release decision

Do not claim “prevents prompt injection” today. The acceptable claim after the P0 test passes is:

> AgentReins locally detects suspicious instructions in recorded external agent content and connects them to the surrounding model and tool activity with explicit evidence confidence.
