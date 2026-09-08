# Trace, Verify, Recover — Development Roadmap

## Objective

AgentReins should independently answer three questions for every coding-agent turn:

1. What did the agent do?
2. Did the resulting code and system state pass independent verification?
3. Can the user safely keep or undo the changes?

The product promise is:

> AgentReins verifies what your coding agent actually changed — and lets you undo it.

## Current baseline

### Available today

- WorkBuddy session discovery and turn reconstruction.
- Captured user input and the model context written to WorkBuddy's local log.
- Model response, tool/function calls, tool results, model name, and token usage.
- Process snapshots and protected-file monitoring.
- Before/after file content and an initial line-based diff for protected text files.
- Local pattern-based scanning of newly changed code lines.
- Backup and automatic recovery for explicitly protected files.
- Memory retrieval and persistence indicators.

### Important limitations

- WorkBuddy is the only native session adapter.
- Captured model context may be partial and must not be labeled as the complete model request.
- File events do not have reliable session, turn, tool-call, or process attribution.
- File monitoring covers configured paths rather than the complete agent workspace.
- The current diff algorithm is not a Git-quality diff.
- Code scanning is pattern-based and does not perform AST or data-flow analysis.
- Build and test claims are not independently verified.
- Recovery is file-based rather than transactional and turn-based.
- Network destinations and data flows are not captured.
- Universal pre-execution enforcement is not available on macOS without deeper integration.

## P0 — Product Hunt minimum credible loop

### 1. Turn lifecycle and workspace snapshot

Create a durable `AgentTurnJournal` when a turn begins.

Required fields:

```text
turn_id
session_id
agent
workspace
started_at
completed_at
status
baseline_git_head
baseline_git_status
baseline_file_manifest
```

Acceptance criteria:

- A turn is recorded before the first mutating tool runs.
- Existing user changes are distinguishable from agent changes.
- An interrupted app can reload an unfinished journal.
- Turn status supports: thinking, running, waiting, completed, failed, cancelled, and stuck.

### 2. Reliable event correlation

Connect agent evidence to computer evidence:

```text
User request
  -> model call
  -> tool call
  -> process
  -> file mutation
  -> verification result
```

Correlation signals, in priority order:

1. Native `session_id`, `turn_id`, and `tool_call_id`.
2. Hook-provided workspace and file path.
3. Parent/child process ownership.
4. File path plus bounded timestamp window.
5. Heuristic inference, explicitly labeled as inferred.

Acceptance criteria:

- Every file change shows an attribution confidence level.
- Confirmed and inferred attribution are visually distinct.
- Missing attribution is shown as unknown, never guessed as fact.

### 3. Git-quality change verification

For Git workspaces, record:

- `git status --porcelain=v2`
- `git diff --stat`
- `git diff --numstat`
- full patch
- new, deleted, renamed, binary, staged, and unstaged files
- HEAD before and after the turn

Acceptance criteria:

- The report separates pre-existing user changes from agent-created changes.
- Inserted and deleted line counts match Git.
- New, deleted, and renamed files are represented correctly.
- Binary files are identified without loading their full content into the UI.

### 4. Independent build and test verification

Detect project type and select only safe, repository-defined verification commands.

Initial support:

- Swift Package Manager
- npm/pnpm/yarn
- Python pytest
- Go test
- Cargo test

Record:

```text
command
started_at
duration
exit_code
stdout
stderr
tests_passed
tests_failed
```

Acceptance criteria:

- Agent self-reported success is shown separately from independent verification.
- A missing test run is displayed as “Not verified,” not “Passed.”
- Verification commands have a timeout and output-size limit.
- Commands never run outside the selected workspace.

### 5. Turn-level recovery

Implement `Undo this agent turn`.

It must restore:

- modified files
- deleted files
- newly created files
- renamed files
- file permissions where recorded

Acceptance criteria:

- Undo does not erase changes that existed before the turn.
- A preview lists every recovery action before execution.
- Recovery writes a second journal and is crash-safe.
- The user can verify the post-recovery Git status.
- Irreversible external effects are labeled as non-recoverable.

### 6. Diff-scoped security review

Keep the fast local scanner, then add optional external engines:

- Semgrep for AST and data-flow findings.
- Gitleaks for secrets.
- OSV-Scanner for vulnerable dependencies.

Acceptance criteria:

- Only agent-introduced changes affect the turn risk summary.
- Findings contain file, line, rule, severity, evidence, and engine.
- Results distinguish confirmed failures, high-confidence findings, and review suggestions.
- Pattern matches are never presented as proven exploitability.

### 7. One additional native agent adapter

Implement Claude Code first because its lifecycle hooks expose pre-tool and post-tool evidence. Add Codex next.

Required events:

- session start/end
- user prompt submit
- pre-tool use
- post-tool use/failure
- permission request/denial
- file changed
- task completed/failed

Acceptance criteria:

- Installation is automated and reversible.
- Existing user hook configuration is preserved.
- AgentReins works after restarting the agent.
- Hook removal leaves the agent configuration valid.

### 8. Outcome-first run report

The primary card should answer:

```text
What the user asked
What the agent changed
Whether build/tests passed
Whether security review found anything
Whether the agent left the workspace
Time, model, tokens, and estimated cost
Keep changes / Undo turn
```

Raw prompts, trace IDs, tool payloads, and JSON remain available as evidence details.

## P1 — After the launch loop works

- Codex, Cursor, OpenCode, and generic OpenTelemetry adapters.
- MCP configuration discovery and an optional MCP proxy.
- Unknown-agent behavioral discovery with confidence scoring.
- Network destination and outbound data-flow monitoring.
- Pre-execution approval for irreversible external actions.
- Non-Git transactional snapshots and recovery.
- Local-model analysis through Ollama or another OpenAI-compatible endpoint.
- Hosted default analysis quota with BYOK as an optional advanced mode.
- Cost calculation by model and provider.
- Windows adapters and filesystem/process equivalents.

## Tomorrow's implementation order

1. Define `AgentTurnJournal`, `FileMutation`, and `VerificationRun` models.
2. Add persistent turn-journal storage with crash recovery.
3. Implement Git baseline and post-turn snapshot collection.
4. Associate WorkBuddy tool paths with Git/file mutations.
5. Replace the custom line diff with the Git patch for Git workspaces.
6. Add a read-only outcome card using the new journal.
7. Implement undo preview, then turn-level recovery.
8. Add one controlled fixture repository and automated tests for modify/create/delete/rename/undo.

Do not begin with additional dashboards, network monitoring, or more scanner rules. The first milestone is one trustworthy end-to-end turn that can be traced, independently verified, and safely undone.

## Product Hunt demo acceptance test

Use a fixture application containing a working login flow.

1. Ask an agent to modify the login implementation.
2. Capture the user request, model/tool trail, and real Git changes.
3. Introduce one detectable security regression in the changed lines.
4. Run the real build and test suite.
5. Display a concise result card.
6. Undo the complete turn.
7. Prove that Git status and tests return to the baseline.

The demo succeeds only if a new user can understand the result and undo the turn without reading raw telemetry.
