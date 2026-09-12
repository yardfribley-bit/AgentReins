# Development Plan — September 12, 2026

> Scope update: Web Agent Security P0 now prioritizes poisoned external content through execution and code consequences. Historical page fingerprint/change detection is deferred. See `WEB-AGENT-SECURITY-P0.md`.

## Objective

Strengthen AgentReins as a zero-trust evidence layer for coding agents. The day is focused on reliable data, correlation, and security conclusions—not visual redesign.

By the end of the day, one WorkBuddy task should produce a durable evidence chain:

```text
User requirement
  -> context sources
  -> model decision
  -> Tool / MCP / Skill
  -> process and network destination
  -> generated or modified code
  -> security findings
  -> independent requirement verification
```

Every link must be labeled `Captured`, `Confirmed`, `Inferred`, or `Unavailable`.

## P0 deliverables

### 1. Unified trust-boundary event model

Add or normalize evidence records for:

- Tool, MCP, and Skill identity, source, version, arguments, result, and observed capabilities.
- External destinations: domain, IP, port, ASN, network owner, cloud/hosting provider, country/region, TLS identity, and reputation result.
- Context inputs: user, agent instruction, project rule, memory, local file, external website, MCP response, Skill, and provider-unknown content.
- Generated code, including inline code that never reaches the project filesystem.
- Requirement, acceptance criterion, verification command, evidence, and outcome.

Acceptance criteria:

- All records carry session, turn, call, process, source, timestamp, and confidence fields when available.
- Missing values remain explicit; no timestamp-only attribution is presented as fact.
- Sensitive payloads are redacted before persistence.
- Existing event files remain readable after schema changes.

### 2. WorkBuddy Tool / MCP / Skill inventory and risk snapshot

Build a WorkBuddy-native inventory from local session and installation evidence.

Record:

- Tool type and exact name.
- Package or built-in source.
- Version and installation path.
- File, process, network, credential, and memory capabilities observed during the task.
- Package/content fingerprint so later changes can be detected.
- Risk findings with evidence and scanner version.

Acceptance criteria:

- The weather task identifies `Bash`, `read_me`, and `show_widget` separately.
- Tool arguments and results remain connected by `toolCallId`.
- A remote script introduced by generated Widget code is attached to the generating tool call.
- Tool capability is described as observed or declared, never assumed permission.

### 3. External destination enrichment v1

Enrich non-model destinations first. Keep model-provider and telemetry endpoints visible but de-emphasized.

Record:

- Domain from tool arguments or proxy evidence.
- Process-owned remote IP and port.
- ASN, organization/network owner, cloud or hosting provider, and country/region.
- TLS certificate subject/issuer where safely obtainable.
- First seen, last seen, occurrence count, and whether the destination is new for this Agent/project.
- Reputation provider, result, checked-at time, and cache expiry.
- Provenance: `tool argument`, `proxy port join`, `DNS`, or `IP only`.

Acceptance criteria:

- `wttr.in` is recorded as the weather task's external content source even when the socket exposes only an IP.
- Domain evidence from a tool argument does not claim an exact socket match.
- Unknown IPs still produce a useful ownership/location record.
- Enrichment uses a bounded local cache and never blocks the live event path.
- No URL path, header, body, cookie, or credential is sent to an intelligence provider.

### 3A. Repository intake safety v1

Treat every repository selected, downloaded, or cloned by an Agent as untrusted until inspected. This is a pre-execution gate, not a claim that static scanning can prove a repository safe.

Record and inspect:

- Repository URL, owner, visibility, requested ref, resolved commit SHA, and acquisition method.
- Account/repository age, archived state, recent ownership or maintainer changes, release signing, commit-signature evidence, and OpenSSF Scorecard results where available.
- Checked-in binaries, archives, executable files, symlinks, Git LFS pointers, submodules, and external submodule hosts.
- Package lifecycle scripts such as `preinstall`, `postinstall`, setup/build hooks, Make targets, Gradle tasks, and shell bootstrap scripts.
- `.github/workflows`, `.devcontainer`, editor tasks/settings, Copilot hooks, and other files that may execute after the repository is opened or pushed.
- Dependency manifests and lockfiles for OSV-based vulnerability checks.
- Static code, secret, malware/YARA, and generated artifact findings through provider interfaces.

Safe acquisition sequence:

```text
Repository requested
  -> metadata and immutable commit resolved
  -> content downloaded into quarantine without execution
  -> archive/path traversal and symlink validation
  -> static, dependency, workflow, and malware scans
  -> explicit trust result
  -> open/install/build only after policy allows it
```

Acceptance criteria:

- AgentReins records the exact commit that was inspected; a branch name alone is insufficient.
- No package manager, build script, Git hook, editor task, dev container, or repository binary runs during inspection.
- Submodules and LFS objects are listed before they are fetched.
- Scanner failure or unavailable reputation is reported as `Unavailable`, never `Safe`.
- High-confidence malware, unsafe lifecycle execution, path escape, or secret-exfiltration behavior blocks execution in protection mode.
- The report distinguishes repository-maintenance posture, known vulnerabilities, suspicious code, confirmed malware signatures, and runtime behavior.

### 4. Context provenance and safety v1

For every WorkBuddy model turn, record the context components visible in the local session evidence:

- Original user request.
- Agent/system reminders recorded locally.
- Project instructions and rules.
- Memory retrievals.
- Skill or internal knowledge reads.
- MCP/tool results.
- External website content.
- Model, input/output/cached/reasoning token counts.

Checks:

- Sensitive data exposure.
- Untrusted instructions and authority impersonation.
- Requirement loss or conflict.
- Repeated/stale payloads and context growth.
- Low-trust content preceding a sensitive tool action.

Acceptance criteria:

- The weather task distinguishes LLM generation, `wttr.in` data, `read_me(chart)` knowledge, prompt-cache usage, and tool execution.
- Locally recorded context is not labeled as the provider's complete final request.
- Every external or persistent context component retains its source identity and trust level.

### 5. Generated-code security pipeline

Use the same finding model for project files and non-persisted code.

Initial coverage:

- Shell/Python heredocs and commands.
- HTML/JavaScript Widget payloads.
- Source-file diffs.
- Hard-coded secrets, command/SQL/DOM injection, dynamic execution, disabled TLS verification, unsafe deserialization, unsafe permissions, and remote script dependencies.

Acceptance criteria:

- The existing weather Widget produces the `remote-script` finding for the Chart.js CDN dependency.
- The finding records artifact type, generating tool, line, evidence, severity, engine, and rule version.
- Findings are review signals, not claims of exploitability.
- Previously stored events can be enriched once without creating duplicate events or a polling loop.

### 6. Requirement completion evidence v1

Create a deterministic requirement record before execution and verify it independently after completion.

Record:

- Original requirement.
- Extracted acceptance criteria and whether the extraction is deterministic or model-assisted.
- Agent-claimed result.
- Independent evidence: files, diff, build/test command, exit code, output, external result, and final state.
- Outcome per criterion: `Verified`, `Failed`, `Not verified`, or `Not applicable`.

Acceptance criteria:

- A task cannot be labeled complete solely because the Agent says it is complete.
- The weather task verifies that current data was retrieved, parsed, rendered, and answered, while separately reporting source freshness and code findings.
- Coding tasks distinguish pre-existing changes from Agent-created changes.

## Schedule

### 09:00–09:45 — Baseline and fixtures

- Freeze the current desktop and source baseline.
- Capture a sanitized WorkBuddy weather fixture.
- Add fixtures for a benign tool, suspicious MCP result, malicious Skill instruction, unsafe generated code, and incomplete coding requirement.
- Record idle and active CPU baselines.

### 09:45–11:15 — Unified evidence schema

- Implement the normalized trust-boundary and provenance fields.
- Add backward-compatible decoding and migrations.
- Add unit tests for evidence confidence and redaction.

### 11:15–12:30 — WorkBuddy supply-chain inventory

- Implement Tool/MCP/Skill identity and version extraction.
- Add fingerprints and observed-capability aggregation.
- Verify the weather task's three distinct tools.

### 13:30–15:00 — Destination enrichment

- Implement cached IP/ASN/owner/location enrichment behind a provider interface.
- Preserve exact provenance for domain and socket evidence.
- Add offline fixtures so tests do not depend on live intelligence services.

### 12:30–13:00 — Repository intake design and fixture

- Define the repository acquisition and immutable-commit evidence model.
- Add one benign repository fixture and one harmless simulated malicious-repository fixture.
- Detect lifecycle scripts, binaries, submodules, executable entry points, and auto-run configuration without executing them.

### 15:00–16:15 — Context provenance and safety

- Normalize context-source events.
- Add trust labels, token contribution, and context-growth findings.
- Verify the weather task's LLM, website, knowledge, cache, and tool sources.

### 16:15–17:15 — Code and requirement verification

- Complete inline generated-code finding metadata.
- Add acceptance-criterion records and deterministic verification results.
- Run controlled safe and unsafe task fixtures.

### 17:15–18:30 — Quality and release gate

- Run the full unit-test suite with zero failures and zero warnings.
- Run a live WorkBuddy acceptance task.
- Measure startup, idle, and active CPU; reject sustained regressions.
- Verify bounded event growth and no duplicate enrichment loop.
- Package and verify Universal 2 (`arm64` and `x86_64`) and code signature.
- Install the desktop build only after all gates pass.
- Publish a focused English commit and require GitHub CI to pass.

## Performance gates

- Idle average CPU: below 1% after startup settles.
- Active monitoring average CPU: below 5% for an ordinary WorkBuddy turn.
- Sustained CPU above 15% for 10 seconds: release failure.
- Intelligence lookup must not run on the main actor or block event ingestion.
- Destination and reputation results must use TTL caches.
- No full-history reconstruction at startup.

## Security and privacy gates

- Local-first persistence remains the default.
- No API key, cookie, full prompt, URL path, or response body is sent to destination-intelligence services.
- External enrichment failures degrade to `Unavailable`, never to `Safe`.
- Reputation results include provider and timestamp.
- Generated-code findings preserve evidence while redacting secrets.
- AgentReins does not claim access to provider-side hidden prompts or hidden reasoning.

## End-of-day acceptance demo

Run one WorkBuddy task that retrieves external content and generates code. AgentReins must produce a machine-verifiable report containing:

1. The user's requirement.
2. Locally captured model-context components and token usage.
3. Tool, MCP, and Skill identities with observed capabilities.
4. External domain, IP, ownership/location enrichment, and reputation status.
5. Generated and modified code artifacts with security findings.
6. Memory reads and writes, if any.
7. Requirement criteria with independent outcomes.
8. A complete evidence-confidence explanation for every inferred or unavailable link.

## Explicitly deferred

- Frontend redesign and visual polish.
- Universal HTTPS interception or CA installation.
- A general-purpose LLM Gateway.
- Automatic cross-Agent memory sharing.
- Default blocking based on heuristic findings.
- Windows implementation beyond keeping the schema portable.

## Release statement allowed after completion

> AgentReins locally connects a WorkBuddy task to its recorded context, tools, external destinations, generated code, and independently verified outcomes, with explicit evidence confidence at every trust boundary.
