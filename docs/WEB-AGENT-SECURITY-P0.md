# Web Agent Security P0

## Product decision

The immediate goal is not continuous website-version monitoring. AgentReins must first protect a user when an AI agent consumes poisoned external content and then downloads, executes, or changes code because of it.

## P0 user outcome

For a supported AI agent turn, AgentReins must answer:

1. Which external websites or files did the agent discover, recommend, open, or read?
2. What page or tool-result content was made available to the agent?
3. Did that content contain instructions associated with prompt injection, credential access, unsafe execution, persistence, or safeguard bypass?
4. What tool, MCP, Skill, shell, network, download, Git, or file action happened afterward?
5. Which relationship is confirmed, inferred, or unavailable?
6. What code or local state changed, and what did the local security scanner find?

The target evidence chain is:

```text
user request
  -> agent/model turn
  -> external URL or file
  -> captured external content
  -> content security findings
  -> later tool and network activity
  -> download / execution / Git operation
  -> generated or modified code
  -> local findings and user-readable result
```

## P0 scope

- Browser evidence for explicitly supported web agents.
- URLs and external content returned by WorkBuddy, Codex, MCP, Skill, search, fetch, and shell tools when locally observable.
- Exact session, turn, tool-call, tab, process, and resource provenance where available.
- Prompt-injection and unsafe-instruction screening of captured external content.
- GitHub URL and clone identity normalization.
- Download, command execution, network destination, and workspace-change correlation.
- Credential references and potential secret-exfiltration behavior visible in locally captured evidence.
- Generated-code and changed-file scanning.
- A deterministic risk result that never labels unavailable evidence as safe.

## P0 acceptance scenarios

### Poisoned page causes execution

A fixture page returns a harmless simulated injection that asks the agent to run a marker command. AgentReins must record the page evidence, finding, later command, process/network evidence when present, and changed test file under one turn. No real payload or credential is used.

### Model recommends a poisoned repository

A model response contains a controlled GitHub-style repository URL. A simulated clone contains an unsafe lifecycle command. AgentReins must connect recommendation, acquisition, inspection finding, attempted execution, and local consequence.

### Benign external lookup

An agent reads a benign page and performs no sensitive action. AgentReins records the external resource and reports no detected high-signal finding without claiming that the page is proven safe.

### Attribution ambiguity

Two turns or tool calls overlap. AgentReins must leave the consequence unattributed unless an exact identifier, process tree, workspace path, or unique bounded correlation supports the join.

## Explicitly deferred

The following capabilities are recorded for later work and are not P0 blockers:

- Continuous page-content fingerprinting and historical change detection.
- Semantic explanations of cosmetic versus behavioral page changes.
- Full third-party script and iframe inventory for ordinary browsing.
- Automatic re-verification solely because a previously visited page changed.
- Broad monitoring of every page a user visits in Chrome.
- Website reputation scoring that is not required to prove the external-content-to-action chain.

These features become valuable after the evidence chain above is reliable. Content hashes may still be stored when cheaply available, but P0 must not depend on historical page comparison.

## Evidence rules

- Raw evidence remains local and append-only.
- Captured content is distinct from provider-hidden prompts or reasoning.
- A later action in the same turn is correlation, not proof that the content caused it.
- An unavailable page body, tool result, network destination, or process owner is shown as `Unavailable`.
- Detection means a reviewable finding, not a claim that a page is malicious or an exploit succeeded.

