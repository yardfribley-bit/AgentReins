# AgentReins Situational Awareness — Data Coverage

This is the contract between collectors and the UI. A collected field must be visible here or in the complete Evidence Drawer. Missing evidence is shown as missing; it is never inferred silently.

| Evidence family | Overview surface | Complete evidence |
|---|---|---|
| Agent discovery | Agent Assets | product, presence, connection mode, process count; adapter coverage remains available in Agent inventory |
| Live process tree | Process tree | executable/service name, PID, PPID, full command line, observed parent relationship |
| User request | Model context / Live chain | `userIntent`, session, turn, trace |
| Model input | Model context / Live chain | full prompt, model name, input/cached/reasoning tokens and cost |
| Model output | Live chain | response, decision, recorded reasoning where the provider emitted it |
| Tool, Function, Skill, MCP | Tools & MCP | tool name, call ID, arguments/command, result/response and attribution |
| Network | Network | local address, remote host/domain/port, process owner, source and attribution method |
| Files and generated code | Files & code | path, before/after content, diff, code finding rule/title/severity/line/evidence |
| Memory | Live chain / Model context | memory retrieval/commit events, prompt exposure and tool evidence when emitted by the agent adapter |
| Tokens and context growth | Model context | input/output/cached/reasoning token samples, growth percentage, USD cost |
| Collection reliability | Coverage | source state, last success, accepted, malformed, dropped, lag/detail/blind spot |
| Evidence linkage | Every row | agent, session, trace, turn, tool call, process/parent process, confidence and method |
| Raw provenance | Evidence Drawer | event ID, timestamp, rule, operation, severity, action and evidence source |

## Process-tree rule

The UI consumes the complete live process inventory, not only risk or short-lived activity events. Long-running helpers such as Storage Service, NodePeer, language servers, renderers and MCP servers therefore remain visible. Their role is labelled unknown unless native agent evidence or the executable identity confirms it.

## Known boundaries

- Process inventory is a live snapshot. A process that exits between samples can be missed.
- Network sockets are sampled and short connections can be missed. `get_coverage.socketSampling` reports the measured effective interval and an estimated miss rate for a 1.5s connection; that rate is an estimate, not a counted total.
- In-process tools such as Read, Edit, Write and Glob do not spawn a subprocess or open a socket. They are outside system-level visibility. Absence in the socket ledger or the proxy journal is not evidence they did not run.
- Proxy requests are attributed from the kernel socket while the client connection is open. If that lookup fails the record says `via proxy · attribution lost` and does not guess a process. A client-supplied pid header is not accepted.
- Prompts, responses, reasoning and tool results depend on what each native adapter exposes. Transport metadata alone cannot reconstruct encrypted model content.
- Cursor Composer evidence can provide stable session/turn/tool-call linkage, prompt-token categories, user prompts, visible model responses, tool arguments/results, and before/after file contents. The actual model name remains unknown when Cursor records only `default`.
- Recorded reasoning means provider-emitted reasoning data; hidden model chain-of-thought is not available as raw evidence.
