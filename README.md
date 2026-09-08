# AgentReins for macOS

AgentReins is a local-first safety and transparency center for personal AI agents. It connects user intent, captured model context, model responses, tool and MCP calls, execution results, file changes, and memory activity into a readable session timeline.

## Product principles

- Show what the agent is doing without turning normal activity into an alarm.
- Explain who acted, what happened, why it matters, and what the user should do.
- Keep monitoring records, protection rules, and recovery data on the device.
- Preserve raw evidence and label missing evidence instead of guessing.
- Make file mistakes recoverable whenever possible.

## Current capabilities

- Native macOS menu bar app and security center.
- WorkBuddy session discovery through the AgentSight local session adapter.
- Per-turn model, context length, token usage, tool calls, results, and memory activity.
- Optional AI summaries using the user's OpenRouter key and selected model.
- Process and protected-file monitoring.
- Natural-language protection rules.
- Sensitive-data scanning for local agent memory.
- Recovery records for protected files.

## Build

```bash
swift build
./package_app.sh
```

The packaged application is written to `AgentReins.app`.

## Development roadmap

See [Trace, Verify, Recover — Development Roadmap](docs/TRACE-VERIFY-RECOVER-ROADMAP.md) for the prioritized capability gaps, acceptance criteria, and next implementation sequence.

- [Provider Trust Roadmap](docs/PROVIDER-TRUST-ROADMAP.md)
- [Product Hunt Launch Plan](docs/PRODUCT-HUNT-LAUNCH.md)

## Distribution

Development builds use an ad-hoc signature. A public build that opens normally on other Macs requires an Apple Developer ID Application certificate and Apple notarization.

## Current limitations

- Command monitoring uses process snapshots and is not a universal pre-execution interceptor.
- File protection uses backups and recovery rather than kernel-level authorization.
- WorkBuddy logs expose only the context the agent writes to disk; this may be smaller than the complete request reported by model token usage.
- Endpoint Security enforcement requires Apple approval, the relevant entitlement, Developer ID signing, and notarization.

## Privacy

Agent activity is stored locally. AI summaries are opt-in. Before evidence is sent to OpenRouter, AgentReins redacts common API keys, tokens, passwords, and private-key blocks on the device.
