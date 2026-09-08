# AgentReins for macOS

AgentReins is a local-first safety and transparency center for personal AI agents. It connects user intent, captured model context, model responses, tool and MCP calls, execution results, file changes, and memory activity into a readable session timeline.

> See what your AI agent changed. Verify it. Undo it.

## Repository layout

```text
.
├── Sources/AgentReins/   macOS application source
├── Assets/               packaged application assets
├── AppIcon.iconset/      source icon sizes
├── docs/                 architecture and product roadmaps
├── Package.swift         Swift Package Manager manifest
└── package_app.sh        local application packaging script
```

Start with [the architecture guide](docs/ARCHITECTURE.md) to understand how agent evidence becomes a session timeline.

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

Requirements: macOS 13 or later and Xcode Command Line Tools.

```bash
swift build
./package_app.sh
open AgentReins.app
```

The packaged application is written to `AgentReins.app`.

## Development roadmap

- [Architecture](docs/ARCHITECTURE.md)
- [Trace, Verify, Recover Roadmap](docs/TRACE-VERIFY-RECOVER-ROADMAP.md)
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
