# Product Hunt Launch Plan

## Launch objective

Position AgentReins as the consumer trust layer for personal coding agents, not as another security-event dashboard.

The launch must demonstrate that a normal user can understand what an agent did, independently verify the result, identify where their data went, and recover from a bad change.

## Product name

**AgentReins**

## Tagline candidates

Primary:

> See what your AI agent changed. Verify it. Undo it.

Provider-trust variant:

> Know what your AI agent changed — and which AI received your code.

Short variant:

> Trust, verify, and undo your AI agents.

## One-sentence description

AgentReins is a local-first macOS safety companion that turns coding-agent activity into a clear timeline, independently checks code changes, reveals model relays and sensitive data exposure, and helps users undo a bad agent turn.

## Product Hunt description

Coding agents can edit hundreds of files, run tools, access memory, and send private context to model providers in seconds. Their logs are built for developers and rarely answer the questions users actually have: What changed? Did it work? Where did my data go? Can I undo it?

AgentReins creates a readable record of each agent turn—from the user's request and captured model exchange to tool calls, file changes, verification results, and memory activity. It independently runs build, test, and security checks, distinguishes agent changes from existing work, warns about unverified model relays, and provides a safe recovery path.

Monitoring stays local by default. Missing evidence is labeled as unknown rather than replaced with a confident guess.

## The launch promise

AgentReins should prove four things:

1. **Trace** — Show what the user asked and what the agent actually did.
2. **Verify** — Check the resulting code independently of the agent's own success claim.
3. **Recover** — Preview and undo the complete set of changes from one agent turn.
4. **Provider Trust** — Show which endpoint received the user's prompts, code, files, and memory.

## Target user

The primary launch user is a consumer or independent builder using coding agents on a personal Mac. They want the productivity of autonomous tools without needing to understand raw JSON, shell telemetry, model-routing infrastructure, or security rules.

## User pains to demonstrate

- “I cannot tell what the agent is doing.”
- “The agent says it finished, but I do not know whether the code works.”
- “I do not know which files it changed or whether it damaged my existing work.”
- “I cannot safely undo one complete agent task.”
- “I do not know what prompt, code, memory, or private data was sent to a model.”
- “My API relay claims to use an expensive model, but I cannot verify the claim.”
- “Security tools show too many events and do not explain the outcome.”

## Hero-section copy

### Headline

> Your AI agent moves fast. AgentReins makes it accountable.

### Subheadline

> Follow every request, model call, tool action, code change, and data destination. Independently verify the result—and undo the turn when something goes wrong.

### Primary call to action

> Download for macOS

### Secondary call to action

> Watch the 60-second demo

## Launch demo

The demo should tell one complete story instead of touring every screen.

1. A user asks a coding agent to modify a login flow.
2. AgentReins shows the request and live progress in plain English.
3. The agent changes several files and introduces a security regression.
4. AgentReins attributes the changes to the correct turn.
5. Independent build and tests run; the agent's claim is shown separately.
6. Diff-scoped scanning identifies the introduced issue.
7. Provider Trust reveals that the prompt and source files passed through an unverified relay.
8. The user previews and performs `Undo this turn`.
9. AgentReins verifies that Git status and tests returned to the baseline.

The audience should understand the result without opening raw evidence.

## Required launch screenshots

1. Outcome card: request, changed files, tests, security result, data destination, and Keep/Undo actions.
2. Turn timeline: user request to model, tools, filesystem, and final result.
3. Code-change evidence: accurate Git diff with agent-introduced findings.
4. Provider Trust: official versus unverified relay and redacted data exposure.
5. Recovery preview: files that will be restored, removed, or recreated.

Use restrained American consumer-product styling: clear hierarchy, generous spacing, short copy, calm colors, and one strong action per screen. Avoid dense SOC dashboards, unexplained severity counters, terminal-first screenshots, and fear-based copy.

## First comment draft

Hi Product Hunt — we built AgentReins because coding agents could change our machines faster than we could understand their logs.

Most agent tooling records activity. We wanted a product that answers the next questions: What did the agent actually change? Did the result pass an independent check? Where did our code and prompts go? Can we undo the whole turn safely?

AgentReins is local-first and begins on macOS. The first integrations focus on personal coding-agent workflows. It connects intent, model activity, tools, code changes, verification, provider identity, and recovery into one understandable result.

We would especially value feedback on which agent integrations and recovery workflows matter most to you.

## Claims we may publish only after acceptance tests pass

- “Independently verifies agent code changes.”
- “Undo an entire agent turn.”
- “Separates agent changes from your existing work.”
- “Shows where your prompts and code were sent.”
- “Detects unverified model relays.”
- “Runs locally by default.”

Do not publish claims of universal monitoring, guaranteed model identification, guaranteed privacy, complete hidden reasoning capture, kernel-level blocking, or support for agents that have not passed an end-to-end integration test.

## Launch readiness checklist

### Product

- One reliable end-to-end Trace + Verify + Recover workflow.
- WorkBuddy plus at least one widely recognized coding-agent integration.
- Accurate Git changes and separation of pre-existing work.
- Independent build/test evidence.
- Turn-level undo with preview and post-recovery verification.
- Provider destination report with honest confidence labels.
- No empty or misleading “0 events” state when supported activity exists.
- English-only product copy reviewed for consistency.

### Distribution

- Developer ID signed and Apple-notarized application.
- Clean installation on a Mac that has never run the development build.
- Clear permission onboarding and complete uninstall instructions.
- Privacy policy, terms, support contact, and release notes.
- Crash reporting and update behavior explicitly disclosed.

### Launch assets

- Product Hunt thumbnail and gallery images.
- 60-second demo video with captions.
- Landing page with the same promise as the product.
- Founder first comment and prepared FAQ.
- Public repository documentation aligned with implemented capabilities.
- A small set of real beta-user quotes, used only with permission.

### Quality gate

- No launch screenshot uses fixture data without a visible demo label.
- No sensitive prompt or API key appears in analytics, screenshots, logs, or crash reports.
- Every primary claim is backed by a repeatable acceptance test.
- A new user can explain the outcome card after a 60-second demo.

## Proposed Product Hunt topics

- Artificial Intelligence
- Developer Tools
- Privacy
- Security
- Mac

Final topic availability and naming must be checked on Product Hunt before submission.

## Metrics for the first week

- Successful installation rate.
- Time to first captured agent turn.
- Percentage of turns with complete attribution.
- Percentage of turns independently verified.
- Recovery preview and completed-undo rates.
- Provider Trust reports viewed.
- Unknown-relay warnings generated and resolved.
- Crash-free sessions.
- Qualitative feedback: whether users can explain what their agent did.

## Launch decision rule

Do not launch merely because the interface looks finished. Launch when the demo is a truthful representation of the installed product and one complete agent turn can be traced, independently verified, attributed to a provider destination, and safely undone.
