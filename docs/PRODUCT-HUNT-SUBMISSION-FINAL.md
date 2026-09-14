# AgentReins — Product Hunt Submission

## Submission fields

**Product name**

AgentReins

**Primary URL**

https://www.chuhaijian.com/

**Tagline**

> See what your AI coding agents do—and where your data goes

**Description (under 260 characters)**

> AgentReins is a local-first macOS security console for AI coding agents. It connects prompts, model routes, tools, processes, network activity, file and memory changes into an evidence-backed live task—with honest confidence labels.

**Pricing**

Free

**Status**

Available now / Alpha

**Product X account**

https://x.com/agentreins

**Topics**

1. Artificial Intelligence
2. Developer Tools
3. Security
4. Privacy
5. Mac

Use only the closest topics that Product Hunt currently offers. Prefer the first three if the form limits the number.

## Gallery order

1. `01-live-console.png` — See every active agent and its current task.
2. `02-evidence-chain.png` — Follow the task from human intent to machine impact.
3. `03-provider-trust.png` — Know which provider or relay received your context.
4. `04-memory-and-code.png` — Inspect persistent memory changes and code findings.
5. `05-evidence-not-guesses.png` — Make evidence gaps visible instead of filling them with guesses.

All gallery images are 1270×760. Use the square 240×240 logo as the thumbnail.

## Maker comment

Hi Product Hunt — I built AgentReins because AI coding agents could change my machine faster than I could understand what they had done.

A short request can cause an agent to assemble a much larger model context, read memory and project files, call tools and MCP servers, spawn execution processes, connect to model relays, and modify code. Yet the user often sees only one sentence: “Done.”

I did not want another event counter or raw log viewer. AgentReins reconstructs supported agent activity into one evidence-backed live task:

**Request → context → model route → tools → processes → network and files → result**

You can inspect the runtime components behind an agent, see captured context categories and tool calls, review network destinations and relay evidence, follow file and persistent-memory changes, and inspect local code findings. Evidence stays on the Mac by default.

The trust model matters to me: “observed” does not mean “safe,” an agent saying it finished does not mean the outcome was independently verified, and a relay claiming a model name does not prove the upstream model's identity. When AgentReins cannot prove something, it says **Unknown**.

This is an Alpha and the repository includes the current limitations. Today I would especially value feedback on:

1. Which coding agent should we support most deeply next?
2. Which evidence would make you trust—or reject—an agent task?
3. Is the live task understandable without reading raw logs?

Thank you for trying it and for challenging the assumptions behind it.

## Short first reply

One design decision I would love feedback on: AgentReins separates **Observed**, **Inferred**, and **Confirmed** evidence. Security dashboards often hide uncertainty, but showing uncertainty can make the interface feel less decisive. Would you rather see the honest evidence gap immediately, or only after opening the details?

## FAQ responses

### Is this an antivirus?

No. AgentReins is a local visibility and trust layer for personal AI coding agents. It connects agent activity with local runtime, network, file, code, and memory evidence. It does not replace endpoint protection, Git, or code review.

### Does it read hidden chain-of-thought?

No. It can show model content that an agent saves locally or exposes through a supported adapter. It cannot read private server-side reasoning that was never returned to the client.

### Can it identify the real model behind a relay?

It can identify the configured gateway, observed network destination, claimed model, context exposure, and supporting confidence. A relay's claim is not cryptographic proof of the upstream model.

### Does my evidence leave the Mac?

Evidence is local by default. Optional model-assisted analysis only runs when the user configures an external OpenAI-compatible endpoint.

### Which agents are supported?

The current build discovers and profiles several macOS coding agents, with deeper evidence depending on each agent's local interfaces and adapter coverage. The UI reports evidence coverage rather than claiming universal capture.

### Is Windows supported?

Not in this Alpha release. The current downloadable product is macOS-first.

## Launch-day posts

### X

> AgentReins is live on Product Hunt.
>
> AI coding agents can read memory, send code to model relays, call MCP tools, run commands, and change files in seconds. AgentReins turns that activity into one evidence-backed live task—locally on your Mac.
>
> I would value your honest feedback: [PRODUCT HUNT URL]

### LinkedIn

> Today I am launching AgentReins on Product Hunt.
>
> I built it around a simple problem: AI coding agents can act faster than users can understand their logs. AgentReins connects the user request, captured model context, tools, processes, network destinations, file changes, memory activity, and result into one readable task.
>
> It is local-first, macOS-first, open source, and honest about evidence gaps. I would appreciate feedback from people who use coding agents in real projects: [PRODUCT HUNT URL]

## Final checklist

- Verify both macOS downloads from a clean Mac.
- Confirm the website, privacy page, GitHub, email, and X links.
- Upload the English demo to YouTube at least 12 hours before adding it to Product Hunt; set it to Public or Unlisted with embedding enabled.
- Upload the square thumbnail and gallery images in the documented order.
- Use a personal Product Hunt account and add yourself as Maker.
- Create a draft first; do not schedule until every preview field is checked.
- Schedule for the intended date; Product Hunt days begin at 12:01 AM Pacific Time.
- Publish the Maker comment immediately after launch.
- Respond personally and specifically. Do not use automated or generic AI comments.
- Never ask for coordinated or purchased votes.
