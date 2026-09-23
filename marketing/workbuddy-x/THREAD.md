# WorkBuddy Data Egress — X Thread

## Post 1 — Hook + image

One short prompt.

82,433 input tokens.

We asked WorkBuddy for a WeChat publishing skill. Before its first action, it sent an upstream model long-term memory, identity files, chat history, tool calls, and local environment data.

What else left the machine? 🧵

Attach: `workbuddy-82433-tokens.png`

## Post 2

The prompt was a single sentence.

The request was not.

AgentReins found:
• Cloud + user memory
• SOUL.md, IDENTITY.md, USER.md
• 21 prior user messages
• 58 assistant messages
• 72 tool calls
• local paths, connector status, and project context

## Post 3

The first request contained 82,433 input tokens. 80,896 were marked as cached.

Later requests grew to 86,335, 88,200, then 91,152 tokens — even without another long user message.

Tool results and intermediate turns kept expanding the context sent upstream.

## Post 4

This is not proof that WorkBuddy stole passwords. We found no plaintext password in the captured prefix.

It is evidence of something broader: excessive context sharing, weak data minimization, and blurred boundaries between projects.

Convenience has an exposure radius.

## Post 5

There is also a forensic blind spot.

WorkBuddy's local trace stops at exactly 100,002 characters, mid-history. But model usage reports 82,433 input tokens.

So we can prove what appeared in the captured prefix — not everything the upstream model received.

## Post 6

Every AI agent should show a data egress manifest before sending:

What is included?
Where did it come from?
Who receives it?
Why is it needed?
What is missing from the audit trail?

That is what we're building with AgentReins.

https://github.com/yardfribley-bit/AgentReins

## Posting Notes

- Post the first item with the image; add the remaining five as replies.
- Do not place the GitHub link in the first post.
- Keep hashtags out of the thread. The subject matter and keywords already provide context.
- Suggested posting window: when the account can reply to early comments for the first hour.
- Pin the strongest evidence question in replies: `Would you allow an agent to send this context if it showed you the manifest first?`

## Optional Standalone Version

One short prompt triggered 82,433 input tokens.

Our local trace of WorkBuddy showed long-term memory, identity files, chat history, tool calls, project context, and machine details inside the upstream model request.

This is not proof of password theft. It is evidence that AI agents need data minimization — and a data egress manifest users can inspect before anything leaves the machine.

Full investigation: https://www.chuhaijian.com
