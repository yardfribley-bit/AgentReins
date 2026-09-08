# Provider Trust Roadmap

## Product question

AgentReins should help users answer:

> Which company and model actually received my prompts, code, files, and memories?

This matters when an agent uses a third-party API relay. A relay may expose a familiar model name while routing requests to an unknown provider, substituting a cheaper model, or retaining sensitive content.

Provider Trust becomes the fourth product pillar:

> Trace + Verify + Recover + Provider Trust

## What AgentReins should detect

### Configured destination

- Agent and application name.
- Configured model name.
- Configured API base URL.
- Configuration source, such as an environment variable, settings file, shell profile, or agent configuration.
- Whether the endpoint is official, known third-party, local, or unknown.

### Actual network destination

- Request hostname and resolved IP addresses.
- Redirect chain.
- System, environment, and application proxy involvement.
- TLS certificate subject, issuer, validity, and public-key fingerprint.
- IP network owner, ASN, and approximate country or region.
- Connection time and response latency.

### Outbound data exposure

- Whether prompts, source code, files, tool results, memory, credentials, or personal data were included.
- Sensitive-data categories and counts.
- Redacted evidence instead of duplicated secrets.
- The session and turn responsible for the transfer.
- Whether the user was warned before transmission.

### Claimed model versus observed model

- Model selected by the user.
- Model sent in the request.
- Model claimed in the response.
- Provider-specific response metadata.
- Supported context window, tool calling, structured output, and other observable capabilities.
- A probabilistic model-identity confidence score based on repeatable probes.

## Truth and product boundaries

AgentReins must not claim certainty that the evidence cannot support.

- A client can show where data was sent, but cannot prove that a remote server did not retain it.
- A relay can falsify response metadata, including the model name.
- Behavioral fingerprinting can identify inconsistencies, but is not cryptographic proof of model identity.
- TLS proves control of a hostname, not the honesty or data-retention behavior of its operator.
- Geographic IP data is approximate.
- Encrypted payload inspection requires an explicit supported integration; AgentReins must not silently install a root certificate or weaken TLS.

## Trust classifications

| Classification | Meaning |
| --- | --- |
| Official | Destination and TLS identity match a maintained official-provider registry. |
| Known relay | The endpoint is a recognized intermediary and is clearly disclosed to the user. |
| Local | The endpoint resolves to the local device or an explicitly trusted local network service. |
| Unknown | Ownership or routing cannot be established with sufficient evidence. |
| Mismatch | Configured, requested, claimed, and observed identities materially disagree. |

The registry must be versioned, signed, auditable, and overrideable by the user. An official endpoint does not automatically mean that every request is safe.

## User-facing connection report

The primary report should remain understandable without networking knowledge:

```text
Selected model        Claude 4.1 Opus
Configured endpoint   api.example-relay.cn
Actual destination    Singapore · Unknown hosting provider
Official endpoint     No
Proxy detected        Yes
Sensitive data sent   3 source files; 1 credential was redacted
Claimed model         Claude 4.1 Opus
Model confidence      Low
Retention policy      Unknown

Risk: Your code and prompts were sent through an unverified relay.
```

Detailed DNS, IP, ASN, certificate, headers, timings, and evidence should be available in an expandable technical view.

## Implementation plan

### P0 — Destination transparency

1. Add `ProviderEndpoint`, `NetworkDestination`, `OutboundExposure`, and `ModelIdentityAssessment` records.
2. Discover base URLs and models from supported agent configuration without collecting API-key values.
3. Build a maintained registry for official OpenAI, Anthropic, Google, OpenRouter, and supported local endpoints.
4. Record hostname, resolved address, redirect chain, TLS identity, and proxy presence for observed model calls.
5. Correlate the destination with the agent session and turn.
6. Scan outbound evidence locally and store only redacted categories and counts by default.
7. Display an outcome-first Provider Trust card.

### P1 — Warning and verification

1. Warn before high-sensitivity content is sent to a non-official or unknown endpoint.
2. Add signed registry updates and user-defined trusted endpoints.
3. Add ASN, operator, jurisdiction, and published retention-policy evidence.
4. Compare selected, requested, and response-claimed model identities.
5. Run opt-in, low-cost capability probes and report confidence with supporting evidence.
6. Detect unexpected endpoint, certificate, and routing changes over time.

### P2 — Policy enforcement

1. Allow policies such as “Never send source code to unknown relays.”
2. Block or require approval for high-risk outbound transfers where the integration supports preflight control.
3. Support enterprise-managed provider registries and policies without changing the consumer product into a server-security product.

## Acceptance criteria

- A user can identify the configured and actual destination of a supported model request.
- Official, relay, local, unknown, and mismatch states are visually distinct.
- Sensitive content is classified locally and raw secrets are not copied into AgentReins logs.
- Every claim shows its evidence source and confidence.
- Unknown data is labeled unknown rather than inferred as fact.
- Model identity is never presented as guaranteed unless a future provider supplies verifiable attestation.
- Monitoring can be removed without leaving proxy, certificate, or agent configuration changes behind.

## Initial development slice

Start with configuration discovery and passive destination reporting for WorkBuddy. Do not begin with TLS interception or universal traffic capture. The first credible milestone is:

> AgentReins identifies that a WorkBuddy session used a non-official relay and explains what categories of user data may have been exposed.
