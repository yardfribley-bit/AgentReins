# ESC mutation survivor (en_26fd4180)

`tools/mutate_esc_calls.cjs` result: **58/59 killed**, 1 survivor.

| Site | Mutated call | Equivalence rationale |
|------|--------------|------------------------|
| `risk-alerts.js` ~detail template `data-risk-id="${esc(a.id)}"` | `esc(a.id)` → bare `a.id` | `a.id` is always the internal alert key from `buildAlerts()` (`${rule}:${path}` or rule-scoped synthetic id). Values are `[A-Za-z0-9_./:-]+` only; probes with `<>"'&` never enter `a.id`. Attribute context still receives a non-metacharacter token, so deleting `esc()` does not change DOM text nodes or introduce HTML/script (mutation test passes). |

All other 58 `esc(` sites feed user/agent/transport/MCP/audit strings and are killed by the data-driven XSS test when `esc()` is removed.
