# Atlas code-index attribution

AgentReins' project structural index uses the document contract and deterministic
indexing approach described by [`atlas-codeindex`](https://github.com/pacifio/atlas/tree/main/crates/atlas-codeindex):
per-file language, imports, symbols, content hash, structural text, and import-based
importance ranking.

Atlas is Copyright its contributors and is licensed under the Apache License 2.0.
The AgentReins Swift implementation is an independent adaptation which adds Swift,
C, C++, and JVM-family source discovery and does not copy Atlas' Rust parser code.
AgentReins can also read Atlas' `.atlas/codebase-index/docs.json` format when it is
already present in a project.

See the upstream license: <https://github.com/pacifio/atlas/blob/main/LICENSE>.
