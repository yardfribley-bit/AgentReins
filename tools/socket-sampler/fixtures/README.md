# socket-sampler fixtures

| file | origin |
|---|---|
| `lsof_linux_recorded.txt`, `ps_linux_recorded.txt` | **Recorded** verbatim from `lsof 4.99.4` / procps `ps` on a Debian box (2026-10-21): a python "agent" (pid 774418) holding a listener, a direct TCP socket, a loopback socket to a local listener on 18891 and a connected UDP socket; its child (774419) in `SYN_SENT`. The listener on 18891 was a plain socket standing in for the audit proxy. |
| `lsof_macos_format.txt`, `ps_macos_format.txt`, `ps_macos_args.txt` | **Hand-written in macOS `lsof -F pcRftPTn` / `ps -o pid=,ppid=,lstart=,comm=` format** (IPv6 brackets, `*:port` unconnected UDP, helper names with spaces, an unrelated Safari process). Not a capture. The real macOS format is exercised live by the CI step `Live socket sampling (macOS)`. |
| `workbuddy-network-routes.jsonl` | **Hand-written** in the exact schema written by `Sources/AgentReins/Resources/workbuddy_network_capture.py::_capture` (route journal). Not a capture. |

Unit tests use these only to check parsing / filtering / merge logic. None of them is evidence.
