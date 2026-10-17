<div align="center">
  <p><strong>English</strong> · <a href="README.zh-CN.md">简体中文</a></p>
  <img src="Assets/agentreins-logo.png" width="144" alt="AgentReins logo">

  <h1>AgentReins</h1>

  <p><strong>See what a local coding agent sent out, and what came back.</strong></p>

  <p>A local-first macOS app for WorkBuddy, Codex, and Cursor.</p>

  <p>
    <img alt="Platform: macOS 13+" src="https://img.shields.io/badge/macOS-13%2B-111111?logo=apple">
    <img alt="Swift 6" src="https://img.shields.io/badge/Swift-6-F05138?logo=swift&logoColor=white">
    <img alt="Status: Alpha" src="https://img.shields.io/badge/status-alpha-F59E0B">
    <img alt="Local-first" src="https://img.shields.io/badge/privacy-local--first-2563EB">
  </p>
</div>

AgentReins keeps the evidence on this Mac. It shows the task an agent is working on, each outbound visit, and the file a download actually wrote. It does not change the system proxy or the system trust store.

Website: [chuhaijian.com](https://www.chuhaijian.com/)

## What you can look at

The realtime window has two views that matter first.

**任务过程.** The original request, where the task is now, what the model asked for, what actually ran, and retries that were kept.

**外网访问.** A list you can scan:

| Column | What it shows |
| --- | --- |
| 时间 | When this visit happened |
| 谁 | The tool or model call |
| 去了哪里 | Host, or “远程访问工具” / “模型服务” |
| 协议 | HTTP version, model, tool call, encrypted channel, or package |
| 结果 | What happened: 通了, 对方返回 502, 证书没配好, 下载了 name, 带走了 name |

Open a row. **送出** and **收回** appear directly under that row. An empty request is written as 没有送出正文. An empty response is 正文是空的. A web page is shown as 网页《title》 plus a short lead. Certificate text, `CONNECT`, and credentials stay out of those two panels. The raw protocol lines stay folded under 协议原文.

A download from wget, curl, or brew shows the file that landed: name, size, and SHA-256. The hash is of the file on disk. The page does not dump the file bytes.

A remote tool such as WebFetch shows the exchange between this machine and the tool: what was submitted, and what the tool returned. The tool’s own later fetch of a website is not a connection from this Mac.

## What is not claimed

- Traffic that ignores the agent proxy, pins a certificate, or uses QUIC never enters the record.
- SSH, SCP, SFTP, and rsync channel bytes stay encrypted. The row says 看不到通道里的内容.
- Git pack bytes are not reconstructed. A push can show the file names that would leave.
- A visit is not assigned to a tool call by clock time. If the call is unknown, the panel says 还没对上哪次工具调用.
- Query strings are removed before they are stored.
- A file larger than 32 MB keeps its size and skips the hash.
- WorkBuddy and Codex that are already running do not see a new command wrapper until they are fully quit and opened again.
- AgentReins does not decide that a coding task is finished, and it does not scan memory for poisoning. Those stay off this page.

Missing evidence stays missing. The app does not invent a body, a host, or a tool call.

## Privacy

Records stay under this user account. The audit proxy listens only on `127.0.0.1:18891`. It is started by AgentReins and stops when AgentReins quits. Normal Terminal windows are not pointed at it. Agent processes that load `~/.agentreins/audit.sh` use that proxy and the local mitmproxy certificate. The system proxy and the system trust store are left alone.

## Build

Requirements: macOS 13 or later, Xcode Command Line Tools, and a Swift 6 toolchain. Install `mitmdump` if you want HTTPS bodies.

```bash
git clone https://github.com/yardfribley-bit/AgentReins.git
cd AgentReins
./scripts/package_realtime.sh
open ".build/realtime-preview/AgentReins Realtime.app"
```

To wrap wget, curl, git, brew, and the other audited commands inside WorkBuddy, Codex, and Cursor:

```bash
python3 scripts/install_codex_transport.py
```

Then quit those apps completely and open them again. A shell that is already running keeps its old functions.

## Layout

```text
Sources/AgentReins/                         macOS app
Sources/AgentReins/Resources/RealtimeWorkspace/   task and network pages
Sources/AgentReins/Resources/workbuddy_network_capture.py
tools/transport-audit/                      command capture for curl, wget, git, brew, ssh
scripts/package_realtime.sh                 build the realtime app
scripts/install_codex_transport.py          install the agent-only audit shell
docs/                                       architecture and roadmaps
```

Further reading: [Architecture](docs/ARCHITECTURE.md), [Data collection](docs/DATA-COLLECTION-ARCHITECTURE.md), [Trace, verify, recover](docs/TRACE-VERIFY-RECOVER-ROADMAP.md).

## License

No open-source license is included yet. The source is public so it can be read. That does not grant the right to copy it into another product.

## Issues

Open an issue when a visit on this machine cannot be explained from the page: who sent it, where it went, what left, and what came back. Do not paste API keys, tokens, or private prompts.
