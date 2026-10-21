# 按进程采样全部连接（不依赖代理）· 设计说明

## 要解决的问题
现在"外网访问"只看得到两类流量：读了 `HTTP(S)_PROXY`、经过审计代理（mitmdump，127.0.0.1:18891）的请求；以及经过 `~/.agentreins/audit.sh` 审计入口的命令（curl/git/ssh…）。
下面这些全都看不见：不认代理变量的 Node/Go/Rust 客户端、agent 自己的模型 API 请求、git over ssh、scp、数据库/裸 TCP/UDP、QUIC。
另外，走了代理的流量在套接字层面目的地全是 `127.0.0.1:18891`，会让人误以为"没有外联"。

## 现状（读代码得出）
| 位置 | 作用 | 缺口 |
|---|---|---|
| `tools/transport-audit/auto.py` | PATH 入口包装命令，写 `transport-audit/<run>/manifest.json, transport.json` | 只覆盖 PATH 解析到的命令 |
| `Sources/AgentReins/ProcessGuard.swift` + `NetworkSnapshotProvider.swift` | App 内每 10 秒 `lsof -iTCP` 采 agent 进程，写 GuardEvent(`lsof-network`) | 只 TCP；不识别 Cursor；代理只对 V2rayU 日志；结果不进 MCP |
| `Resources/workbuddy_network_capture.py` | mitmdump 插件，写 `workbuddy-network-routes.jsonl`（含 `clientAddress` 与 `host`） | 从未被用来给套接字找回真实目的地 |
| `tools/agentreins-mcp/evidence.py`、`Sources/AgentReinsMCP/main.swift` 的 `list_network` | MCP 只读接口 | 只列 transport-audit 命令 |
| `network-view.js`（外网访问页） | 渲染任务卡片 + 命令外联 | 没有"未走代理"的视图 |

## 方案（第 1 步，无 Network Extension）
新增 `tools/socket-sampler/socket_sampler.py`（只用系统自带 `ps`、`lsof`，标准库实现，与 auto.py 同一采集层）：

1. **进程树**：`ps -axww -o pid=,ppid=,lstart=,comm=` 建全机进程表（只在内存里），按可执行路径/argv[0..1] 的文件名识别 Codex / Cursor / WorkBuddy / Claude 根进程（项目路径里出现 "codex" 不算），再向下收全部子孙；也可用 `--root-pid PID:Agent` 指定根。进程参数只用于识别，**不落盘**。
2. **连接**：`lsof -nP -w -a -p <树内 PID> -i -F pcRftPTn`，TCP + UDP、IPv4 + IPv6；丢弃监听和未连接的 UDP。
3. **合并成台账** `~/Library/Application Support/AgentGuard/socket-ledger.json`（0600，原子替换，文件锁，最多 3000 条/7 天）：同一 `pid+进程启动时间+协议+本端+对端` 合并，记 `firstSeen/lastSeen`（UTC ISO8601）和 `sampleCount`。
4. **真实目的地** `realDestination` + `destinationSource` + `destinationEvidence`：
   - 对端是本机代理端口：用代理路由日志（AgentReins 审计代理 `workbuddy-network-routes.jsonl`、V2rayU 日志）按 **本机客户端端口 + 时间窗 15 秒** 精确对上 → `proxy_observed`，Correlated；同端口在窗内对上多个主机 → 视为不确定；对不上 → `proxy_unjoined`，Unknown（**不再把 127.0.0.1 当目的地**）。`transportPeer` 始终保留实际对端（如 `127.0.0.1:18891`），`viaProxy=true`。
   - 直连：同一进程或其祖先经过审计入口、命令参数里有主机，且该主机正向解析包含这个对端 IP → `argv_parsed`，Correlated；
     否则做反向 DNS（PTR，带正向核对标记 `forwardConfirmed`）→ `dns_inferred`，Inferred；
     都没有 → `realDestination` 就是对端 IP，`socket_sampled`，Observed。
   - 套接字本身（谁、哪个 PID、连到哪个 IP:端口、状态）一律 `evidence=Observed`。
5. **覆盖说明** `coverage`：采样方式、间隔、"短于间隔的连接会漏掉"、DNS 不可见、不读正文，失败次数。不估算漏掉的比例。

## 接线
- MCP `list_network`（Python 与打包的 Swift 版同时改）：原 `network` 不变，新增 `sockets`（字段白名单 + 脱敏）、`socketSummary`（其中 `notViaProxyPublic` = 未走代理的外网连接数）、`socketCoverage`；台账不存在时明确 `not_running / Unknown`。`get_coverage` 的"未走代理流量"盲区随采样状态如实改变。
- 外网访问页：`loadTransportAudit` 载荷新增 `sockets`（`SocketLedgerArchive.swift`，只读、字段白名单），"全部外网访问"下方新增"按进程采样的全部连接 · 不论是否走代理"表，逐列转义。
- 运行：`python3 scripts/install_socket_sampler.py` 安装用户级 LaunchAgent（默认每 3 秒）；安装包内带 `Resources/socket-sampler/`。

## 测试
- `tools/socket-sampler/test_socket_sampler.py`：真实录制的 lsof/ps 输出（Linux lsof 4.99.4）+ 标明是手写格式样例的 macOS 输出；覆盖解析、进程树过滤（无关进程不入账）、代理路由对上/对不上/冲突、反向 DNS、argv 正向核对、重复采样合并。
- `tools/agentreins-mcp/test_list_network_sockets.py`、`Tests/Manual/network/test_socket_ledger_view.cjs`。
- CI（macOS runner）现场：`live_direct_check.py` 清空代理变量，起 bash→python 孙进程直连外网（TCP 443 + 已连接 UDP 53），并起一个无关进程做对照；断言台账里 PID/PPID、`viaProxy=false`、`ESTABLISHED`、≥2 次采样、无关进程不出现；顺带报告短命的 `git ls-remote` 是否被 0.2 秒采样抓到（不作为失败）。`mcp_list_network_live.py` 用**安装包里**的采样器 + 打包的 Swift MCP 端到端验证 `list_network.sockets`。

## 已知局限
- 采样不是拦截：短连接可能漏；`lsof` 有开销，默认 3 秒。
- DNS 查询由系统 mDNSResponder 发出，不属于 agent 进程，看不到；反向 DNS 往往只得到 CDN/云厂商名字（标 Inferred）。
- 直连 HTTPS 只能看到 IP 和端口，看不到 SNI/正文。
- 进程识别靠可执行文件名/路径；以别名启动的 agent 需用 `--root-pid`。
- 同一用户的恶意进程可以改台账；本步不做防篡改。
- 第 2 步：Network Extension（NEFilterDataProvider）拿逐条连接 + 进程 + 主机名（需 Apple 开发者 content-filter 授权）。
