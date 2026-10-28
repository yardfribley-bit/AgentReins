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
| `tools/agentreins-mcp/evidence.py`、`Sources/AgentReinsMCP/AgentReinsMCP.swift` 的 `list_network` | MCP 只读接口 | 只列 transport-audit 命令 |
| `network-view.js`（外网访问页） | 渲染任务卡片 + 命令外联 | 没有"未走代理"的视图 |

## 方案（第 1 步，无 Network Extension）
新增 `tools/socket-sampler/socket_sampler.py`（只用系统自带 `ps`、`lsof`，标准库实现，与 auto.py 同一采集层）：

1. **进程树**：每轮只跑便宜的 `ps -axo pid=,ppid=,comm=`；进程启动时间和 argv[0..1] 只对**新出现的进程**用一次 `ps -ww -o pid=,lstart=,args= -p <新 PID>` 取来并缓存（旧版每轮对全机约 500 个进程算 `lstart`，在真实 Mac 上出现过 10 秒超时）。按可执行路径/argv[0..1] 的文件名识别 Codex / Cursor / WorkBuddy / Claude 根进程（项目路径里出现 "codex" 不算），再向下收全部子孙；也可用 `--root-pid PID:Agent` 指定根。进程参数只用于识别，**不落盘**。
2. **连接**：只扫 agent 进程树，不再对全机跑 `lsof -i`。Linux 用 procfs（`/proc/net/tcp` + 这些 PID 的 fd）；macOS 用 libproc 列进程，套接字用 `lsof -a -p <进程树> -i`（只这些 PID）。libproc 的 `socket_fdinfo` 布局和当前内核一致时，代理侧归因直接走 libproc。TCP + UDP、IPv4 + IPv6；丢弃监听和未连接的 UDP。旧的「每轮一次全机 lsof」只留给夹具回放。
3. **合并成台账** `~/Library/Application Support/AgentGuard/socket-ledger.json`（0600，原子替换，文件锁，最多 3000 条/7 天）：同一 `pid+进程启动时间+协议+本端+对端` 合并，记 `firstSeen/lastSeen`（UTC ISO8601）和 `sampleCount`。
4. **真实目的地** `realDestination` + `destinationSource` + `destinationEvidence`：
   - 对端是本机代理端口：用代理路由日志（AgentReins 审计代理 `workbuddy-network-routes.jsonl`、V2rayU 日志）按 **本机客户端端口 + 时间窗 15 秒** 精确对上 → `proxy_observed`，Correlated；同端口在窗内对上多个主机 → 视为不确定；对不上 → `proxy_unjoined`，Unknown（**不再把 127.0.0.1 当目的地**）。`transportPeer` 始终保留实际对端（如 `127.0.0.1:18891`），`viaProxy=true`。
   - 直连：同一进程或其祖先经过审计入口、命令参数里有主机，且该主机正向解析包含这个对端 IP → `argv_parsed`，Correlated；
     否则做反向 DNS（PTR，带正向核对标记 `forwardConfirmed`）→ `dns_inferred`，Inferred；
     都没有 → `realDestination` 就是对端 IP，`socket_sampled`，Observed。
   - 套接字本身（谁、哪个 PID、连到哪个 IP:端口、状态）一律 `evidence=Observed`。
5. **覆盖说明** `coverage`：写的是**实测**结果，不是配置值（见下一节）。不估算漏掉的比例。

## 覆盖率怎么算（如实，不按配置填）
- 台账 `samples.rounds` 保留最近若干轮的 `[开始时间, 耗时, 是否成功]`，**跨重启保留**。
- `configuredIntervalSeconds`：配置的间隔，只是愿望。
- `observedCycleSecondsP50/P95`：相邻两轮实际相隔多久。
- `successGapSecondsP95`、`missesShorterThanSeconds`：相邻两次**成功**采样相隔多久的 p95。比这更短的连接可能整条漏掉。失败的轮次会把这个间隔拉长，所以它比配置间隔更真实。
- `effectiveIntervalSeconds` / `effectiveIntervalSecondsP95`：成功采样间隔的 p50 / p95，也就是实际生效的采样间隔。`get_coverage.socketSampling` 每读一次都带上这两个数，不是只在安装时量一次。
- `estimatedMissRate`：按持续 `referenceShortConnectionSeconds`（1.5 秒，对应实测里 1–2 秒就结束的 python urllib）的连接，对每段成功间隔算 `max(0, 1 - 1.5/间隔)` 再取平均。这是估计，不是数过的漏采条数。
- `maxFirstDetectionDelaySeconds`：窗口内最长的成功间隔。
- `roundDurationSecondsP50/P95`：每轮本身花多久。
- `windowRounds`、`windowFailedRounds`、`failures`：轮数与失败数。
- 样本不足 6 轮时 `measurementConfidence=Unknown`，并写明"不要按配置间隔理解覆盖"。
- **失败不会悄悄丢掉**：`samples.failureLog` 逐条记录（UTC 时间、阶段、原因），类别有：
  - `timeout`：ps/lsof 超时；
  - `error`：命令出错，或这一轮代码出了异常；
  - `partial`：lsof 退出码 1 且有报错，这一轮可能缺进程；
  - `restart_gap`：采样器重启前有多久没采样，以及上次是正常停止还是被杀；
  - `integrity`：启动时发现台账被改，见"防篡改"；
  - `stopped`：收到停止信号，不计入失败数。
- MCP 读台账时还会看新鲜度：最后一次成功采样早于 `max(10 秒, 3 × 间隔)` 就报 `stopped`，并给出 `staleSeconds`，不会把停掉的采样器说成"正在采样"。
  - 间隔优先用实测的成功采样间隔 p95；不足 6 轮、还没有实测值时，用配置间隔；
  - 新鲜度按**读到台账的那一刻**计算，不会把读钥匙串的等待时间算进去。
- 旧版（v1）台账没有实测数据：MCP 标 `measurementConfidence=Unknown`，注明"配置间隔，不是实测"。

## 接线
- MCP `list_network`（Python 与打包的 Swift 版同时改）：原 `network` 不变，新增 `sockets`（字段白名单 + 脱敏）、`socketSummary`（其中 `notViaProxyPublic` = 未走代理的外网连接数）、`socketCoverage`；台账不存在时明确 `not_running / Unknown`。`get_coverage` 的"未走代理流量"盲区随采样状态如实改变。
- 外网访问页：`loadTransportAudit` 载荷新增 `sockets`（`SocketLedgerArchive.swift`，只读、字段白名单），"全部外网访问"下方新增"按进程采样的全部连接 · 不论是否走代理"表，逐列转义。
- 运行：`python3 scripts/install_socket_sampler.py` 安装用户级 LaunchAgent（默认每 0.5 秒；2026-10 之前的安装器把 `--interval 2.0` 写进 plist，再早是 3 秒）。安装包内带 `Resources/socket-sampler/`。再跑一次安装器会改写 plist 并重新 bootstrap。只重启 App 不会改这个 plist。已经写着 `--interval 2.0` 的 plist，在采样器进程换成新脚本之后，会被当成过期默认值，按 0.5 秒跑（台账 `coverage.intervalNote` 会写明）。传不是 2.0 的 `--interval` 则保持原值。
- `list_network` 的每条连接、`get_execution` 都给出同一组字段 `realDestination / destinationSource / transportPeer`。Python 用 `evidence.destination_fields`，Swift 用 `Destination.fields`，规则一样，由 `test_swift_parity.py` 对照检查。
- 打包：`package_app.sh` 最后一步检查安装包。下面任何一项缺失、为空、不是 universal（arm64 + x86_64），或者采样器不是 `socket-sampler/2`，都直接报错退出，不出包：
  - `AgentReinsMCP`
  - `AgentReinsKeychainHelper`
  - 采样器与安装脚本
  - `evidence.py`、`server.py`
  - 脱敏规则
  - 前端脚本

## 测试
- `tools/socket-sampler/test_socket_sampler.py`：真实录制的 lsof/ps 输出（Linux lsof 4.99.4）+ 标明是手写格式样例的 macOS 输出；覆盖解析、进程树过滤（无关进程不入账）、代理路由对上/对不上/冲突、反向 DNS、argv 正向核对、重复采样合并。
- `tools/agentreins-mcp/test_list_network_sockets.py`、`Tests/Manual/network/test_socket_ledger_view.cjs`。
- `tools/socket-sampler/test_sampler_rounds.py`（19 项）：用录好的 macOS 输出回放，模拟以下情况，并确认失败都记进台账、覆盖率按实测计算：
  - ps 超时、ps 明细出错、lsof 出错或只采到一部分；
  - 代码异常；
  - 重启间隙、停止。
  同一文件还测台账签名链：篡改、换钥匙、回滚、删台账，以及 MCP 的校验结果和采样器自己的判断是否一致。
- CI（macOS runner）现场：`live_direct_check.py` 清空代理变量，起 bash→python 孙进程直连外网（TCP 443 + 已连接 UDP 53），并起一个无关进程做对照；断言台账里 PID/PPID、`viaProxy=false`、`ESTABLISHED`、≥2 次采样、无关进程不出现；覆盖率断言用实测字段（`missesShorterThanSeconds` 必须等于实测的 `successGapSecondsP95`，失败数和失败日志对得上），并打印 `LIVE_COVERAGE`；顺带报告短命的 `git ls-remote` 是否被 0.2 秒采样抓到（不作为失败）。`mcp_list_network_live.py` 用**安装包里**的采样器 + 打包的 Swift MCP 端到端验证 `list_network.sockets`：采样器像 LaunchAgent 一样持续运行（0.5 秒），等到至少 3 轮（最多 60 秒）才查询 MCP，然后断言 `sampling`；失败时打印采样器日志、台账的 `samples` 和 `failureLog`、签名状态，以及 MCP 调用耗时。CI 用一个专用的、不会自动上锁的钥匙串（`scripts/ci_keychain.sh`），并在测打包版之前把它重建，让打包版 helper 自己创建密钥。

## 已知局限
- 采样不是拦截：短连接可能漏。漏多短看 `missesShorterThanSeconds`，实际隔多久看 `effectiveIntervalSeconds`，对 1.5 秒连接的估计漏采率看 `estimatedMissRate`。这三个数 `get_coverage` 每次都从台账里带出来。新安装的配置间隔是 0.5 秒；采样器只扫 agent 进程树，目标是常态 Mac 上有效间隔 ≤ 1 秒。已有 plist 里的 `--interval 2.0` 在新采样器进程里按 0.5 秒执行。
- 走审计代理（127.0.0.1:18891）的请求，在连接还活着时由 mitm 插件用内核套接字反查客户端 PID、父进程链和 agent，写进路由日志和正文存档。查不到就写 `via proxy · attribution lost`，不猜测，也不采用客户端自己带的 pid 头。`list_network.proxyFlows` 列出这些记录。App 每次启动用 `Bundle` 里的 `workbuddy_network_capture.py` 新起一个 mitmdump（`--scripts` 指向该文件）；退出再打开 App 会停掉旧进程并加载新插件。更新 App 之前已经在跑的 mitmdump 要等这次重启才会换脚本。插件旁边的 `proc_lookup.py`（`Resources/proc_lookup.py` 或 `Resources/socket-sampler/proc_lookup.py`）随安装包一起换。
- Read / Edit / Write / Glob 这类不派生子进程、也不打开套接字的进程内工具，系统级采样和代理都看不到。`get_coverage.blindSpots` 里有这一条。没看到不等于没发生。Network Extension 不在这一步里。
- DNS 查询由系统 mDNSResponder 发出，不属于 agent 进程，看不到；反向 DNS 往往只得到 CDN/云厂商名字（标 Inferred）。
- 直连 HTTPS 只能看到 IP 和端口，看不到 SNI/正文。
- 进程识别靠可执行文件名/路径；以别名启动的 agent 需用 `--root-pid`。
- 防篡改有边界，见下一节。
- 第 2 步：Network Extension（NEFilterDataProvider）拿逐条连接 + 进程 + 主机名（需 Apple 开发者 content-filter 授权）。

## 防篡改（台账签名链）
- 每次写台账，同时写旁边的 `socket-ledger.json.mac`。内容是 `seq`（递增序号）、`prevHash`（上一份的哈希）、`fileSha256`（这一份台账的字节哈希）、时间，再用钥匙串里的完整性密钥做 HMAC-SHA256。密钥和 MCP 审计链用的是同一把。
- 同样的内容再写一份"封条"到 `~/Library/Application Support/AgentReinsIntegrity/seals/socket-ledger.seal`，跟台账不在同一个目录。
- MCP（Python 与 Swift 规则一样）读台账时校验：
  - `verified`：签名对、内容对、序号和封条接得上。这时连接按原标签给出。
  - `tampered`：只要出现下面任一情况，`socketSummary.ledgerIntegrity` 就是 tampered，**所有连接都标 Unknown**：
    - 改了台账内容；
    - 删了 `.mac`；
    - 签名对不上；
    - 用旧版本回滚；
    - 签过之后又删了台账，或者换成不签名的版本。
  - `unsigned`：老版本采样器从没签过名，标 Unknown 并注明。
  - `unverifiable`：读的人拿不到密钥，标 Unknown。
- 采样器启动时如果发现台账被改：不会在被改的内容上继续签名。它把原文件改名为 `socket-ledger.json.tampered-<时间>` 留着备查，从空台账重新开始，并在 `failureLog` 里记一条 `integrity`。
- 拿不到密钥时（helper 超时、需要授权、出错），采样器照常采样，不会卡住，也不会退出：
  - `.mac` 里写明"未签名"和原因；
  - `failureLog` 里记一条计入失败数的 `key_unavailable`（阶段 `keychain`）；
  - 不会自己造一把文件密钥。
  helper 的规则见 `docs/EVIDENCE-INTEGRITY.zh-CN.md`"helper 永远不等弹窗"。
- **边界**：同一用户的进程能通过钥匙串 helper 拿到密钥（见 `docs/EVIDENCE-INTEGRITY.zh-CN.md` 的 b6），所以签名只能证明"没被不知道密钥的程序改过"，挡不住有心的同用户恶意程序。因此 `get_coverage` 的完整性摘要里写着 `sameUidCanForge=true`，摘要置信度固定为 Unknown；`verified` 只说明签名链本身是通的。
