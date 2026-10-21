# 证据完整性：当前记录、历史记录与分界点

本文说明 MCP 怎样判断审计记录和证据文件是否被改过，以及**哪些事它证明不了**。
Python（`tools/agentreins-mcp/evidence.py`）和打包的 Swift MCP（`Sources/AgentReinsCore/Core*.swift`）规则相同，由 `tools/agentreins-mcp/test_swift_parity.py` 用同一批场景对照检查。

## 签了什么
- **MCP 审计日志**：`~/Library/Application Support/AgentGuard/mcp-supervisor-audit.jsonl`。每条记录带 `prevHash`（上一条的哈希）和 HMAC-SHA256 签名，连成一条链。
- **封条**：记下链的最后一条和总条数，存两份：
  - `mcp-supervisor-audit.seal`；
  - `AgentReinsIntegrity/seals/` 下的副本。
  删掉末尾几条、删掉封条，都会被发现。
- **证据文件**：每次执行的 `transport.json` 和 `manifest.json` 旁边各有一个 `.mac`。
- **执行清单** `transport-run-inventory.jsonl`：它的签名放在 `AgentReinsIntegrity/transport-run-inventory.mac`，它的哈希也写进封条。
- **按进程采样的连接台账**：见 `docs/SOCKET-SAMPLING.zh-CN.md` 的"防篡改"。
- **密钥**：只放在 macOS 钥匙串（服务名 `com.agentreins.mcp-integrity`）。所有读写都经过随 App 打包的 `AgentReinsKeychainHelper`。
  - 拿不到密钥时（helper 不在、钥匙串出错、15 秒超时）：**不会**另造一把文件密钥，也不追加审计记录。状态报 `key_unavailable`，说明"读不到密钥，无法校验，不是篡改结论"，括号里写明具体原因。
  - 钥匙串里没有密钥、但写入新密钥被拒绝时，同样报 `key_unavailable`，**不会**退回去写明文密钥文件。
  - Python MCP 和 Swift MCP 一样：没有密钥时照常回答查询，只是不签名。

## helper 永远不等弹窗
采样器（LaunchAgent）、被 agent 拉起的 MCP、CI 都没有人能点钥匙串的授权弹窗。以前 helper 在这种情况下会一直卡住，直到调用方 15 秒超时；CI 运行 39655188074 就是这样失败的。现在规则如下：
- `get`、`set`、`delete` 一律关闭钥匙串交互（`SecKeychainSetUserInteractionAllowed(false)`）。钥匙串锁着，或者这个 helper 还不在条目的访问列表里时，helper 立刻以**退出码 4** 结束（表示需要用户授权）。调用方把它记成 `error`，原因写"keychain needs user approval"。
- 其他退出码：0 成功，3 没有这个条目，1 其他钥匙串错误。
- 每次调用 helper 都限时 15 秒。超时算失败，而且同一进程 60 秒内不再调用 helper，直接报"timed out recently; not retried yet"。这样钥匙串卡住时，每分钟只耗一次超时，不会每个账户、每次 MCP 调用都等 15 秒。Python 与 Swift 规则相同。
- `AgentReinsKeychainHelper authorize` 是唯一允许弹窗的操作，只在有人登录、主动运行时使用。它会让 macOS 弹出一次授权（选"始终允许"），不输出任何密钥。升级后如果出现"needs user approval"，运行一次即可。
- `AgentReinsKeychainHelper status [账户]`：不弹窗地试读一次，不输出任何内容，只用退出码报状态（0/3/4/1）。
- App 启动时先用 `status` 检查；结果是需要授权、出错或超时时，弹出说明框（「授权…」/「以后再说」），用户点「授权…」后才运行 `authorize`，结果再弹框告知。从不静默弹钥匙串窗口。首页的覆盖横幅在 `key_unavailable` 时也给出「授权…」按钮和终端命令。
- App 和打包的 MCP 共用 `Sources/AgentReinsCore`（SwiftPM 库目标），App 自己校验采样台账，不再为此拉起 MCP。

## 为什么要分"当前"和"历史"
早期版本把密钥放在普通文件里。迁移到钥匙串时，旧密钥被删掉了。用旧密钥签的那些记录，从此既证明不了完好，也证明不了被改。
以前的做法是把它们一律算成"被篡改"（误报），或者用新密钥重签（等于洗白）。现在两样都不做，而是把结果拆成三部分：

| 字段 | 含义 | 是否影响 `ok` |
|---|---|---|
| `currentTampered` | 分界点之后的记录校验失败：被改、被删、伪造、截断、封条对不上、清单被改…… | 是：只要大于 0，`ok=false` |
| `legacyUnverifiable` | 分界点之前、用已删除的旧密钥签的历史记录（含时间范围 `from`/`to`） | 否，单独标 Unknown |
| `status` / `statusText` | `ok`、`current_ok_legacy_unverifiable`、`current_tampered`、`key_unavailable`，并配一句中文说明 | — |

## 分界点（boundary marker）
分界点只在第一次升级时记录一次，内容如下：
- 第几条之前算历史（`auditBoundaryIndex`）；
- 这些历史记录原样字节的哈希（`auditPrefixSha256`）；
- 历史证据文件清单的哈希（`legacyManifestSha256`）；
- 历史记录的条数和时间范围；
- 当前密钥的指纹；
- 来源（`source`）。

整个分界点用当前密钥签名，并且存在三处：
1. **钥匙串**（账户 `integrity-boundary`）：这是唯一的权威副本。
2. `AgentReinsIntegrity/integrity-boundary.json`：只是镜像。单改或单删这个文件不起作用。
3. 审计链里的一条 `integrity-boundary` 记录：它本身也受签名链保护。

分界点是怎么定出来的（`source`）：
- `recorded-at-signed-era-start`：新装，或者从未签名的版本升级。分界点就是"现在"，之前没有签名的旧记录都归为历史。
- `upgrade-inferred`：从"文件密钥"版本升级。按两条线索取较早的一处：第一条能用新密钥验证通过的记录，以及钥匙串里记下的启用时间。这一项是推断出来的，所以 `boundary.confidence=Inferred`。

几条防洗白的规则（都有测试）：
- **删掉分界点不会让记录变成"历史"。** 审计链里已经有 `integrity-boundary` 记录，钥匙串里却找不到分界点，就报 `boundary_marker_deleted`，算当前篡改。系统**不会**重新划一次分界点。
- 伪造分界点（签名对不上），报 `boundary_marker_mac_mismatch`。
- 改动任何一条历史记录，前缀哈希就对不上，报 `legacy_audit_prefix_modified`，算当前篡改。历史记录只是"无法证明"，并不等于"可以随便改"。
- 改动历史证据文件，或者删掉、改动历史清单，都算当前篡改。
- 把日志截断到分界点以内，报 `audit_truncated_below_boundary`。
- 读取永远不会重签任何东西。以前每次读取都会把被改过的执行清单重新签一遍，等于自动洗白，这个问题已经修掉。现在只有当清单先通过校验，追加新执行编号后才会重签。

## b6：同一用户能不能伪造（如实写）
`b6.sameUidCanForge` 现在恒为 `true`，这是按事实得出的，不是默认值：
- 钥匙串条目的访问控制只信任 helper 这个程序，而 helper 不检查是谁在调用它。同一用户的任何进程都可以运行 `AgentReinsKeychainHelper get hmac-key` 拿到密钥。
- 日志、签名、封条都由同一个用户写，没有 root 守护进程，也没有远端锚点。

`b6.keyStorage` 列出实际情况：
- 用的是哪种后端；
- 密钥在不在钥匙串里；
- 有没有残留的明文密钥文件；
- helper 在哪里。

所以：
- 校验通过，只能说明记录没有被"不知道密钥的程序"改过；
- `get_coverage.integritySummary.confidence` 固定为 Unknown；
- 校验全部通过时，结果里写 `observedBlockedBy=same_uid_no_external_anchor`。

## 在哪里看
- MCP `get_coverage`：
  - `integritySummary`：`ok`、`status`、`statusText`、`currentTampered`、`legacyUnverifiable`、`legacyRange`、`sameUidCanForge`；
  - `evidenceIntegrity`：完整明细，包括 `boundary` 和 `b6`；
  - `socketLedgerIntegrity`：连接台账的签名链状态。
- MCP `list_mcp_audit`：完整明细。

## 测试
- `test_tamper_b1_b6.py`、`test_tamper_b7_b10.py`、`test_tamper_b11_b12.py`、`test_tamper_b14_b16.py`：原有 B1–B16 全部保留，没有放宽。另外新增一项：B8 执行清单被改后，后续读取或新执行都不能把它洗白。
- `test_integrity_split.py`：覆盖以下场景：
  - 分界点的记录；
  - 当前与历史的拆分；
  - 改迁移后的记录；
  - 删分界点；
  - 伪造分界点；
  - 只改镜像；
  - 改历史记录或历史证据；
  - 删历史清单；
  - 截断；
  - b6 与实际存储一致；
  - 钥匙串读错时不造新密钥。
- 测试专用的钥匙串替身在 `tools/agentreins-mcp/keychain_fake.py`，只由测试用 `mock.patch` 注入。随包代码里不再有 `AGENTREINS_KEYCHAIN_BACKEND=memory|file`、非 macOS 的文件密钥退路或 `AGENTREINS_REDACT_SELFTEST`；`package_app.sh` 和 CI 会检查它们没有回到打包产物里。
- `test_swift_parity.py`：同一批场景下，Python 与 Swift 的结论逐项相同，包括 Python 和 Swift 交替写同一条审计链。

## 已知局限
- 同一用户的恶意程序能拿到密钥，见 b6。要真正防住，需要 root 守护进程或远端锚点，这不在本步范围内。
- 历史记录是 Unknown。它们没被证明完好，只是从分界点起字节没再变过。
- 钥匙串里如果已有旧条目，其访问控制可能只认旧 helper。打包版 helper 不会弹窗，而是报 `key_unavailable`（需要授权），直到有人运行一次 `AgentReinsKeychainHelper authorize`。
