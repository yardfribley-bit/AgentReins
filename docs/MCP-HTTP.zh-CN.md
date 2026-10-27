# 本机 HTTP MCP（只听 127.0.0.1）

同一台 Mac 上的 agent 用固定地址读 AgentReins，不必每家各写一条 stdio 启动命令。stdio 仍然是默认模式，现有 Codex 配置不用改。

```text
http://127.0.0.1:18977/mcp
```

二进制还是 `AgentReins.app/Contents/MacOS/AgentReinsMCP`。加上 `--http` 才进 HTTP。

## 安装

App 不必在运行。安装器写入用户级 LaunchAgent `com.agentreins.mcp-http`（`RunAtLoad` + `KeepAlive`，`ThrottleInterval` 10 秒），日志在 `~/Library/Logs/AgentReins/mcp-http.log`。

已装到 `/Applications` 时：

```bash
python3 /Applications/AgentReins.app/Contents/Resources/agentreins-mcp/install_mcp_http.py
```

开发树，或 App 不在 `/Applications`（安装器会把实际路径写进 plist）：

```bash
python3 scripts/install_mcp_http.py --binary /path/to/AgentReins.app/Contents/MacOS/AgentReinsMCP
```

换端口（发现文件会写成新端口；各客户端配置要一起改，不会自动换端口）：

```bash
python3 scripts/install_mcp_http.py --port 18977
# 或环境变量 AGENTREINS_MCP_PORT
```

只看 plist、不安装：

```bash
python3 scripts/install_mcp_http.py --print
```

卸掉：

```bash
python3 scripts/install_mcp_http.py --uninstall
```

## 验证

```bash
curl -sS http://127.0.0.1:18977/healthz
# {"ok":true,"version":"0.2.0-swift"}

curl -sS -D - http://127.0.0.1:18977/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Host: 127.0.0.1:18977' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

响应头里有 `Mcp-Session-Id`。随后的请求带上这个头。`GET /mcp` 返回 405（这一版不推 SSE）。`DELETE /mcp` 结束会话。

发现文件（0600）：

```text
~/Library/Application Support/AgentGuard/mcp-endpoint.json
```

字段：`url`、`port`、`pid`、`version`、`state`（`listening` 或 `port_in_use`）、`startedAt`、`auth`（`none` 或 `bearer`）。`get_coverage` 的 `mcpEndpoint` 是同一份状态，stdio 和 HTTP 都能读到。

客户端片段在 `tools/agentreins-mcp/client-configs/http/`。

## 安全模型

只绑定 `127.0.0.1`，不监听 `0.0.0.0`，不监听 IPv6，不开 Bonjour。启动后用 `lsof` 核对监听地址，不是回环就退出。

默认没有 token，因为同用户进程本来就能读 `~/Library/Application Support/AgentGuard/` 下的原始记录（`sameUidCanForge`）。挡的是另外两件事：

| 威胁 | 处理 |
|---|---|
| 浏览器 / DNS rebinding | `Host` 只允许 `127.0.0.1:<端口>` 和 `localhost:<端口>`；带 `Origin` 且不是 `null` 或本机回环则 403；POST 必须是 `application/json` |
| 这台 Mac 上的其他用户 | libproc 把对端源端口对上 PID，UID 不是当前用户则 403；对不上进程也 403 |

可选 bearer（默认关）：

```bash
python3 scripts/install_mcp_http.py --require-token
```

安装器在 `~/Library/Application Support/AgentGuard/mcp-http.token` 生成 0600 文件（已存在则不轮换、不打印内容）。之后请求要带 `Authorization: Bearer <token>`。`GET /healthz` 仍只做 Host / Origin / 同用户检查，方便探活，响应里没有业务数据。

工具仍是原来的 6 个只读工具。名字里带 write / delete / update / set_ / save / dismiss / accept / whitelist / mute 的调用返回 `isError`。没有 resources、prompts、sampling。请求体上限 1 MB，同时最多 16 个连接，空闲 30 秒关掉连接。

## 审计

`actor` 仍是审计行里的一个字符串，HMAC 链的字段没变。HTTP 会话各自记自己的 clientInfo，格式：

```text
<clientInfo.name>/<version> via http pid=<pid> exe=<可执行文件名>
```

`pid` 和 `exe` 来自内核（libproc），`clientInfo` 是客户端自己报的。App 里原来的 MCP 审计列表不用改就能看见这段文字。

同一进程里的 `tools/call` 串行执行。`Integrity.append` 对审计日志 `flock`，避免 HTTP 进程和 stdio 进程同时写坏链。

## 排障

| 现象 | 原因 |
|---|---|
| 进程马上退出，发现文件 `state` 为 `port_in_use` | 18977 已被占用。日志里有 `lsof -nP -iTCP:18977 -sTCP:LISTEN` 的输出。改 `--port` 后要同步每个客户端，不会自动换端口 |
| 能读数据，但 `list_mcp_audit` / `get_coverage` 是 `key_unavailable` | LaunchAgent 下钥匙串 helper 还没被授权。数据照常返回，审计先不签名。在终端对同一个二进制跑一次会触发授权的读（与 socket-sampler 相同的 helper） |
| LaunchAgent 装了但没进程 | plist 里的路径是安装时的 `.app`。App 被改名或挪走之后要重新安装。未签名包若带 quarantine，launchd 可能被 Gatekeeper 拦住 |
| 某个客户端连不上 | 这一版只回 JSON，不推 SSE。客户端若只要旧的 HTTP+SSE，继续用 stdio |
| `Host` 403 | URL 请写 `127.0.0.1`，不要写局域网 IP。`localhost` 若被解析成 `::1` 会连不上，因为没有 IPv6 监听 |

测试钩子（HTTP 请求改不了，只在进程启动时读）：`AGENTREINS_MCP_ENDPOINT_FILE`、`AGENTREINS_MCP_TOKEN_FILE`。给测试用，避免覆盖正在使用的发现文件或 token。

App 设置里的开关不在这一期。
