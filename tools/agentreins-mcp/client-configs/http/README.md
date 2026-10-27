# 本机 HTTP MCP 客户端片段

固定地址（默认端口，不要改成 `0.0.0.0` 或局域网 IP）：

```text
http://127.0.0.1:18977/mcp
```

先在这台 Mac 上启动服务（用户级 LaunchAgent，App 没开也能用）：

```bash
python3 /Applications/AgentReins.app/Contents/Resources/agentreins-mcp/install_mcp_http.py
curl -sS http://127.0.0.1:18977/healthz
```

| 客户端 | 文件 |
|---|---|
| Codex | `codex.config.toml` |
| Cursor | `cursor.mcp.json` |
| Claude Code | `claude-code.mcp.json`（或 `claude mcp add --transport http --scope user agentreins http://127.0.0.1:18977/mcp`） |
| WorkBuddy | `workbuddy.mcp.json` |

默认不需要 token。安装时加了 `--require-token` 才要带 `Authorization: Bearer`。stdio 配置仍在上一级目录，HTTP 客户端不兼容时用那个。
