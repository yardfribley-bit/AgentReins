# AgentReinsMCP 客户端接入片段

包内二进制路径（CI / 安装后）：

```text
AgentReins.app/Contents/MacOS/AgentReinsMCP
```

开发态也可用：

```text
python3 tools/agentreins-mcp/server.py
```

WorkBuddy：粘贴配置后必须在客户端点「信任」才会真正启用 stdio MCP。

| 客户端 | 文件 |
|---|---|
| Codex | `codex.config.toml` |
| Claude Code | `claude-code.mcp.json` |
| Cursor | `cursor.mcp.json` |
| WorkBuddy | `workbuddy.mcp.json` |

同一台 Mac 上的 HTTP 入口（`http://127.0.0.1:18977/mcp`，需先装 LaunchAgent）在 [`http/`](http/README.md)。stdio 配置保持可用。
