# Codex Git/curl 自动入口实测

当前 Codex zsh 执行器的普通 curl/git 已接入自动采集，无需每条命令手动包装。WorkBuddy 未停止、未重启、未发消息。

- curl 直连百度：退出 0，HTTP 收发与连接证据、227 字节落盘文件、SHA256，记录原生 CODEX_THREAD_ID。
- Git 直连 clone：停滞后仅停止本次测试进程，退出 -15，保留失败证据。
- Git 使用现有 1087 代理 clone：退出 0，结果提交 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d，README 13 字节，保存 /private/tmp/agentreins-codex-auto-git-proxy-20261014。
- 非 Codex shell：移除两项 Codex 环境标识后，curl/git 仍使用普通外部命令。
- 解析回归：5 项通过。

## 实际边界

入口在 ~/.zshenv 中受 CODEX_THREAD_ID 与 CODEX_CLI_PATH 双条件保护，源代码安装器 scripts/install_codex_transport.py。原始收发 trace 留在本机受限目录。

当前关联到原生 Codex 会话；尚未关联到具体轮次与 tool call。绝对路径、command curl、其它 shell、程序内部执行的 curl/git 会绕过 shell 函数；不能宣称覆盖所有 Codex 网络行为。Git 二进制正文仍未完整还原，连接到子进程的逐条映射仍待完善。

本机预览服务已恢复，/transport-audit.json 提供真实自动记录。浏览器验证被浏览器安全策略拒绝，本轮未确认渲染效果。
