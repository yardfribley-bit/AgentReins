# 进程内明文探针：隔离验证阶段

当前状态：Node HTTP/1 request/get 的发送明文和响应解码前 HTTP body 字节探针。不是已部署产品采集器，不自动修改 Agent、不注入运行中应用、不修改系统代理或证书。界面未变。

仅在显式提供 AGENTREINS_PLAINTEXT_OUTPUT 与 AGENTREINS_PLAINTEXT_AGENT 并加载此模块时启用。Agent 标签来自启动配置，不能作为已验证进程归属。尚未接入产品数据库或任务关联。

数据：独立 flow ID、PID/PPID、请求方法/路径/脱敏头、正文 base64、全观察字节 SHA256、实际保存字节数、截断状态、正常或异常结束。单方向最多保存 1 MiB；摘要记录的是观察字节，不证明传输到达对端。响应字节可能仍是 HTTP 压缩编码，不能当作已解压文本。

局限：不覆盖 fetch/undici、HTTP/2、Bun、Electron net、原生 Rust/TLS；不证明 WorkBuddy/Codex 的实际网络栈已接入。记录使用同步本地写盘，仅供验证，不满足产品级性能和可靠队列要求。正文包含敏感数据，测试仅使用虚构数据，文件以 0600 创建；正式接入前必须补来源身份、持久队列、错误健康报告与存储策略。

验证：`node tools/plaintext-probe/test.cjs`。只访问回环 HTTP 服务。2026-10-12 实测通过中文分块发送/返回、哈希、流配对、结束标记和凭据头隐藏。HTTPS 真实握手、异常中断、并发及限额仍待验证，不声称全面通过。

## 后续产品接线与验证

新增 ProcessPlaintextEvidence 适配器，经 WorkBuddyNetworkCapture 的既有 journal 入口进入原始证据保存及 GuardEvent 回调，RealtimeNetworkBodyPreview 复用现有布局。探针启动入口为 scripts/launch_workbuddy_plaintext.sh，默认输出到既有 journal；不自动重启桌面、不覆盖已运行进程。来源保持 process-plaintext，不能伪称代理或已确认任务。

真实回环 HTTPS（显式信任临时证书）、16 路并发、1 MiB 截断、响应中断、readable 读取、setEncoding 二进制字节均已通过。测试发现 setEncoding 导致原探针哈希失真，改为在 res.push 字节入口采集后复测通过。原 HTTP 测试复测通过。Swift 既有正文预览四项及 journal→事件→预览集成测试一项通过。

WorkBuddy 已安装 CLI --help 实测成功加载探针，观察到真实 request/error 记录；这不代表模型正文已采集成功。桌面运行中实例和 Codex 原生网络路径尚未接入。同步写盘与有限正文仍属局限，不能作为全量低开销验收通过。

真实 WorkBuddy CLI 新消息测试：退出码 0，但未得到预期回复；记录 19 个 request、13 个 response、5 个 error。模型路由 /v2/chat/completions 观察到 32,110 字节的发送片段，complete=false，随后 request_error，未取得模型响应，片段不包含测试标记。因此模型任务端到端验收失败，不将后台接口成功响应计入模型覆盖。失败日志仅保存在本机临时目录，不提交正文。探针追加错误 code 字段用于后续诊断，不输出可能含敏感信息的错误 message。
