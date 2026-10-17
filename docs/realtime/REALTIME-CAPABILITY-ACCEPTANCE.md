# WorkBuddy / Codex 实时能力恢复与验收

范围固定：两个 Agent 的实时任务、安全能力；其他适配器保留但不启动。安装前历史不扫描，已经采集的数据按需查询。不打包、不替换运行实例，直到单独完成运行验收。

| 能力 | 现有来源 | 本次状态 | 仍需验收 |
|---|---|---|---|
| 原生任务/工具/模型记录 | WorkBuddySight、CodexSight、Hook | 保留 | 多轮、并发、子任务、日志轮转 |
| 进程树/身份/退出 | ProcessGuard、ProcessObservationCoordinator | 保留 | 短命进程及共享网络进程 |
| TCP/代理目标 | NetworkSnapshotProvider、ProxyDestinationProvider | 上轮修复失败被当作空集合 | 系统事件来源、UDP、短连接、权限缺口 |
| HTTP 请求返回 | WorkBuddyNetworkCapture | 保留现有覆盖 | Codex、绕过代理、超时重试、内容完整性 |
| 代码安全 | CodeSecurityScanner、FileGuard、WorkBuddySight | 本轮恢复实时卡片字段和详情；补 Codex 调用检测、cmd 参数读取 | 真正的新任务 UI 检查；patch/Edit 参数与检测覆盖仍待核查 |
| 文件变化及 diff | FileGuard、工具证据 | 存在，尚未完整验收 | 当前监控路径、快速连续修改、归属 |
| 外联安全与 SSH | 旧 AgentEgressAudit、SSHSessionEvidence | 仍待修核和接回实时投影 | 禁止直接恢复旧的不充分关联与完整性推断 |
| 敏感规则 | 本地策略、SensitiveRuleEditor | 上轮接回实时窗口入口 | 配置事务、错误降级、敏感值存储保护 |

## 防退化要求

- 正文、连接、工具报告独立标明来源；未经证明的关系不标确认。
- 每个新增能力必须有请求/返回配对、负例及缺失数据测试。
- 代码检测只使用本次事件携带的内容，不额外遍历工作区或历史会话。发现是待核查提示，不是已确认漏洞。
- 代码安全结果保留到任务详情，不能在展示转换中丢字段。安全风险与执行成功失败分别表示。
- 所有完成声明需要区分单元测试、真实采集、界面验证、性能验证。
- 新版本空闲/活跃 CPU、内存、队列积压与丢事件尚未测量，不能宣称已达标。

## 当前测试边界

RealtimeWorkspaceTests 中原生 WebKit 渲染测试在本次执行报 InvalidTransition failed(deinit)，另有一项跳过；不能把该套件报为全部通过。新增代码安全回归单独验证采集格式、配对后保留、敏感片段隐藏和无命中负例。真实 Agent 新任务仍待运行验收。

后续验证：新增 RealtimeCodeSecurityTests 三项通过；原生 WebKit 渲染测试在获准的非沙箱执行下单独复测通过（1 项）。这证明现有渲染回归可运行，不代替新增安全区块的真实任务端到端验收。JavaScript 语法检查与 git diff --check 通过。

## 2026-10-12 约束纠正：特殊授权不是交付前提

用户再次确认 Apple 特殊授权路线不可作为当前项目方案。重新查阅 `docs/architecture/HOOK-PROCESS-COLLECTION-V4.zh-CN.md`、`docs/v2/scoped-process-collection.md`、`docs/LOCAL-COLLECTION-ARCHITECTURE-V3.zh-CN.md`（相关归档提交 `5b170db`）：V4 明确不引入 ESF，已有 Hook 唤醒、进程树/出生身份、定向观察与合并触发。V3 协调器是讨论稿，不能视为已实现。

撤回“先申请 ES/NE 授权才能继续”的交付计划。`tools/collection-preflight` 仅为一次独立环境探测，不是默认采集架构，也不是用户需要满足的前置条件。

后续基于原生 Hook/日志增量、限定进程树、应用协议正文适配器、文件变化通知与有预算的定向状态核对继续实现。先核查既有接线与实际覆盖，不另造不兼容采集链。不声称 Hook 或进程身份自动提供所有系统调用，也不承诺免授权方案零漏采。特殊授权方案不作为本次交付依赖。
