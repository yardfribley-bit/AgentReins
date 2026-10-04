# AgentReins v2：在现有 macOS 工程上演进

基础提交：e838fb5，分支：codex/agentreins-v2。

保留现有 SwiftUI 应用、持久化证据、WorkBuddy 本机审计代理、语义适配器、文件和进程采集以及现有任务证据投影。AppLens 不作为本项目的运行依赖。原版本目录不变。

第一步：新增 `agentreins_v2` 可执行产品，进入同一原生应用；任务页默认展示执行链路，并保留原任务视图切换。已存储的请求、返回和工具原文直接显示，回放只突出已有轮次，不生成伪造执行事件。

这一步不是已确认动态原型的完整交付。仍需继续完成稳定布局中的节点间流动、工具与模型内容往返、进程/文件/网络证据附着、失败和重试分支，以及实时更新的局部刷新。

工具与文件继续采用现有 `toolCallID` 关联。网络归属未知时保持任务级证据，不凭时间相近认定因果。原工程的系统事件覆盖必须逐项实测；不能因使用原工程就宣称所有短连接和短命进程都已捕获。

构建：`swift build -j 2 --product agentreins_v2`。

回归：`swift test -j 2 --filter 'TaskStoryRegressionTests|ToolEvidenceCompanionTests|AgentEventProtocolTests'`。

打包沿用原 `package_app.sh`，后续以单独应用包交付并沿用 Assets/AgentReins.icns。不安装覆盖现有应用，不同时启动两份观察进程。
