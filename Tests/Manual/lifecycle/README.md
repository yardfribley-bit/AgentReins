# 生命周期验收夹具

配套文档：`docs/realtime/TEST-E2E-RUNBOOK.zh-CN.md`。fixture.py仅运行本地测试脚本和127.0.0.1 HTTP服务，不控制Agent、不修改代理、不启动AgentReins。

- init：要求新的空路径，创建输入样本、output/evidence和manifest。
- serve：随机本地端口，提供data/retry/redirect/slow/invalid/download，记录独立server.jsonl。
- run：stream（5行交替stdout/stderr）、fail（exit1）、business-error（exit0但业务失败）、large（2000行）、report（429→200→JSON/Markdown）。每个report使用唯一run标记。
- verify.py：独立检查固定三天数据、报告字段、服务实际请求序列和文件hash，不导入生产者逻辑、不读取AgentReins界面数据。

2026-10-09执行了夹具自检，验证五类脚本返回、重试序列、独立校验成功及损坏报告被拒绝。没有执行真实Agent/生产采集/生产UI验收，不得将此记录计为E2E通过。自检证据保存在本次测试临时目录，正式验收按RUN_ID另行收集。

原始输出时间记录用于独立对账；来源采集与UI时间仍需真实应用采样。服务日志记录请求和拟响应内容，不证明客户端已完整收到正文。测试结束停止自己启动的服务，保留证据目录。
