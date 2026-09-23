# X 线程发布稿

## 主帖

ZCode 的代码上传风波，让大家第一次认真追问：AI 编程工具到底从电脑里拿走了什么？

我们用 AgentReins 检查了另一个更隐蔽的数据出口：模型请求里的长期记忆。

用户只发一句话，Agent 可能同时带上人格、身份、用户画像、项目资料和本地代码。🧵 1/7

配图：`docs/memory-security-assets/01-zcode-to-memory-security.png`

## 2/7

公开 issue 报告称，ZCode 将工作区源码、文档和 `.git` 历史纳入加密快照；一个样本约 313 MB，并记录了 564 次重试。

这是整仓上传。我们继续追问：没有整仓打包时，Agent 每次请求又在发送什么？

来源：GitHub Issue #16、#707、#715。

## 3/7

AgentReins 在 WorkBuddy 的真实上下文里看到三个文件：

SOUL.md：Agent 的人格、行动原则和隐私边界  
IDENTITY.md：Agent 身份、能力和沟通习惯  
USER.md：用户称呼、设备、账号备注、活跃项目、本地路径和长期偏好

这不是三个标签，是完整原文。

配图：`docs/memory-security-assets/02-three-memory-files.png`

## 4/7

用户只输入一个句号，模型看到的也可能是：

系统指令 + SOUL + IDENTITY + USER + 历史对话 + 项目结构 + 工具定义 + 连接器状态。

最新样本输入 73,331 tokens，输出只有 206 tokens。数字只是规模，内容才是风险。

配图：`docs/memory-security-assets/03-dot-to-context.png`

## 5/7

我们又做了 Canary 实验：

① 第一次模型输入没有标记  
② WorkBuddy 调用 Read，读取带标记的本地代码  
③ 第二次模型输入出现同一标记

这证明本地代码进入了下一轮模型上下文。

配图：`docs/memory-security-assets/04-canary-proof-chain.png`

## 6/7

但我们不会把本地 trace 冒充网络接收证明。

当前证据证明“代码进入待发送上下文”；接收域名和远端 IP 仍需同一请求的网络证据关联。超长 trace 还存在约 100,002 字符的截断。

安全研究最重要的是：结论必须和证据强度一致。

## 7/7

AgentReins 不只告诉你“上传了多少 tokens”。

它要回答四件事：
内容是什么、来源是什么、去了哪里、是否有必要。

AI Agent 的数据边界不应藏在一次请求的几十万字符里。用户应该看得见，也应该能控制。

配图：`docs/memory-security-assets/05-agentreins-evidence-model.png`

## 发布配置

- 首帖使用图 1，避免一上来堆技术细节。
- 第 3、4、5、7 条分别使用图 2 至图 5。
- 不在图片或正文中公开真实用户名、绝对路径、仓库名、Token 或凭据。
- ZCode 数字始终写成“公开 issue 报告”或“开发者样本”，不要写成 AgentReins 已独立复现。
- WorkBuddy 结论写成“进入模型上下文”；获得网络同流证据前，不写“服务器已经接收”。
- 建议发布时间：工作日 11:30 或 20:30；首帖 24 小时内置顶。
