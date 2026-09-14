# AgentReins B 站首发包

## 推荐定位

不要把首稿做成传统产品广告。B 站首稿应是一条 4–6 分钟的技术问题复现：给 WorkBuddy、Codex 或 Cursor 一个真实任务，展示短短一句需求背后，Agent 实际发送了多少上下文、连接了哪个模型或中转、调用了哪些工具、启动了哪些进程、修改了哪些文件，以及“Agent 声称完成”是否通过独立验证。

60 秒英文宣传片可以作为后续动态或短预告，不建议替代首支中文技术视频。

## 首选标题

**我把 AI 编程 Agent 的后台扒开了：你的代码、记忆和密钥发给了谁？**

备选标题：

1. **你让 AI 写一行代码，它背后到底做了什么？**
2. **Codex / Cursor / WorkBuddy 在后台干了什么？我做了一个实时监控工具**
3. **AI 编程工具真的安全吗？一次任务背后的模型、进程、网络和文件证据**
4. **Agent 说“完成了”，但它真的完成了吗？**

推荐使用第一个。它同时包含问题、冲突和用户利益点，但没有承诺无法证明的结论。

## 封面文案

主标题：

> 你的代码发给了谁？

副标题：

> 拆开 AI Agent 的完整执行链

画面建议：左侧是一句用户需求，中间是 AgentReins 的 Live Task / Runtime Map，右侧突出三个黄色证据：`Private Relay`、`Memory`、`API Key`。不要堆满小字。

## 4–6 分钟视频脚本

### 00:00–00:20 开场：直接提出问题

> 你对 AI 编程工具说：“帮我写一个 hello.c，然后编译运行。”你看到的可能只有一句“已完成”。但在这一分钟里，它可能读取了项目、记忆和 Skill，把上下文发给模型或第三方中转，调用 Shell 和 MCP，启动多个子进程，修改文件，甚至连接远程服务器。问题是：这些事情，用户几乎看不见。

画面：真实输入需求 → Agent 回复完成 → 立刻切换 AgentReins 实时任务链。

### 00:20–01:05 问题一：传统日志无法说明完整因果关系

> 进程工具只能告诉我 PID，网络工具只能告诉我 IP，Git 只能告诉我文件变化，Agent 日志可能只记录 Tool Call。单独看它们都没有错，但无法回答：这次网络连接是不是这个 Agent 发起的？这个文件是谁改的？它属于哪次对话？

画面：进程、网络、文件三个分散视图 → 合并为 `用户需求 → 上下文 → 模型 → 工具 → 进程 → 网络/文件 → 结果`。

### 01:05–02:00 问题二：模型中转可能看到完整上下文

> 很多 AI 编程工具使用订阅账号或第三方中转。中转返回一个 model 字段，不等于真实上游模型已经得到证明。更重要的是，用户输入可能只有十几个字，Agent 实际构造的请求却包含系统提示词、项目代码、长期记忆、Skill、工具结果，甚至密钥。

> AgentReins 把“配置的模型”“实际连接的网络目标”和“中转声称的模型”分开显示。只有捕获到正文证据时，才展示具体上下文；只有 Socket 证据时，就明确告诉用户我们只能证明连接存在。

画面：External Services / Provider Trust，突出网关、IP 位置、ASN、声称模型和暴露内容类别。

### 02:00–03:10 解决方式：重建 Live Task

> 我们没有再做一个日志列表，而是把一次任务还原成普通人可以理解的过程：用户提了什么需求、Agent 准备了什么上下文、请求了哪个模型、调用了哪个 MCP 或 Shell、正在修改哪个文件、编译和测试到了哪一步。

> 点击任何节点，才继续看完整参数、工具结果、PID、工作目录、网络目标、文件 Diff 和原始证据。

画面依次高亮：User Request、Context Prepared、Model Connection、MCP、Shell、File Update、Compile、Test。

### 03:10–04:05 进程不是树，而是 Agent 的运行时地图

> AI Agent 不是一个进程。它可能包含 Agent Core、Context Engine、Storage Service、MCP Tool Server、Node REPL、Sandbox 和 Code Execution Host。它们的安全职责完全不同。

> AgentReins 基于真实 PID/PPID 和 Agent 专属 Adapter 建立 Runtime Profile。重复 Worker 可以折叠，但存储、沙箱、MCP 和执行宿主这些关键边界必须保留。

画面：Codex 或 WorkBuddy Runtime Map；点击 Storage Service、Node REPL、Shell 显示解释。

### 04:05–04:45 Agent 说完成，不等于验证通过

> 我们严格区分 Observed、Agent reported complete 和 Verified。Agent 自己说任务完成时，结果仍然是黄色。只有独立的编译、测试或安全检查通过，结果才能变绿。

画面：黄色 `Agent reported complete` → 独立验证 → 绿色 `Verified`。

### 04:45–05:20 诚实说明边界

> 这是一个 Alpha 项目。没有 macOS Endpoint Security 权限时，我们不能保证抓到所有毫秒级短进程；TLS 和 SSH 正文不会仅靠 Socket 自动变成明文；模型从未展示、本地也从未保存的隐藏思维链，我们无法读取。无法证明的事实会显示 Unknown，而不是猜测。

画面：Collector Health / Evidence Coverage / Unknown。

### 05:20–05:45 结尾

> 我做 AgentReins 的初心很简单：让每个人都能看懂、验证并信任自己的 AI Agent。项目已经开源，支持 macOS，官网提供 Apple 芯片和 Intel 版本。如果你正在使用 Codex、Cursor、WorkBuddy 或其他 Agent，欢迎用真实任务测试它，也欢迎把漏采证据和适配需求提交到 GitHub。

画面：Logo、中文官网、GitHub、X。

## 投稿简介（可直接复制）

AI 编程 Agent 已经可以读取项目和记忆、请求模型、调用 MCP、执行 Shell、修改代码并连接服务器。但用户最终往往只看到一句“任务已完成”。

这期视频用一个真实任务拆解 Agent 背后的完整执行链：

- 用户需求与模型上下文
- 模型服务商与第三方中转
- Tool、Skill、MCP 和 Shell 调用
- Agent Runtime Map 与子进程职责
- 网络、SSH、文件、代码和记忆变化
- “Agent 声称完成”与独立验证的区别

AgentReins 是一个面向 macOS 个人 AI 编程 Agent 的本地优先安全与透明度项目。无法证明的事实会显示 Unknown，而不是猜测。

项目开源地址：
https://github.com/yardfribley-bit/AgentReins

中文官网：
https://www.chuhaijian.com/zh-CN/

X：
https://x.com/agentreins

邮箱：
yardfribley@gmail.com

## 推荐分区

首选：`科技 → 计算机技术`

如果视频更偏真实开发流程，也可以选择编程相关的细分分区。不要选择资讯分区，因为核心价值是原创技术演示。

## 推荐标签

`AI`、`人工智能`、`网络安全`、`编程`、`AI编程`、`Agent`、`Codex`、`Cursor`、`MCP`、`开源`

标签不要同时堆叠大量不相关模型名称。视频中真实展示哪个 Agent，就优先保留哪个标签。

## 动态文案

> 我把 AI 编程 Agent 的后台执行链拆开了。
>
> 一句简单需求背后，它向模型发送了什么？经过哪个中转？调用了哪些 Tool / MCP？启动了什么进程？修改了哪些文件？它说“完成”以后，结果真的通过验证了吗？
>
> AgentReins 尝试把这些分散证据还原成一条普通人也能看懂的 Live Task。首个 Alpha 版本已经开源，欢迎用真实任务测试和挑错。

## 置顶评论

> 这是 Alpha 版本，我们尤其需要三类反馈：
>
> 1. 你希望优先支持哪个 AI 编程 Agent？
> 2. 哪类 Agent 行为最让你不放心：上下文、中转、MCP、外部网页、代码还是记忆？
> 3. 如果出现漏采或错关联，请把可复现步骤提交到 GitHub Issue。无法证明的地方，我们会明确显示 Unknown。
>
> GitHub：https://github.com/yardfribley-bit/AgentReins

## 发布前检查

- 使用中文真人口播或经过人工调整的自然声音，避免机械配音。
- 第一屏在 5 秒内出现具体问题，不要先播放长 Logo 动画。
- 必须展示至少一次真实任务和真实证据，不使用全程静态效果图。
- 屏幕录制隐藏真实 API Key、密码、个人文件和服务器凭据。
- 字幕烧录，1080p 横屏，关键字段放大，移动端也能看清。
- 声明“自制”，不要声明独家，便于同步 YouTube、X 和 Product Hunt。
- 简介中的 GitHub、官网、X 与邮箱逐个验证。
- 发布后前 2 小时优先回答技术质疑，不用模板化回复。

## 后续内容系列

1. 《第三方 AI 中转到底能看到什么？一次真实请求拆解》
2. 《Codex 的进程结构：Node REPL、存储、沙箱分别在做什么？》
3. 《MCP Server 有多大权限？如何判断一个工具是否危险》
4. 《AI Agent 的长期记忆，如何被一次提示注入永久污染》
5. 《Agent 说测试通过，为什么我们仍然不相信它》
