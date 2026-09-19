# ZCode Security Intelligence Pilot

> 基于 2026-09-19 本机 ZCode 实测会话、ZCode 本地数据库、运行日志、发行包 `zcode.cjs` 与 AgentReins 操作系统证据形成的第一版安全情报样稿。

## 先给用户看的结论

### 本次任务发生了什么

ZCode 在一个本地工作区内执行了长链路开发任务。AgentReins 关联到 **21 次模型请求、18 次工具调用、937,207 个累计输入 tokens、908,160 个缓存读取 tokens 和 24,032 个输出 tokens**。ZCode 将任务上下文发送至其声明的 `GLM-5.3` 路由，并在任务期间创建或修改项目文件、安装第三方依赖，同时产生多类外部网络连接。

### 风险判断

**总体风险：中等，需要知情。**

没有证据证明本次任务上传了 SSH 私钥、API Key、其他项目或完整 Git 历史；但已确认或高度确信以下事实：

1. 本机身份与开发环境信息进入了 Agent 上下文；
2. 工作目录、用户需求、工具结果和任务代码会在后续模型轮次中持续复用；
3. 上下文最高增长到 64,086 tokens，存在明显膨胀和敏感信息传播半径扩大的风险；
4. ZCode 使用第三方 Electron 镜像，并执行了带 `--no-audit` 的依赖安装；
5. ZCode 会连接模型服务、产品遥测和网页相关域名，但当前网络归属只能达到进程/时间关联，不能把每个域名都断言为模型请求；
6. 完整 HTTPS Request Body 未保留，因此不能逐字证明每一轮实际上传的全部字段。

### 用户应该做什么

- 查看“发送给模型的数据摘要”，确认工作目录、代码和工具输出符合预期；
- 对第三方镜像和 `--no-audit` 进行供应链复核；
- 不要把“ZCode 自报没有读取敏感文件”当作独立证明；
- 对新的项目任务启用项目边界、敏感文件读取和外联目的地规则；
- 如果需要证明具体文件内容是否上传，下一轮应保留请求正文或建立内容指纹匹配。

---

## 情报卡 1：模型上下文持续膨胀

**情报类型**：Context Exposure / Context Growth
**严重度**：Medium
**可信度**：Confirmed for token usage；Correlated for content reuse
**影响范围**：当前 ZCode Session

### 已确认

| 指标 | 实测值 |
|---|---:|
| 成功模型请求 | 21 次 |
| 累计输入计费量 | 937,207 tokens |
| 累计缓存读取 | 908,160 tokens |
| 累计模型输出 | 24,032 tokens |
| 单次最小输入 | 38,280 tokens |
| 单次最大输入 | 64,086 tokens |
| 本地保存的 reasoning | 58,631 字符 |

### 安全价值

这不是单纯的费用统计。上下文越长，之前读取过的路径、代码、工具结果和敏感数据在后续请求中继续存在的概率越高。AgentReins 可以进一步识别：

- 哪一轮开始明显膨胀；
- 哪次工具结果造成增长；
- 哪些内容在多轮请求中被重复携带；
- 敏感信息进入上下文后持续了多少轮；
- 压缩后是否丢失用户的原始需求或安全约束。

### 证据边界

Token 规模来自 ZCode 本地 `turn_usage`，属于可验证的本地记录；具体每轮完整正文当前没有独立网络载荷证据。

---

## 情报卡 2：模型路由与上游身份

**情报类型**：Model Route Intelligence
**严重度**：Medium
**可信度**：Confirmed for declared route；Inferred for independently verified upstream

### 已观察

```text
Provider: account:zai-start-plan
Model: GLM-5.3
Endpoint: https://zcode.z.ai/api/v1/zcode-plan/anthropic
Transport: SSE
```

AgentReins 在同一 Session/Turn 的操作系统网络证据中观察到 `zcode.z.ai`。发行包 `zcode.cjs` 中也可以定位到 `zcode.z.ai` 字符串。

### 安全价值

三层证据可以被分开表达：

1. **实现声明**：`zcode.cjs` 包含模型路由实现或配置痕迹；
2. **Agent 自报**：会话库声明 Provider、Model 与 Endpoint；
3. **系统观察**：ZCode 归属进程实际连接到对应域名/IP。

只有三者一致时，才能把结论从“UI 显示 GLM-5.3”提升为“发行实现和运行行为均与 GLM-5.3 路由相符”。即便如此，如果存在中转，仍不能仅凭域名证明最终上游模型身份。

### 产品输出示例

> **模型路由基本一致，但上游身份未完成密码学验证。**
> ZCode 声明通过 `zcode.z.ai` 使用 GLM-5.3；本机确实观察到该域名连接。当前没有上游模型证明或完整响应指纹，因此将模型身份标记为 `declared + route observed`，而不是 `verified upstream`。

---

## 情报卡 3：供应链安全信号

**情报类型**：Dependency Supply Chain
**严重度**：Medium
**可信度**：Confirmed

### 已确认

ZCode 执行：

```bash
ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/ \
npm install --no-fund --no-audit
```

### 为什么重要

- Electron 二进制来自第三方镜像，而非默认上游；
- `--no-audit` 主动关闭 npm 漏洞审计；
- 安装行为由 Agent 自动触发，用户可能只看到“依赖安装成功”；
- 即使镜像本身合法，来源改变与审计关闭也必须成为可见的安全决策。

### 不能得出的结论

- 不能据此认定镜像恶意；
- 不能据此认定下载内容被篡改；
- 不能据此认定 ZCode 有恶意意图。

### 下一步独立验证

- 记录下载 URL、重定向链、文件哈希与签名；
- 将包哈希与官方 Electron Release 对照；
- 对 `package-lock.json` 和最终依赖树执行独立漏洞扫描；
- 检测安装脚本与原生二进制。

---

## 情报卡 4：外部网络行为分层

**情报类型**：Agent Network Surface
**严重度**：Needs Classification
**可信度**：Inferred attribution

AgentReins 在该 ZCode Session/Turn 周围观察到三类网络目的地：

### A. 模型与产品服务

- `zcode.z.ai`
- 多个暂未完成域名归属的 IPv4/IPv6 地址

### B. 产品遥测

- `zhipuaishengchan.datasink.sensorsdata.cn`

### C. 网页及广告分析相关域名

- `www.google.com`
- `www.google.co.jp`
- `www.googletagmanager.com`
- `analytics.google.com`
- `stats.g.doubleclick.net`
- `ad.doubleclick.net`

### 安全价值

AgentReins 不应把这些连接混成一张“网络列表”，而应该回答：

- 哪一个连接是模型流量；
- 哪一个是产品遥测；
- 哪一个来自 Agent 打开的网页；
- 哪一个来自用户自己打开的浏览器页面；
- 哪些 IP 尚未完成域名、ASN、云厂商和地理位置归属；
- 某次文件读取之后，是否出现与任务有关的新外联。

### 当前证据边界

上述网络事件目前多为 `operatingSystem + inferred`。它们与 ZCode Session/Turn 发生关联，但部分网页域名可能来自内嵌浏览器或页面子资源，不能直接称为“ZCode 主动把代码发给广告域名”。

---

## 情报卡 5：Agent 自报与系统证据的差异

**情报类型**：Evidence Integrity
**严重度**：High when conflicting

ZCode 本地数据库能够提供：

- 用户输入；
- Agent 对需求的理解；
- reasoning；
- 模型与 Provider；
- 工具名称、参数和结果；
- Token 使用情况；
- Todo 与任务状态。

但这些均属于 **Agent 自报证据**。AgentReins 的操作系统证据负责验证：

- 哪个进程实际读取了文件；
- 是否访问 `.git`、密钥或其他项目；
- 是否创建归档或临时文件；
- 实际连接了哪个域名/IP；
- 是否真的启动编译、测试或部署；
- Agent 宣布完成后是否存在独立验证动作。

### 冲突即情报

| Agent 自报 | 系统证据 | 情报结论 |
|---|---|---|
| 只读取当前项目 | 观察到读取项目外敏感文件 | 项目边界违规 |
| 未访问网络 | 进程存在外联 | 自报不完整或归属错误 |
| 已运行测试 | 未观察到测试进程 | 完成声明未验证 |
| 使用官方模型 | 实际连接未知中转 | 上游身份不可信 |
| 只生成本地索引 | 随后产生归档与大流量上传 | 高优先级数据外发调查 |

---

## `zcode.cjs` 能增加的情报价值

当前发行包中的文件：

```text
/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs
Size: 14 MB
SHA-256: 8f5cfccf2a899b92e57bc2a5760b949c1a928f739652fffc9e6d07c24f11ba05
```

这是发行版构建产物，不是完整开源源码。但它能作为“实现证据”，把底层行为映射为业务语义。

本机样本中可以直接找到：

- `zcode.z.ai`：8 处；
- `modelIoFullRetentionEnabled`：30 处；
- `no-audit`：3 处。

这些命中本身不等于风险结论，但能帮助建立稳定的 Runtime Profile：

```text
Context Engine
Model Router
Tool Executor
Permission Policy
Session / Reasoning Store
Memory & Skills
MCP Manager
Git / Checkpoint Service
Browser Automation
Telemetry
```

随后把 AgentReins 事件关联到具体组件，而不再只显示 `node`、`socket` 和文件路径。

---

## 最终可以形成的安全情报产品

### 第一层：用户一眼看懂

> ZCode 正在为一个 Electron 项目执行开发任务。它已向 GLM-5.3 路由发起 21 次请求，调用 18 次工具，最大上下文 64K tokens。它安装了来自第三方镜像的依赖，并关闭 npm audit。未发现密钥上传证据，但本机环境、工作目录、代码与工具结果进入了模型上下文。任务完成声明尚需独立验证。

### 第二层：安全人员可验证

- 完整时间线；
- 模型请求与 Token 演进；
- 工具调用、参数和结果；
- 文件读取、创建和修改；
- 网络目的地、ASN、云厂商与地理位置；
- Memory/Skill/MCP 注入；
- 进程和父子关系；
- 规则命中与策略结果；
- Agent 自报和独立证据冲突。

### 第三层：原始证据

- ZCode Session/Turn/Tool Call ID；
- `zcode.cjs` 文件哈希和代码位置；
- ZCode SQLite 原始记录哈希；
- AgentReins Raw Evidence 哈希链；
- 操作系统事件 ID；
- 网络和文件证据；
- Collector Health 与盲区说明。

---

## 这项能力真正的差异化

普通日志产品只能说：

> ZCode 连接了一个 IP，执行了 npm install。

Agent 自己只能说：

> 我安装了依赖并完成任务。

AgentReins 应该说：

> ZCode 为完成用户的 Electron 开发需求，从第三方镜像安装依赖并主动关闭 npm audit；该动作由第 N 次模型决策触发，对应工具调用为 X，下载进程和网络目的地已被系统证据观察。当前没有发现下载包哈希异常，但供应链验证尚未完成。随后 Agent 报告任务完成，是否真实通过测试仍需独立验证。

这就是可以对外传播、可以形成规则、也可以支持取证的安全情报，而不是日志堆积。

## 当前还缺什么

1. `zcode.cjs` 稳定语义索引：函数/模块/字符串到 Runtime Profile 的版本化映射；
2. 精确进程归属：降低浏览器子资源和 ZCode 主动访问之间的误关联；
3. 请求内容证明：通过官方 Gateway、可选代理或内容指纹证明具体字段是否外发；
4. 文件读取证据：尤其是 `.git`、`.env`、SSH、Memory 和项目外文件；
5. 下载物哈希与供应链验证；
6. 独立测试与任务完成验证；
7. 情报对象模型：Finding、Evidence、Entity、Relationship、Confidence、Blind Spot；
8. 跨版本比较：ZCode 更新后新增了哪些端点、工具、权限或数据流。

## 是否值得产品化

值得。建议将能力命名为：

> **Agent Runtime Intelligence — 发行实现、Agent 自报与系统行为的三方验证。**

第一阶段不追求证明厂商恶意，而是稳定回答四个问题：

1. Agent 为什么做这件事？
2. 它实际做了什么？
3. 哪些数据去了哪里？
4. 它声称的结果能否被独立验证？

这四个答案本身就是 AgentReins 可以产生的安全情报价值。
