# AgentReins 用户配置指南

AgentReins 是面向桌面编码智能体（Kiro / WorkBuddy / Codex / Cursor / Claude 等）的**运行时安全护栏**。它在 agent 落地动作前/后做三层防护：

1. **文件层**：监控并自动还原受保护文件的删除/修改。
2. **命令层**：实时监测 agent 运行的高危命令（`rm -rf`、`curl|bash`、读凭据等）。
3. **记忆体审计层**：扫描 agent 记忆文件，检测是否落盘了密钥/令牌/私钥等敏感信息。

App 里有两套**用户可自主配置的规则库**：

- **Agent 规则库**（左侧自然语言添加）：控制文件保护、命令监测。
- **记忆体规则库**（左侧「记忆体规则」区域）：控制扫描哪些敏感信息类型。

---

## 一、Agent 规则库（文件 + 命令）

### 1.1 添加方式

在左侧输入框用**自然语言**描述规则，点「添加规则」。例如：

| 你想拦的动作 | 输入示例 |
|---|---|
| 保护项目配置文件 | `agent 不允许 删除 修改 我项目中的 .env 文件` |
| 保护 SSH 私钥 | `agent 不能读取 ~/.ssh/id_rsa` |
| 阻止强制推送 | `agent 不能执行 git push --force` |
| 禁止递归删除 | `agent 不能执行 rm -rf` |

解析结果会落到「Agent 规则」列表，右侧「拦截规则」面板也会同步显示。

### 1.2 规则类型

- **文件保护规则**：监控指定路径的 `delete`、`modify`、`read`、`move`、`rename`、`execute`，命中后自动从备份还原（soft restore）。
- **命令监测规则**：用正则匹配 agent 进程树中执行的命令，目前只做**可视化展示**（看到 agent 在跑什么），硬拦截需要配合 `agentguard-esf` 的 Endpoint Security Framework 系统扩展。

### 1.3 内置命令规则（默认启用，不可删但可查看）

| 规则 | 严重级 | 说明 |
|---|---|---|
| `rm -rf` | critical | 递归强制删除 |
| `curl \| bash` / `wget \| bash` | critical | 下载即执行 |
| 读 `~/.ssh` / `~/.aws` / `.env` | high | 读取敏感凭据/配置 |
| `git push --force` | high | 强制推送 |
| `sudo` | medium | 提权执行 |

---

## 二、记忆体规则库（敏感信息检测）

### 2.1 作用

Kiro、Claude、Cursor、Codex 等 agent 会把会话、全局记忆、知识库、规则、执行日志落盘到本地。AgentReins 会扫描这些位置是否保存了密钥/令牌/私钥/数据库连接串。

覆盖位置：

- `~/.kiro/crew/workspace/memory/`
- `~/.kiro/knowledge/memory/`
- `~/.kiro/steering/`
- `~/.kiro/sessions/cli/`
- `~/.agent-memory/`
- `~/Library/Application Support/Kiro/`
- `~/.claude`、`~/.cursor`、`~/.codex`

### 2.2 内置记忆体规则

左侧「记忆体规则」区默认列出 11 条规则，每条可单独开关：

| 规则名 | 检测内容 | 严重级 |
|---|---|---|
| AWS Access Key ID | `AKIA...` | high |
| AWS Secret Access Key | `aws_secret_access_key=...` | high |
| OpenAI API Key | `sk-...` | high |
| Anthropic API Key | `sk-ant-...` | high |
| GitHub Token | `ghp_...` / `github_pat_...` | high |
| Google API Key | `AIza...` | high |
| Stripe Secret Key | `sk_live_...` | high |
| Slack Token | `xoxb-...` | high |
| Private Key Block | `-----BEGIN PRIVATE KEY-----` | critical |
| DB Connection String | `postgres://user:pass@...` | high |
| Generic Secret Assignment | `api_key="..."` / `password="..."` 等 | medium |

### 2.3 自定义规则

点左侧「记忆体规则」→「添加自定义规则」，填写：

- **规则名称**：如「公司内网 Token」
- **描述**：可选，方便自己识别
- **正则表达式**：标准的 Python `re` 正则，会被传给 `agentguard-memory-scan.py`
- **严重级**：critical / high / medium / info

自定义规则可随时删除；内置规则不能删除，只能关闭或点「恢复默认规则」重新启用全部。

### 2.4 扫描触发

- **立即扫描**：右侧切成「记忆体审计」→「立即扫描」。
- **每日自动**：右侧「记忆体审计」→ 打开「每日自动」。App 启动 2 秒后会先扫一次，之后每 24 小时自动扫。

### 2.5 记忆体 Inspector（结构 + 内容 + 修正）

扫描完成后，「记忆体审计」面板变成**三栏 Inspector**，既能看结构、也能看内容、还能就地修正：

- **左栏 · 结构树**：按 agent（Kiro / Claude / Cursor / Codex 等）分组列出记忆文件，每个文件标注 `命中数` 或 `干净` 与大小。点文件即选中。
- **中栏 · 内容**：显示选中文件的原文，**命中的敏感行高亮**（带行号）。SQLite 二进制库不内联显示，仅列出命中（脱敏预览）。点敏感行即选中该命中。
- **右栏 · 修正面板**：
  - 选中某处命中后，给出 **打码**（敏感片段 → `***`）、**删行**（仅删该行）、**忽略**（取消选中）。
  - 未选中命中时，给出 **编辑全文**（弹编辑器改整文件）、**还原 .bak**（撤销到编辑前备份）。
  - **所有写回操作改前自动备份**：原文件复制为 `<文件名>.agentreins.bak`，可随时一键还原，避免误伤正常记忆。

> ⚠️ 修正（打码/删行/编辑）会真实改写 agent 的记忆文件。建议优先用片段级「打码/删行」，不要整文件自由编辑，以免破坏 agent 记忆功能。SQLite 库不支持内联打码/删行，只能手动编辑或还原。

> 首次扫描前，需要在 **系统设置 → 隐私与安全性 → 完全磁盘访问权限** 中把 `AgentReins.app` 勾选，否则无法读取 `~/.kiro`、`~/.ssh`、`~/Library/Application Support/Kiro` 等受 macOS 保护的目录。

---

## 三、模型配置（自然语言解析）

默认勾选「使用 LLM 解析」，App 会调用你填写的 OpenAI 兼容接口把自然语言转成规则。支持：

- OpenRouter：`https://openrouter.ai/api/v1`，模型如 `tencent/hy4-preview`
- OpenAI：`https://api.openai.com/v1`，模型如 `gpt-4o-mini`
- DeepSeek：`https://api.deepseek.com/v1`，模型如 `deepseek-chat`
- Ollama：`http://127.0.0.1:11434/v1`，模型名填本地模型

若留空 API Key 或 LLM 调用失败，App 会自动回退到**本地关键词解析**（识别率略低但离线可用）。

---

## 四、首次使用流程

1. 双击 `AgentReins.app`。
2. 若系统提示「无法验证开发者」或「已损坏」：
   - 系统设置 → 隐私与安全性 → 找到 AgentReins → 点「仍要打开」；或
   - 右键 `AgentReins.app` → 打开。
3. 在系统设置 → 隐私与安全性 → **完全磁盘访问权限** 中勾选 AgentReins。
4. 在 App 左侧添加 Agent 规则，在「记忆体规则」区确认需要启用的检测项。
5. 点「启动监控」，切换到右侧「实时运行过程」或「记忆体审计」查看结果。

---

## 五、常见问题

### Q1：打开 App 后窗口一直转圈圈？

已修复。原因是旧版本在主线程同步访问 `~/.kiro`、`~/.ssh` 等受 TCC 保护目录时，macOS 弹权限窗导致主线程死等。当前版本已把所有文件/子进程操作移到后台线程并加 20 秒超时。

### Q2：记忆体审计扫不到任何内容？

检查「系统设置 → 隐私与安全性 → 完全磁盘访问权限」里是否已授权 AgentReins。如果未授权，扫描器无法读取 agent 记忆目录。

### Q3：命令层只是展示，没有真正拦截？

是的。当前 `ProcessGuard` 只负责**可视化监测**（看到 agent 在跑什么命令），真正的硬拦截需要 macOS Endpoint Security Framework 系统扩展 + Apple 特殊授权 `com.apple.developer.endpoint-security.client` + Developer ID 签名/公证。

### Q4：想把 App 发给朋友用？

当前是 **ad-hoc 签名**，只能在你本机打开。要分发需要：

1. Apple Developer Program 账号（$99/年，和你做 iOS 的账号是同一个）。
2. 向 Apple 单独申请 ESF entitlement。
3. Developer ID 签名 + 公证(notarization)。

---

## 六、构建命令（开发者）

```bash
cd AgentGuardApp
./package_app.sh
# 产物：AgentReins.app（已 ad-hoc 签名 + 清除隔离属性）
```

---

## 七、文件结构速览

```
AgentGuardApp/
├── Sources/AgentReins/
│   ├── AgentGuardApp.swift        # App 入口，注入两套规则库
│   ├── ContentView.swift          # 主 UI（Agent 规则 + 记忆体规则配置）
│   ├── Rule.swift / RuleStore.swift         # Agent 规则库模型与持久化
│   ├── MemoryRule.swift / MemoryRuleStore.swift   # 记忆体规则库模型与持久化
│   ├── MemoryScanManager.swift    # 调用扫描脚本（后台+超时）+ 文件读取/打码/删行/编辑/还原
│   ├── MemoryFile.swift           # 记忆体文件节点模型（结构树 + 命中）
│   ├── FileGuard.swift            # 文件层监控/还原
│   ├── ProcessGuard.swift         # 命令层监测
│   ├── NLParser.swift             # 自然语言 → 规则
│   └── UIHelpers.swift            # 配色/文案辅助
└── package_app.sh                 # 一键编译、签名、清隔离，产出可双击 .app
```

---

## 八、版本 / 关闭行为 / 资源占用

### 关闭行为（已修复「无法关闭」）
- **关闭窗口 = 退出程序**：点窗口左上角红叉即彻底退出（Dock 中也消失），不再后台残留。
- 退出时会自动强杀可能正在运行的记忆体扫描子进程，不留下 python 孤儿进程。
- 若你希望「关窗后继续后台监控」，告诉我，我可以把该行为改成可切换。

### 版本与是否最新
- App 左下角显示：`v1.1.0 (build 20260903.xxxx) · 开发编译版（未公证，非发布版）`
- 下面一行：`构建于 YYYY-MM-DD HH:MM · 重新打包后会更新此时间，可据此判断是否最新`
- 因为没有发布服务器/自动更新，判断手里的 .app 是否最新，看「构建于」时间与重新打包时间即可。

### 资源占用（实测）
- **主程序常驻 ≈ 86 MB**（物理 footprint，峰值 92 MB）。
- 记忆体扫描时临时起一个 python3 子进程，额外 ~25–40 MB，**扫完即退出，不常驻**。
- 文件/命令轮询开销可忽略。

---

> 当前版本为本地编译版（未公证），主要面向本机自用与功能验证。硬拦截与跨机分发需 Apple ESF 授权 + Developer ID。
