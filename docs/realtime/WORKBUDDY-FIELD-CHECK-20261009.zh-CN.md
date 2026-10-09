# WorkBuddy 实际任务采集验收：REA 调研

时间：2026-10-09 19:12–19:19。原始需求：**最近开源项目 rea 很火帮我调研一下**。

会话 `b2ea545b-1ce3-466b-8825-d2ca1e7d8ed5`；原生轮次 `4bd7aab5-b8ed-45d6-b7c3-a921487848a6`。

## 已核对的实际链路

- 原话：本地 prompt 和 UserPromptSubmit Hook 都有真实文本。
- 模型：已采完整 HTTPS 请求与对应返回，并与原生轮次关联；本地记录另有思考摘要和后续回复。不以本地片段称完整上下文。
- 执行：两次 WebSearch、两次 Bash、一项 Write、一项 present_files 调用及其返回（6 个本地 call/result）；Hook 另有开始／结束与进程关联记录。
- Bash：实际通过 gh api 拉取仓库元信息、Release、提交与 README。原生返回含 Command、Stdout、Stderr、Exit Code，现场发现并修正分栏解析。
- 文件：报告 `/Users/jatsmith/WorkBuddy/2026-10-07-14-17-32/rea-research-report.md` 实际存在，9,766 字节；原生 present_files 返回该路径。已修正产物提取并核对预览。
- 结束：收到 Stop Hook，其没有 turn_id，但有 last_assistant_message。仅当同 Agent／会话内原生最终回复正文唯一匹配时关联轮次；多轮相同内容保持未关联。已修正完成看板。
- 网络：模型请求资源 `copilot.tencent.com/v2/chat/completions`，观察到远端 IP `36.150.72.74`；系统连接、搜索结果链接与真实资源请求分开表达。搜索结果链接不证明本机打开过这些网站。

已采当前会话快照含 78 条记录（含 Hook 进程协调观察），不把所有观察都算成执行步骤。

## 现场修复与验证

1. WorkBuddy Bash labelled envelope 提取 stdout／stderr／退出码，非零退出只标步骤失败。
2. Stop 与原生最终答复唯一精确匹配后标任务完成；无匹配／歧义不完成其他轮次。
3. 仅原生 present_files_result 的 files 列表可作为交付物候选，再核对本机文件。
4. 实际采集快照经后端投影及原生 WebKit 运行，确认需求、成功 Bash、WebSearch 返回、存在报告及完成看板。47 项相关测试通过，包含该现场快照检查。

现场证据：`/private/tmp/agentreins-workbuddy-field-active.json`；真实投影与截图：`/private/tmp/agentreins-workbuddy-field-ui/actual-workbuddy-payload.json`、`actual-workbuddy-board.png`；测试日志：`/private/tmp/agentreins-workbuddy-field-ui.log`。不将现场正文提交到 Git。

## 不能由此次任务证明的能力

- 此任务没有原生运行中逐行输出事件，Bash 展示的是最终输出，不能宣称逐行直播已验证。
- 没有 MCP／Skill 执行记录，不能宣称这两类现场覆盖已通过。
- gh api 命令参数是已执行命令证据，但不代表已采到每条 GitHub HTTP 请求的完整资源正文／连接。外网资源级覆盖仍需独立验证。
- 报告文件存在和可预览不代表内容准确或用户认可；本次仅验收采集与可视化链路，不核验 REA 调研结论。
- 开发期间原生界面截图读取的是此次实际已采快照；用户任务完成前的运行中图仍需更多慢任务检验。
