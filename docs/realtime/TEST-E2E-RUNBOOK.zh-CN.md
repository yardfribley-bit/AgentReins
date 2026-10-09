# AgentReins 连续验收任务执行手册

版本：2.0 · 2026-10-09 · 真实任务步骤尚未执行；不把夹具自检计为产品通过。

## 1. 固定环境准备

终端A（仓库根目录）：

```sh
QA_ROOT="$(mktemp -d /private/tmp/agentreins-acceptance-XXXXXX)"
rmdir "$QA_ROOT"
python3 Tests/Manual/lifecycle/fixture.py init --root "$QA_ROOT"
python3 Tests/Manual/lifecycle/fixture.py serve --root "$QA_ROOT"
```

init要求目录不存在，避免复用旧证据；mktemp仅用于获得唯一目录名，再删除空目录，不删除任何已有资料。serve只监听127.0.0.1随机端口，终端保持前台运行。复制打印的ROOT和服务URL到运行记录。终端B在同仓库操作，手动将QA_ROOT设为终端A打印的准确路径；不得误用其他业务目录。

固定脚本路径：仓库绝对路径下 `Tests/Manual/lifecycle/fixture.py` 与 `verify.py`。记录二者SHA256。提交前准备独立saved prompt，不依赖AgentReins保存用户原话；在提交后核对源原生消息。

每次运行使用不同标记：`WB-RUN-A01`、`CX-RUN-A01`等。把下文`ROOT`、`FIXTURE`、`VERIFY`、`RUN_ID`替换成记录中的实际绝对路径和唯一标记，并保存替换后的完整提示词。占位符未替换不得开始。

固定源记录字段：来源文件/流、起始与结束字节位置或原生ID、Agent/session/turn/call/flow、时间、原始正文hash。测试数据库/投影引用不能替代源记录。

## 2. 主验收任务：E2E-04 网络、输出、文件、回流、验证、交付

### 提交原话（固定模板）

```text
验收任务 RUN_ID。
请只在 ROOT 内工作，不修改 fixture.py、verify.py 或输入样本：
1. 读取 ROOT/input/notes.txt，展示两行内容。
2. 执行：python3 "FIXTURE" run --root "ROOT" --case stream --run "RUN_ID-STREAM"
3. 执行：python3 "FIXTURE" run --root "ROOT" --case report --run "RUN_ID"
4. 执行：python3 "VERIFY" --root "ROOT" --run "RUN_ID"
5. 读取 ROOT/output/RUN_ID/report.md，展示报告，并给出实际文件路径。
如出现错误，请展示实际错误，不要编造成功。不要访问本地夹具以外的网络，不要安装依赖。
```

### 逐步验收

| 检查点 | 独立事实O | 来源S/E | 页面U与判定 |
| --- | --- | --- | --- |
| 原话进入 | 测试者保存的完整submitted.txt | 原生用户消息及turn | 任务出现，原话逐字一致；找任务≤2次点击 |
| 材料 | input/notes.txt的2行与hash | 实际Read/命令返回 | 显示已返回材料，不能仅路径算全文 |
| 持续执行 | runner中5行及exit时间 | 原生工具开始/输出/返回 | 1—4行在exit前可见；stdout/stderr与来源一致 |
| 第一次HTTP请求 | server日志429、attempt1 | 资源请求/返回或脚本输出 | 当前步骤保留限流；整任务继续，不提前失败 |
| 第二次HTTP请求 | server日志200、attempt2、正文hash | 第二次资源记录 | 展示请求URL、方法、两次状态；脚本内部重试不冒充两次Agent工具调用 |
| 文件产生 | output/RUN_ID/weather.json及report.md | 写入/工具返回/系统观察 | 两文件真实存在，内容与hash一致；独立系统观察关联依据明确 |
| 结果回流 | 工具实际返回内容 | 下一原生模型请求/消息 | 有实际请求则确认回流；只有本地片段不能称完整模型请求 |
| 验证 | verify独立检查数据/报告/服务日志 | 实际验证调用和返回 | 退出0且verified=true；验证范围正确，不声称天气真实性 |
| 交付 | 原始文件字节及最终答复 | 原生结束/最终回答 | 完成未读，产物最多2次点击可预览，路径可打开 |

script report内部生成文件这一事实不证明Agent原生Write调用发生；没有原生Write就显示命令生成文件，不能补造工具。系统文件/网络观察在各自来源核对，不以脚本stdout替代多源采集。

### 独立对账命令（测试者执行，不由页面生成）

```sh
python3 Tests/Manual/lifecycle/verify.py --root "$QA_ROOT" --run WB-RUN-A01
shasum -a 256 Tests/Manual/lifecycle/fixture.py Tests/Manual/lifecycle/verify.py
shasum -a 256 "$QA_ROOT/output/WB-RUN-A01/weather.json" "$QA_ROOT/output/WB-RUN-A01/report.md"
```

与提交前脚本hash比较，若被改动则场景不可信、失败。Agent执行verify的输出与测试者独立执行结果均保留；verify不能以P/U字段作为输入。

### 主任务失败判定

原话缺失/串任务；输出只在结束后一次出现；图中有实际未发生的调用；服务429被抹掉；只有IP却没有任务已知资源；产物假预览或打不开；验证未发生却标通过；原生结束前提前完成。任一发生，E2E-04失败并登记具体断点。材料/命令未按模板执行，场景未建立，不把缺少事件当功能通过。

本地任务不证明公网HTTPS覆盖；另完成RS-08并在R11结果中一起汇总。

## 3. 其余固定场景

### E2E-01：问候

前置P-LIVE/P-EVIDENCE。提交：`验收 RUN_ID：请原样回复“你好，实时验收”。不要调用任何工具。`

步骤：保存原话→查找任务→观察模型边界/最终答复→等待原生结束→查看结果卡。预期：最终文本包含指定内容，原话一致，不出现伪工具/文件；源不提供完整模型请求时缺口明确且R05不算完整通过。证据：submitted、原生消息与结束、事件/投影、原话和结果截图。收尾C0。

### E2E-02：写文件并读取

前置P-LAB。提交：`验收 RUN_ID：在 ROOT/output 创建 RUN_ID.txt，UTF-8内容恰为 hello 后接一个换行。读取并展示它，最后给出实际路径。不要修改其他文件。`

步骤：提交前确认文件不存在→提交→从图进入实际写/读→独立读取字节→完成卡打开。预期字节hex=`68 65 6c 6c 6f 0a`，实际工具形式照实展示，不强制Bash或Write；确认读返回、文件、产物一致。预存同名文件则换新RUN_ID；不得用旧产物通过。收尾保留文件与证据。

### E2E-03：命令全过程

前置P-LAB。提交：`验收 RUN_ID：只执行 python3 "FIXTURE" run --root "ROOT" --case stream --run "RUN_ID"，等待真实结束并报告退出码。`

步骤：录屏开始→提交→每行记录U可见时间→取得独立runner exit→核对5行/通道/时序。通过要求：A-STREAM；完整命令与目录可见；call/执行器有依据；退出0。第1—4行只在exit后出现属于失败，不能因最终文本完整而通过。结束后用源引用和录屏逐行对账。

### E2E-05：失败重试与业务错误

前置P-LAB，新RUN_ID。先运行主任务report（第一次429后200）；再单独提交执行`--case fail`与`--case business-error`的两个任务。

步骤：核对server原始两次请求→看失败分支与当前状态→核对后两任务的独立exit、业务failed及最终答复。预期：保留HTTP重试且最终成功；exit1明确；外层exit0的业务失败不被绿色掩盖。不要把脚本内部重试叫Agent重新调用；Agent重试需新原生调用证据。

### E2E-06：并行与阅读固定

前置P-LAB，两会话A/B。分别提交E2E-03，RUN_ID为A/B。A输出期间点开A详情并上滚，启动B。

步骤：记录A选中对象、投影版本、滚动/焦点→等待A/B各新增3条事件→不主动切换时查看页面→搜索B标记→切到B→返回A。

预期：A不混B行、不被抢走，阅读版本固定且有更新提示；搜索定位B具体命令，切回A可达最新结果。独立runner日志各自5行，各自call/turn不混。保存全程录屏、两组源与投影。两端均执行；另做跨Agent并行ID-01。

### E2E-07：真实审批/单任务取消

前置P-CONTROL，测试运行表必须写明来源实际原生接口/人工确认路径，不允许只有原型按钮。使用不安装依赖的隔离目录写入审批动作；取消用持续命令，另一个任务同时运行。

步骤：核对审批前没有副作用→允许/拒绝分别新任务→保存原生决定→运行A/B→取消A→核对原生确认、A结束与B继续。

预期同CTL-01/02；无控制通道记阻塞，不通过按钮本地变色放行。控制不是强行结束整个WorkBuddy/Codex应用。收尾仅测试任务，恢复原权限。

### E2E-08：中断与恢复

前置已采原话且stream运行中；保存活跃检查点与源水位。只重启AgentReins实时应用，外部Agent与夹具不重启。

步骤：退出前快照→记录退出时刻→重启同版本→查原任务原话/调用→核对停机期源记录及后续结果→比较去重和用量。

预期：原话与身份恢复；停机缺口明确；不扫描旧任务正文回填；无重复任务/计量；工具返回缺失不能假完整。另做CAP-02短暂断源变体。收尾确认自有代理及全部采集来源恢复。

## 4. 公网与IP归属专项补充

执行RS-08前填写：受控实际HTTPS URL、允许访问方法、预期响应内容及hash、服务访问日志入口、DNS解析时间/IP、独立IP数据库版本/时间、允许的查询方式。缺任一关键基准记环境阻塞，不把真实第三方服务临时随意替换。

只核对实际资源访问，不主动探测目标补造网页。UI归属估计须和指定库记录一致，不用“真实服务器物理位置”作无法取得的预期。查询失败时看降级，不伪造城市/ASN。该专项与本地server测试分开报告。

## 5. 证据收集、恢复与交接

保存submitted、脚本hash、runner/server、文件hash、源字节区间、E/P快照、U录屏/截图及逐断点结果到本RUN目录。将无关任务和凭证排除；外部源限制不能被测试投影补造。

收尾：终端A Ctrl-C停止仅该服务；停止自己启动的剩余测试命令，恢复测试用权限/代理；确认原采集来源正常。保留ROOT，不自动删除。按报告模板给出通过、失败、阻塞和待复核，不写笼统“链路正常”。

测试接手者照本手册重新建立不同ROOT和RUN_ID，独立重复，不复用前次产物。复核者未执行时状态仍为待复核。
