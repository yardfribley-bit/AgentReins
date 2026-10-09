# GitHub上传网络采集断层修复（2026-10-10）

## 本次事实与根因

实际上传的Git进程链为Codex CLI → Git → Git → git-remote-https，HTTPS helper PID 12300。00:12:08.79进入观察，00:12:15.54记录消失，约6.8秒。00:12:09.131已采到TCP `127.0.0.1:62129 → 127.0.0.1:1081 ESTABLISHED`；V2rayU元数据在00:12:08确认同一客户端端口的目标为`github.com:443`。

原逻辑在新进程的定向采样中只保存进程socket活动，跳过代理日志读取和kind=network事件输出。十秒周期扫落在进程启动前和退出后，任务图没有网络记录。不是Git没有网络，也不是原始TCP采集完全失效。

另有三项缺口：按工具URL覆盖其它进程的socket域名；worktree及真实workdir没解析使`git push origin`缺仓库目标；只含CommandExecution完成记录时命令参数没有进入执行详情。

## 修复

- 定向与周期采样都输出网络事件并读取代理目的地，使用同一批已验证PID出生身份的进程快照。
- 保留原始socket端点、PID/出生身份、TCP状态、代理来源/时间。只有相同客户端端口、十五秒内和匹配进程出生窗口的路由才确认目标；未知路由保留本机连接，不猜外部IP。
- socket观测域名不被工具请求域名覆盖；修复已采活跃展示中的上述旧标签。
- 工具目标解析支持实际workdir、file URL、git -C、worktree gitdir/commondir、remote及pushurl。目标记录明确wireObserved=false，不生成HTTP方法、响应码或网站IP。
- 仅完成记录也展示原始argv命令与工作目录，逻辑执行器ID不当OS PID。
- API/网络模块同时显示网络记录数量，详情分别排版系统连接、代理目标、工具目标；WebSearch等原有工具返回仍可查看。

## 验证

相关Swift回归168项，167通过、1项旧研究现场资料缺失跳过、0失败；实际Git socket与代理原始元数据回投验证、worktree仓库目标和命令详情验证通过。浏览器实际片段点击验证通过，未以构造HTTP请求代替源记录。

日志在本机私有临时目录：`agentreins-github-network-final-tests.log`、`agentreins-git-network-ui.log`。原始代理行、JSONL、数据库切片没有加入Git。

仍需区分：采样可能漏掉短于进程发现间隔的活动；Git HTTPS本次没有HTTP正文/服务器IP，代理目标和Git仓库目标不能冒充解密HTTP。新一轮只读访问现场结果另行补入本记录。


## 新一轮运行采集器验收

对原仓库进行了3次只读git ls-remote（没有重新上传），每次约2.7—2.9秒。Git HTTPS helper PID 21482、21517、21559在定向采样中均产生network/connect：原始连接127.0.0.1:1081保留，代理日志分别匹配clientPort 51540、51550、51552 → github.com:443。三条均未强行补session/turn/call，旧的执行、资源、socket、IPC和退出记录也都保留。

现场随后发现未归属网络记录被通用最新200条列表挤出。因此增加独立最近100条网络记录保留和重启恢复；任务图网络模块另列同Agent独立观察，点击显示未关联状态。没有把观察伪装成当前工具因果关系。对应回归确保250条后续资源采样不会让网络记录消失。


最终实时界面检查通过：3条GitHub独立连接在网络模块可点开，显示实际代理端点、V2rayU目标以及“未确认任务归属”。它们在后续资源采样之后仍保留，当前截断和保存错误均为false/无。网络独立观察保持来源区别，不被硬挂到当前任务。
