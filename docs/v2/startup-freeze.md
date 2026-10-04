# 启动卡顿取证与修复

2026-10-03 至 2026-10-04，本机 v2 预览实测。

历史提交 9ba0120（Fix dashboard switching and indexing stalls）已包含在基础提交 e838fb5 中；其后台派生投影修复没有被 v2 覆盖。当前变更前，CPU 约 97%，主线程取样几乎全部停在 WebAgentSight / CursorSight 的 EvidenceDatabase.updateHealth → sqlite3_step → SQLite busy handler。后台 claimParseJob 同时长时间查询并占用数据库写事务。

修复一：原同步 updateHealth 保留供后台和测试使用，采集回调改用 enqueueHealth。每个数据库实例后台串行执行，按来源合并待写健康快照，界面侧不等待 SQLite 锁。正文和游标持久化未改为易丢失的 UI 队列。

修复二：解析领取由逐候选检查历史前驱，改为 materialized 分区未完成首项投影。重试等待、运行租约、隔离记录阻塞同分区的语义保留；只领取到期可运行首项。不删除积压证据。

验证：写锁占用时连续提交 100 条健康快照不等待写锁，释放后最新状态落库。持久化、协议与处理流水线回归共 26 项通过。主线程修复后的实际采样显示主要处于事件循环等待，没有原健康写入阻塞。最终应用重新打包。

本机约 5 万条待解析历史任务仍会造成后台负载；未宣称 CPU 性能问题全部解决。不能通过关闭采集、清空历史数据或隐藏缺口来消除卡顿。

最终包再次启动并取样：主线程未出现 updateHealth 或 SQLite busy handler，正常处于 AppKit 事件循环；后台仍有积压处理负载，尚需继续验证持续运行及真实点击交互。

## 统一写入入口（2026-10-04）

生产采集模块与 EventStore、历史页通过 `EvidenceDatabase.shared(url:)` 复用同一 writable connection。规范化路径作为注册键，实例内部递归锁串行化事务；任务详情仍使用独立只读连接。后台安全队列与搜索索引使用各自数据库，不合并到证据文件。

WebAgentSight 和 QoderSight 在采集后台队列中用 persistCollected 原子提交原文、事件和 checkpoint；只有成功提交后才推进界面持有的读取位置。失败保留原位置供下次重放，事件回调不会确认未持久化的数据。搜索索引计数也改为后台读取。

解析队列的候选查询和 JSON 解码在 BEGIN IMMEDIATE 之前执行。领取工作时条件更新校验待处理状态与租约到期时间，防止其他进程在查询与领取之间抢先领取造成重复处理。进程间仍依赖 SQLite 锁与租约；本次修改没有引入 Kafka，也没有宣称彻底消除大历史查询的 CPU 消耗或将所有内存队列改成磁盘队列。

验证：CollectorHealthResponsivenessTests、DurableEvidencePipelineTests、SecurityEvidenceStreamTests、PipelineArchitectureAcceptanceTests 合计 27 项通过（0 失败）。重新打包启动预览进程 98957，3 秒采样 `/private/tmp/agentreins-unified.sample.txt` 中主线程没有 sqliteDefaultBusyCallback，也没有 saveCheckpoint/updateHealth/persistCollected 写入栈，主线程在正常事件循环等待。该采样不代表持续 UI 操作或所有高负载场景均已验证；后台积压处理 CPU 开销仍需后续评估。
