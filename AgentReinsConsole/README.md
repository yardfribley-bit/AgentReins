# AgentReins 企业审计管理平台

独立于产品官网 `AgentReinsWebsite`。本工程不使用官网分析接口、账号、数据库、域名或部署目录。

## 当前交付

- 根据确认的管理端原型实现数据流向审计前端。
- 进程、敏感内容、记忆、模型请求、中转位置与归属四类证据对照。
- 原始证据完整保留，不在前端脱敏；按需展开完整关联 JSON。
- 默认真实接口模式；必须主动切换才展示模拟案例。没有自动演示数据兜底。
- 历史游标每页 20 条，手动加载；前台每 10 秒按更新游标读取最多 20 条摘要，不轮询全量历史或正文。后台标签页暂停。
- 当前详情保持原样；出现新证据时提示点击该任务重新读取。自动累积摘要保留约 100 条，历史仍可分页查看。
- 使用者（本机账号）、设备名、内网 IPv4 显示在任务主体行；稳定设备 ID 用于后台关联，不把账号当作已认证企业员工。旧客户端未采集的字段明确标注。
- 无法连接、权限失败、空记录、格式不兼容分开处理。
- “标记已核对”仅供演示；真实模式没有未经服务端授权的写入操作。

## 本地启动

`node dev-server.cjs`

访问 `http://127.0.0.1:8899/`。点“查看演示数据”，或访问 `/?demo=1`。
预览仅监听本机，没有审计上传服务，也不会连接已提供的云主机。

## API 契约

`GET /api/audit/cases?limit=20&cursor=<opaque>`

响应：`{schemaVersion:1, items:[{id, record}], nextCursor:null|string, updateCursor:string}`。
后续使用 `GET /api/audit/cases?after=<updateCursor>&limit=20` 获取新增与更新摘要，按更新顺序前进；不下载任务正文。
每页最多 20 项。record 包含字符串 title、who、summary、process、data、send、target、conclusion、limit、receipt。
views 包含 request、memory、relay、process；各项有 facts（解释标题与内容的二元字符串数组）、raw（完整 JSON 证据）。前端不将证据作为 HTML 执行。

完整证据由 `GET /api/audit/cases/<id>` 按需读取。列表不返回 views 或 snapshot。

`POST /api/audit/ingest` 接收 deviceID、sequence、snapshot 及可选 identity（localUser、deviceName、localIPs、observedAt）。身份采样与原始 snapshot 分开保留，重试包保持不变。重复序号内容冲突会被拒绝。仅接受设备启用后开始且有用户请求证据的任务。

`audit_server.py` 使用 SQLite 保存完整证据、入库回执和访问日志；写入使用设备令牌，读取使用独立管理员 HTTP Basic 认证，必须置于 HTTPS 后。凭据不入 Git。部分内嵌浏览器不支持 Basic 登录，暂用支持认证对话框的浏览器。

当前是单企业初版，不具备多租户隔离、员工目录绑定、细粒度角色权限、服务端组织策略或节点情报。它们不能从现有数据推断为已实现。`dev-server.cjs` 仅预览，真实部署使用服务脚本与 Nginx 配置。

## 验证

`npm install` 后运行 `npm test`；默认使用已安装 Chrome，可设置 AUDIT_BROWSER_CHANNEL。
测试覆盖无接口不显示假案件、证据类别切换、窄屏、空状态、游标分页与恶意原文按文本显示。
后端：`python3 -m unittest discover -s tests -p 'test_*.py'`。新增身份兼容、历史拒绝、幂等性、乱序版本及增量分页测试。
