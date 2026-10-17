# 实时系统事件能力探测

运行：

```sh
xcrun clang -fblocks tools/collection-preflight/main.c -lEndpointSecurity -o /private/tmp/agentreins-collection-preflight
/private/tmp/agentreins-collection-preflight
```

只创建并关闭 ES 客户端，不订阅系统事件，不修改权限，不请求认证事件，不阻断应用。不把成功创建客户端当作完整覆盖通过。退出 2 表示环境条件未满足，具体原因在 JSON 中；系统可能只报告最先遇到的条件，不能据此认为其他条件已满足。

2026-10-12 本机实测：编译成功，返回 requires_privileged_service。代码签名身份查询返回 0 valid identities；当前 package_realtime.sh 使用 ad-hoc 签名。未发现项目内 ES / NE entitlement 或系统扩展目标。未读取或更改开发者凭据。

## 事件版的实际交付依赖

- Endpoint Security：具备获批 entitlement 的签名及配置、特权服务部署、用户隐私授权。订阅进程创建/执行/退出及文件修改事件，记录队列序列缺口。
- Network Extension：独立网络过滤系统扩展、对应签名配置及用户启用。以 flow 的 sourceAppAuditToken / sourceProcessAuditToken 联接进程身份；不能把 ES 当作 TCP/UDP 网络事件来源。
- 进程范围：启动时的 Agent 树基线 + fork/exec/exit 更新，PID 复用不能继承旧归属；关联失败的事件不能静默丢弃或冒充无流量。
- 现有 Agent Hook、请求正文适配器和持久化保留；系统事件不自动提供 HTTPS/SSH 明文或任务 ID。
- 当前未开启系统事件版，不停用原有降级采样。只有完成签名部署和真实流量对照后，才能切换主来源。

官方依据：
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension

本目录只是可运行的环境探测，不是已完成的事件采集器。
