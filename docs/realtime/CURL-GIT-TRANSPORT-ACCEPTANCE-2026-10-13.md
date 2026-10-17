# curl / Git 子连接采集验收

结论：未完成产品验收。新增的是显式启动的原生传输采集入口，不是自动覆盖所有 WorkBuddy/Codex 命令。当前运行应用未被本次脚本改动替换。

## 已执行

| 测试 | 实际结果 | 范围 |
|---|---|---|
| curl HTTPS 直连百度 | 退出 0，原生 transfer/connection ID、实际 IPv6 连接、HTTP 收发块；正文 227 字节 | 显式启动入口 |
| 正文核对 | SHA256 3d7414a921a24780e3fc3774dcbbf6dace8eec37162daed0fa0a0f3fb0b9a3a7，与下载文件一致 | 此次响应 |
| Git HTTPS ls-remote | 退出 0；Trace2 捕获两层子进程，libcurl 记录 CONNECT github.com:443 | 显式启动入口 |
| 代理实测 | 命令配置 1087，实际记录连接 127.0.0.1:1081 | 不把配置当成实际连接；覆盖原因未判定 |
| curl 重定向 | 独立服务端记录 302→200，正文 1 MiB，采集字节数一致 | 本机测试服务器，不代表外网覆盖 |
| curl 中断 | 实收 65536 字节，命令非零退出 | 正文块完整不等于整个响应完整 |
| curl 续传 | 服务端收到 Range bytes=65536-，返回 206，剩余字节数一致 | 同上 |
| 最终文件 | 1 MiB，SHA256 fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83 | 独立测试内容 |
| 解析回归 | 5 项通过：TLS 不算 HTTP 正文、缺字节、并发 curl ID、Git 不伪造 ID/完整正文、子进程 ID 按父级隔离 | 自动测试 |

## 未通过 / 尚未完成

- WorkBuddy/Codex 普通命令自动接入，不应要求用户手动给每条命令加包装。
- launcher 输入的任务 ID 只是标签，未独立核验原生任务归属，不能展示为确认关联。
- Git libcurl 文本日志没有可靠逐行 PID/connection ID。并发 helper 连接尚不能准确归属，不可根据相邻时间硬关联。
- Git 二进制 trace 是有损文本，不能声称已取得完整 pack 原始字节。
- Git clone/fetch/submodule、SSH、并发任务隔离、代理失败和重试仍需真实验收。
- 现有应用界面尚未接入这份 transport.json；没有宣称前端完成，也未打包。
- 原始 trace 可能含凭据，只在本机受限目录存放；公开展示前的脱敏、保留与容量控制尚需实现。

## 实现与复现

入口：tools/transport-audit/run.py；解析：tools/transport-audit/parse.py。
解析逐行读取 curl trace，记录实际连接事件、原生连接与传输 ID、HTTP 块长度及哈希；SSL 密文/握手块不混入 HTTP 正文。

测试：

    python3 Tests/Manual/network/test_native_transport.py
    python3 Tests/Manual/network/test_native_curl_integration.py

第二项需允许绑定临时 loopback 端口。测试临时数据自动清理。实际外网测试证据位于 /private/tmp/agentreins-transport-audit，含敏感可能性，不公开原始内容。
