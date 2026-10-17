<div align="center">
  <p><a href="README.md">English</a> · <strong>简体中文</strong></p>
  <img src="Assets/agentreins-logo.png" width="144" alt="AgentReins 标志">

  <h1>AgentReins</h1>

  <p><strong>看见这台电脑上的编程 Agent 送出了什么，又收回了什么。</strong></p>

  <p>面向 WorkBuddy、Codex、Cursor 的本地优先 macOS 应用。</p>

  <p>
    <img alt="macOS 13+" src="https://img.shields.io/badge/macOS-13%2B-111111?logo=apple">
    <img alt="Swift 6" src="https://img.shields.io/badge/Swift-6-F05138?logo=swift&logoColor=white">
    <img alt="Alpha" src="https://img.shields.io/badge/status-alpha-F59E0B">
    <img alt="本地优先" src="https://img.shields.io/badge/privacy-local--first-2563EB">
  </p>
</div>

证据留在这台 Mac 上。AgentReins 展示 Agent 正在做的任务、每一次外网访问，以及下载真正落到磁盘上的文件。它不改系统代理，也不改系统信任库。

官网：[chuhaijian.com](https://www.chuhaijian.com/)

## 能看到什么

实时窗口里先看这两处。

**任务过程。** 原来的话、任务现在到了哪、模型问了什么、实际跑了什么。失败后的重试保留下来，不会被后来的成功盖掉。

**外网访问。** 列表只用来扫：

| 列 | 内容 |
| --- | --- |
| 时间 | 这次访问发生的时刻 |
| 谁 | 工具或模型调用 |
| 去了哪里 | 主机；远程工具写「远程访问工具」，模型写「模型服务」 |
| 协议 | HTTP 版本、模型、工具调用、加密通道或安装包 |
| 结果 | 发生了什么：通了、对方返回 502、证书没配好、下载了某文件、带走了某文件 |

点「打开」。**送出**和**收回**出现在这一行下面。没有请求正文时写「没有送出正文」，没有响应正文时写「正文是空的」。网页显示为「网页《标题》」加一句摘录。证书英文、`CONNECT` 和凭据不进这两栏。协议行收在「协议原文」里，默认折起。

wget、curl、brew 的下载显示落到磁盘的文件：名字、大小、SHA-256。校验的是磁盘上的文件。页面不把文件字节铺开。

WebFetch 这类远程工具显示的是这台机器和工具之间的往来：提交了什么，工具返回了什么。工具自己再去打开的网站，不是这台机器发出的连接。

## 现在不承诺的事

- 不走这个代理的流量、校验证书钉死的程序、QUIC，不会进入记录。
- SSH、SCP、SFTP、rsync 的通道字节没有解密。结果写「看不到通道里的内容」。
- 不还原 Git pack 字节。push 可以显示将要离开的文件名。
- 不用时间去猜这次访问属于哪一次工具调用。对不上时写「还没对上哪次工具调用」。
- 查询字符串在写入前去掉。
- 大于 32 MB 的文件保留大小，不计算校验。
- 已经打开的 WorkBuddy 和 Codex 要完全退出再打开，才会用上新的命令入口。
- 这一页不判断编程任务是否完成，也不做记忆体投毒检测。

没有采到的内容就保持没有。应用不编造正文、主机或工具调用。

## 隐私

记录留在当前用户目录。审计代理只听 `127.0.0.1:18891`，由 AgentReins 启动，应用退出时一起退出。普通终端不会被指到这个代理。加载了 `~/.agentreins/audit.sh` 的 Agent 进程才使用它，以及本机的 mitmproxy 证书。系统代理和系统信任库保持原样。

## 构建

需要 macOS 13 或更高版本、Xcode Command Line Tools、Swift 6。要看 HTTPS 正文，再安装 `mitmdump`。

```bash
git clone https://github.com/yardfribley-bit/AgentReins.git
cd AgentReins
./scripts/package_realtime.sh
open ".build/realtime-preview/AgentReins Realtime.app"
```

让 WorkBuddy、Codex、Cursor 里的 wget、curl、git、brew 等命令走进采集：

```bash
python3 scripts/install_codex_transport.py
```

然后把这些应用完全退出，再重新打开。已经在跑的 shell 仍用旧的命令函数。

## 目录

```text
Sources/AgentReins/                         macOS 应用
Sources/AgentReins/Resources/RealtimeWorkspace/   任务过程与外网访问页面
Sources/AgentReins/Resources/workbuddy_network_capture.py
tools/transport-audit/                      curl、wget、git、brew、ssh 等命令采集
scripts/package_realtime.sh                 打包实时应用
scripts/install_codex_transport.py          安装只对 Agent 生效的审计环境
docs/                                       架构与路线
```

深入阅读：[系统架构](docs/ARCHITECTURE.md)、[数据采集](docs/DATA-COLLECTION-ARCHITECTURE.md)、[Trace、Verify、Recover](docs/TRACE-VERIFY-RECOVER-ROADMAP.md)。

## 许可

仓库里还没有开源许可证。源码公开，供阅读。这不表示可以把代码复制进其他产品。

## 问题

如果这台机器上的一次访问无法从页面上看出是谁发出、去了哪里、送出了什么、收回了什么，请开一个 issue。不要贴 API key、令牌或私人提示词。
