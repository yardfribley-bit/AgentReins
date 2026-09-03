// AgentGuard — Endpoint Security Framework (ESF) 拦截参考实现
//
// 这是 agentguard-block（PATH-shim）的生产级升级：ESF 系统扩展能在
// 内核层拦截「所有」进程的文件/进程/网络事件，不依赖 PATH、对所有 agent
//（包括 GUI 版 Cursor / Codex）通用。
//
// ⚠️ 重要前提（本沙箱无法满足，需在真实 Mac 上构建）：
//   1. 需要 Apple 发放的专属 entitlement：`com.apple.developer.endpoint-security.client`
//      —— 须向 Apple 申请（https://developer.apple.com/contact/request/endpoint-security/）。
//   2. 必须用付费开发者账号签名 + notarize，并在「系统设置 → 隐私与安全性」里批准。
//   3. 系统扩展以 root 运行，受 SIP 保护（ESF 本身在 SIP 开启时即可用）。
//   4. 无法在 CI / 沙箱里跑；下面代码是可直接放进 Xcode 工程参考的实现。
//
// 设计要点（与 AgentSpec 的 enforce 对齐）：
//   - block 规则 -> es_respond_auth_result(... ES_AUTH_RESULT_DENY)  直接拒绝
//   - ask   规则 -> 先 DENY 并记录，弹用户确认（ES 不能同步阻塞等 UI，
//                 通常做法：缓存事件+异步提示，用户允许后再放行下一次）
//   - allow 规则 -> ES_AUTH_RESULT_ALLOW

import Foundation
import EndpointSecurity

// MARK: - 规则判定（与 agentguard/rules.json 的命令层语义对应，这里用简化 blocklist 演示）
struct GuardPolicy {
    // 命中即拒绝执行的进程路径/参数特征（对应 destructive_rm / curl_pipe_bash）
    static let blockExecSubstrings: [String] = [
        "rm -rf",
        "rm -fr",
    ]
    // 命中即需询问的文件路径前缀（对应 read_secret / protect_ssh）
    static let sensitivePathPrefixes: [String] = [
        NSHomeDirectory() + "/.ssh/",
        NSHomeDirectory() + "/.aws/",
    ]

    static func shouldBlockExec(_ msg: es_message_t) -> Bool {
        guard let proc = msg.event.exec.target.process else { return false }
        let path = String(cString: proc.executable_path)
        // 真实实现应对 msg.event.exec.args 逐个取 ascii 拼成命令行再匹配；
        // 这里仅以可执行路径示意。
        return blockExecSubstrings.contains(where: path.contains)
    }

    static func isSensitivePath(_ path: String) -> Bool {
        sensitivePathPrefixes.contains(where: path.hasPrefix)
    }
}

// MARK: - ES 客户端
func createESClient() -> es_client_t? {
    var client: es_client_t?
    let result = es_new_client(&client) { client, message in
        let msg = message.pointee
        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            // 进程即将执行：破坏性命令直接拒绝
            if GuardPolicy.shouldBlockExec(msg) {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY)
                logDecision("block", rule: "destructive_rm", detail: "exec \(msg.event.exec.target.process)")
                return
            }
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW)

        case ES_EVENT_TYPE_AUTH_UNLINK:
            // rm 删除文件：敏感目录直接拒绝
            let path = String(cString: msg.event.unlink.target.path.data)
            if GuardPolicy.isSensitivePath(path) {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY)
                logDecision("block", rule: "protect_ssh", detail: "unlink \(path)")
                return
            }
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW)

        case ES_EVENT_TYPE_AUTH_OPEN:
            // 打开文件读取：敏感目录走「询问」流程（示意：先拒绝并记录，等用户确认）
            let path = String(cString: msg.event.open.file.path.data)
            if GuardPolicy.isSensitivePath(path) {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY)
                logDecision("ask-deny", rule: "read_secret", detail: "open \(path)")
                // 生产做法：此处把事件入队，弹 UserNotification 询问，用户允许后放行下一次。
                return
            }
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW)

        default:
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW)
        }
    }
    if result != ES_NEW_CLIENT_RESULT_SUCCESS {
        NSLog("AgentGuard ESF: es_new_client 失败 (\(result))——检查 entitlement / 系统设置批准")
        return nil
    }
    return client
}

func logDecision(_ decision: String, rule: String, detail: String) {
    // 真实实现写 JSONL 审计（同 agentguard 风格）；这里打印
    NSLog("[AgentGuard][\(decision)][\(rule)] \(detail)")
}

// MARK: - 入口（系统扩展的 main）
let client = createESClient()
if client == nil {
    exit(1)
}
// 进入 runloop，等待内核事件
RunLoop.main.run()
