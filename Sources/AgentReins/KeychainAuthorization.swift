import AgentReinsCore
import AppKit
import Foundation

/// The sampler, the MCPs and this app read the integrity key without any UI (the helper runs with Keychain
/// interaction disabled). When macOS wants a person to approve the helper on the key's access list (exit 4),
/// nothing can be signed or verified until someone in the logged-in session says yes. The app asks for that
/// visibly — at launch and from the 首页 coverage banner — and only runs `AgentReinsKeychainHelper authorize`
/// (which lets macOS show its own prompt) after the user clicks 授权. Never silently.
@MainActor
enum KeychainAuthorization {
    private static var inFlight = false

    /// States where a person can fix it by approving. "missing" (no key yet) and "no_helper" (dev build) are not.
    nonisolated static func needsUser(_ state: String) -> Bool {
        ["needs_approval", "error", "timeout"].contains(state)
    }

    /// Launch check: non-interactive `status` off the main thread; ask only if approval is needed.
    static func checkAtLaunch() {
        DispatchQueue.global(qos: .utility).async {
            let state = SocketLedgerArchive.helper.status()
            guard needsUser(state) else { return }
            Task { @MainActor in Self.request(currentState: state, completion: nil) }
        }
    }

    /// Explain, ask, then (only on 授权) run the interactive authorize step and report the result.
    static func request(currentState: String?, completion: ((String) -> Void)?) {
        guard !inFlight else { completion?("busy"); return }
        inFlight = true
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "需要你允许 AgentReins 读取钥匙串里的完整性密钥"
        alert.informativeText = """
        当前状态：\(label(currentState))。
        没有这把密钥，连接台账和 MCP 审计日志都无法签名或校验，首页会显示“未签名 / 无法校验”。
        点“授权…”后，macOS 会弹出钥匙串确认框，请在框里选择“始终允许”（可能需要输入登录密码）。
        AgentReins 不会读取或显示密钥内容。也可以稍后在终端运行：
        /Applications/AgentReins.app/Contents/MacOS/AgentReinsKeychainHelper authorize
        """
        alert.addButton(withTitle: "授权…")
        alert.addButton(withTitle: "以后再说")
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else {
            inFlight = false
            completion?("declined")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let helper = SocketLedgerArchive.helper
            let result = helper.authorize()
            let after = result == "ok" ? helper.status() : result
            Task { @MainActor in
                inFlight = false
                let done = NSAlert()
                done.alertStyle = after == "ok" ? .informational : .warning
                done.messageText = after == "ok" ? "钥匙串授权完成" : "钥匙串授权没有完成"
                done.informativeText = after == "ok"
                    ? "完整性密钥现在可以读取；下一轮采样起台账会重新签名，首页覆盖率横幅会随之更新。"
                    : "结果：\(label(after))。\(helper.lastError ?? "")"
                _ = done.runModal()
                completion?(after)
            }
        }
    }

    nonisolated static func label(_ state: String?) -> String {
        switch state {
        case "ok": return "可以读取"
        case "missing": return "密钥尚未创建（采样器首次运行时创建）"
        case "needs_approval": return "需要用户批准（钥匙串已锁定，或此助手尚未在密钥的访问列表里）"
        case "timeout": return "钥匙串没有响应 / 确认框无人应答"
        case "no_helper": return "找不到 AgentReinsKeychainHelper"
        case "declined": return "已取消"
        case nil: return "未知"
        default: return "钥匙串读取失败"
        }
    }
}
