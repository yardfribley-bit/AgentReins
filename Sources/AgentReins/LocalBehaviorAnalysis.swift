import Foundation
import CryptoKit

/// Runs over saved task evidence independently of model availability. These
/// are behavioral observations; success and authorization require separate evidence.
enum LocalBehaviorAnalysis {
    static let version = 2

    static func report(events: [GuardEvent], reportedDomains: Set<String> = []) -> HistoricalSecurityAnalysis {
        let ordered = events.sorted { $0.ts < $1.ts }
        let calls = ordered.filter { $0.kind == "tool" && $0.op == "call" }
        var findings: [AIHistoricalFinding] = []
        func add(_ rule: String, _ title: String, _ summary: String, _ advice: String,
                 _ evidence: [GuardEvent], severity: String = "medium") {
            guard let first = evidence.first else { return }
            let ids = Array(Set(evidence.map { $0.id.uuidString })).sorted()
            let material = "\(rule)|\(first.sessionId ?? "")|\(first.turnId ?? "")|\(first.toolCallId ?? first.id.uuidString)"
            var item = AIHistoricalFinding(id: SHA256.hash(data: Data(material.utf8)).map { String(format: "%02x", $0) }.joined(),
                title: title, severity: severity, summary: summary, recommendedAction: advice,
                evidenceEventIds: ids, ruleId: "behavior:\(rule)",
                llmSelfExamine: LLMSelfExamination(verdict: "needs_review", confidence: 1,
                    evidenceSufficient: true, falsePositiveRisk: "行为可能属于用户授权的正常任务；请核对原文与执行结果。",
                    counterEvidence: "调用、返回和后续行为分别保留；不把时间先后当作因果或执行成功。",
                    rationale: "本地行为检测器基于保存的调用与内容，未调用模型作判断。"))
            item.agentName = first.agent
            item.taskTitle = ordered.compactMap(\.userIntent).first(where: { !$0.hasPrefix("<") && !$0.isEmpty }).map { String($0.prefix(160)) }
            item.observedAt = ISO8601DateFormatter().string(from: first.ts)
            findings.append(item)
        }
        func results(_ call: GuardEvent) -> [GuardEvent] {
            guard let id = call.toolCallId else { return [] }
            return ordered.filter { $0.op == "result" && $0.toolCallId == id && $0.sessionId == call.sessionId && $0.turnId == call.turnId }
        }
        let proxyNames = ["vmess", "vless", "v2ray", "xray", "sing-box", "clash", "shadowsocks"]
        let proxyCalls = calls.filter { call in
            let value = (call.command ?? "").lowercased()
            let tool = (call.toolName ?? "").lowercased()
            return proxyNames.contains(where: value.contains)
                && ["bash", "shell", "exec", "write", "edit", "powershell", "terminal"].contains(where: tool.contains)
                && ["install", "deploy", "下载", "部署", "systemctl", "sc.exe", "new-service", "schtasks", "guiConfigs".lowercased(), "guindb", "config.json", "set-itemproperty", "start-process"].contains(where: value.contains)
        }
        if let first = proxyCalls.first {
            let outputs = proxyCalls.flatMap(results)
            let names = proxyNames.filter { name in proxyCalls.contains { ($0.command ?? "").lowercased().contains(name) } }
            add("proxy_configuration", "Agent 调用了代理安装或配置操作 · \(names.joined(separator: " / "))",
                "本次关联证据包含 \(proxyCalls.count) 次相关工具调用、\(outputs.count) 条匹配返回，不代表整项任务的调用总数。涉及代理安装、节点配置或服务设置，可能改变网络出口。是否安装成功及是否回退需核对返回和后续记录。",
                "核对目标设备、节点接收方及用户授权；检查系统代理、TUN、后台服务和回退结果。若不符合预期，在对应 Agent 停止任务并检查残留配置。",
                [first] + Array(proxyCalls.dropFirst()) + outputs)
        }
        for call in calls {
            let command = (call.command ?? "").lowercased()
            let outputs = results(call)
            if command.contains("--no-audit") && (command.contains("npm install") || command.contains("npm ci")) {
                add("dependency_audit_disabled", "依赖安装命令关闭了 npm 安全审计",
                    "工具参数包含 --no-audit。镜像与下载目标需在原始命令及网络证据中核对；此参数不证明下载内容恶意，也不证明安装成功。",
                    "检查安装来源和锁文件，并按项目需要补做依赖漏洞检查。", [call] + outputs)
            }
            let domain = ExternalURLEvidence.firstDomain(in: call.command)
            let matchedDomain = domain.flatMap { host in reportedDomains.first { host == $0 || host.hasSuffix("." + $0) } }
            let suspicious = outputs.compactMap { event -> (GuardEvent, [InjectionFinding])? in
                guard let body = event.modelResponse, !body.isEmpty else { return nil }
                let scan = WebContentThreatAnalysis.scan(body)
                return scan.isEmpty ? nil : (event, scan)
            }
            let webTool = ["web", "fetch", "browser", "search"].contains { (call.toolName ?? "").lowercased().contains($0) }
            guard matchedDomain != nil || ((domain != nil || webTool) && !suspicious.isEmpty) else { continue }
            let source = domain ?? "外部网页"
            let patterns = suspicious.flatMap { $0.1.map(\.evidence) }
            let resultTime = outputs.map(\.ts).max() ?? call.ts
            // Require a substantial exact content passage in the captured request.
            let requests = ordered.filter { event in
                guard event.kind == "model", event.ts > resultTime,
                      event.sessionId == call.sessionId, event.turnId == call.turnId,
                      let prompt = event.modelPrompt else { return false }
                return patterns.contains { $0.count >= 32 && prompt.contains($0) }
            }
            let followups = calls.filter { $0.ts > resultTime && $0.sessionId == call.sessionId && $0.turnId == call.turnId }
            let stage = outputs.isEmpty ? "已记录访问调用，但未找到匹配的工具返回正文。" : "已找到 \(outputs.count) 条同调用 ID 的返回记录。"
            let signal = suspicious.isEmpty ? "目的域名命中用户配置的关注列表；域名标记本身不证明攻击成功。" : "返回内容自动检出可疑指令或凭据索取，已保留原文供核查；不代表已经泄露或攻击成功。"
            let propagation = requests.isEmpty ? "尚未通过内容匹配确认网页指令进入后续请求。" : "在 \(requests.count) 条后续模型请求中找到相同可疑内容片段。"
            add("external_content", "访问需核查的网页 · \(source)",
                "\(stage)\(signal)\(propagation)本次关联范围内有 \(followups.count) 次后续工具调用，不代表整个任务的全部行为；不能仅凭顺序认定网页导致了这些操作。",
                "核对网页原文中的登录、上传、下载执行或指令替换要求，再检查后续工具参数、敏感读取和外联；如已提交凭据，应更换对应凭据。",
                [call] + outputs + requests + Array(followups.prefix(20)), severity: suspicious.isEmpty ? "medium" : "high")
        }
        return HistoricalSecurityAnalysis(findings: findings, rules: [],
            generatedAt: ISO8601DateFormatter().string(from: Date()), model: "本地行为检测 v\(version)", examinationPasses: 0)
    }
}
