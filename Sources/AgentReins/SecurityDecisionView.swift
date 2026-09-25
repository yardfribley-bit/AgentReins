import SwiftUI

enum SafetyQuestion: String, CaseIterable {
    case all = "全部发现"
    case privacy = "读取了什么隐私？"
    case destination = "数据发给了谁？"
    case command = "执行了危险命令吗？"
    case changes = "改了哪些东西？"

    func matches(_ events: [GuardEvent]) -> Bool {
        events.contains { event in
            switch self {
            case .all: return true
            case .privacy: return event.kind == "file" || event.ruleId.contains("credential") || event.ruleId.contains("secret")
            case .destination: return event.remoteHost != nil || event.remoteDomain != nil || event.modelPrompt != nil
            case .command: return event.command != nil || event.kind == "cmd" || event.kind == "tool"
            case .changes: return event.kind == "memory" || event.beforeContent != nil || event.afterContent != nil || event.fileDiff != nil
            }
        }
    }
}

/// Presentation of observations, never a claim about unseen services or final recipients.
enum SecurityDestinationFacts {
    static func endpoints(_ events: [GuardEvent]) -> [GuardEvent] {
        var seen = Set<String>()
        return events.sorted { $0.ts > $1.ts }.filter {
            guard $0.remoteHost != nil || $0.remoteDomain != nil else { return false }
            let key = "\($0.remoteHost ?? "")|\($0.remoteDomain ?? "")|\($0.remotePort ?? -1)"
            return seen.insert(key).inserted
        }
    }

    static func service(_ event: GuardEvent) -> String {
        switch NetworkDestinationAssessment.assess(domain: event.remoteDomain, host: event.remoteHost).kind {
        case .modelProvider: return "已识别模型服务域名；仍需核对发送内容"
        case .modelRelay: return "模型中转入口；后续接收方尚未验证"
        case .developerService: return "开发资源服务；具体上传或下载行为需核对正文"
        case .telemetry: return "遥测服务；发送内容需另行核对"
        case .localInfrastructure: return "本机入口；不代表最终外联地址"
        case .externalContent, .unknown:
            return "服务用途未确认；不能仅凭端口判断为 SSH 或模型服务"
        }
    }
}

struct SecurityDecisionView: View {
    let summary: String
    let recommendation: String
    let events: [GuardEvent]
    @StateObject private var geolocation = IPGeolocationStore()
    @State private var showStopHelp = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("发生了什么，对我有什么影响").font(.headline)
            Text(summary).textSelection(.enabled)
            Text("这是待核查的安全发现，不代表已经确认违规。只有连接记录时，不能据此认定文件已经上传。")
                .font(.caption).foregroundStyle(.secondary)
            destinations
            VStack(alignment: .leading, spacing: 10) {
                Text("现在建议你做什么").font(.headline)
                Text(recommendation)
                Button("如何停止 Agent") { showStopHelp.toggle() }
                if showStopHelp {
                    Text("请到对应 Agent 中停止当前任务。本页未接入拦截控制；停止不能撤回已发出的数据，也不会自动撤销文件修改。")
                }
            }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                .background(TaskStoryStyle.soft, in: RoundedRectangle(cornerRadius: 10))
            DisclosureGroup("这件事能撤销吗？") {
                Text(events.contains { $0.beforeContent != nil }
                     ? "记录中包含修改前内容，可在下方核对差异。恢复前需检查文件当前版本，避免覆盖后续修改；本页不执行自动恢复。已发送数据无法撤回。"
                     : "当前证据未提供可恢复的修改前内容，不能承诺一键撤销。请检查版本管理或备份；已经发送的数据无法由本机撤回。")
                    .padding(.top, 8)
            }
        }
    }

    private var destinations: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("数据去向与接收地址").font(.headline)
            let endpoints = SecurityDestinationFacts.endpoints(events)
            if endpoints.isEmpty {
                Text("当前关联证据未记录接收地址。模型名称、正文中的网址不能代替实际接收方证据。")
                    .foregroundStyle(.secondary)
            }
            ForEach(endpoints) { event in
                VStack(alignment: .leading, spacing: 9) {
                    Text(event.remoteDomain ?? event.remoteHost ?? "未知地址").font(.headline).textSelection(.enabled)
                    Text("地址：\(event.remoteHost ?? "IP 未采集") · 端口：\(event.remotePort.map(String.init) ?? "未采集")")
                        .textSelection(.enabled)
                    Text(SecurityDestinationFacts.service(event))
                    if let host = event.remoteHost, let record = geolocation.records[host.lowercased()] {
                        Text("网络位置：\(record.locationLabel == "Location unavailable" ? "未查询到" : record.locationLabel)")
                        Text("网络归属：\(record.ownerLabel ?? "未查询到")")
                        Text("来源：ipwho.is · 查询时间：\(record.fetchedAt.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption).foregroundStyle(.secondary)
                    } else if let host = event.remoteHost, IPGeolocationStore.isPublicIPAddress(host) {
                        Text("网络位置与归属：尚无可用查询结果")
                        Button(geolocation.pending.contains(host.lowercased()) ? "查询中…" : "查询此 IP 的位置与归属") {
                            geolocation.resolve([host])
                        }.disabled(geolocation.pending.contains(host.lowercased()))
                        Text("查询仅将此 IP 发给 ipwho.is，不发送任务正文。查询失败时可重试。")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("位置未查询：未采集公网 IP，或地址属于本地 / 保留地址。")
                            .foregroundStyle(.secondary)
                    }
                    Text("服务经营者尚未验证。IP 位置不等于数据存储地，网络归属不等于经营者。")
                        .font(.caption).foregroundStyle(.secondary)
                    DisclosureGroup("这个地址上观察到了什么服务？") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("当前证据记录的端口：\(event.remotePort.map(String.init) ?? "未采集")；协议未单独采集，不按端口猜测。")
                            Text("Agent：\(event.agent ?? "归属未采集") · \(event.ts.formatted(date: .abbreviated, time: .standard))")
                            Text("来源：\(event.source ?? "未记录") · 归属方法：\(event.attributionMethod ?? "未记录")")
                            Text("范围仅限本项关联证据，不是该 IP 的完整服务清单。外部服务情报尚未接入；不会主动扫描端口。")
                        }.font(.caption).padding(.top, 8)
                    }
                }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
                    .background(TaskStoryStyle.background, in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}
