import SwiftUI

/// Turns an exact IP query into task-local, inspectable memory-write provenance.
struct MemoryWriteLineageView: View {
    let snapshot: AgentTaskSnapshot
    let address: String?

    private var writes: [MemoryCommitEvidence] {
        snapshot.analysis.memoryCommits.filter { write in
            guard let address else { return true }
            return write.contentDiff?.localizedCaseInsensitiveContains(address) == true
        }.sorted { $0.observedAt < $1.observedAt }
    }
    private var otherWrites: [MemoryCommitEvidence] {
        guard let _ = address else { return [] }
        return snapshot.analysis.memoryCommits.filter { candidate in !writes.contains(where: { $0.commitId == candidate.commitId }) }
            .sorted { $0.observedAt < $1.observedAt }
    }
    private var matchingEvents: [GuardEvent] {
        guard let address else { return [] }
        return snapshot.sourceEvents.filter { event in
            [event.path, event.relatedPath, event.command, event.beforeContent, event.afterContent, event.fileDiff,
             event.modelPrompt, event.modelResponse, event.userIntent].compactMap { $0 }.contains { $0.contains(address) }
        }.sorted { $0.ts < $1.ts }
    }
    private func associatedEvents(for write: MemoryCommitEvidence) -> [GuardEvent] {
        let ids = Set(write.evidenceEventIds.map { $0.lowercased() })
        return snapshot.sourceEvents.filter { ids.contains($0.id.uuidString.lowercased()) }
    }
    private func mutationEvent(for write: MemoryCommitEvidence) -> GuardEvent? {
        if let id = write.writeEventId,
           let event = snapshot.sourceEvents.first(where: { $0.id.uuidString.caseInsensitiveCompare(id) == .orderedSame }) {
            return event
        }
        guard let callID = write.toolCallId else { return nil }
        return snapshot.sourceEvents.first { $0.toolCallId == callID && $0.kind == "tool" }
    }
    private func contextEvents(for write: MemoryCommitEvidence) -> [GuardEvent] {
        let callID = write.toolCallId
        return snapshot.sourceEvents.filter { event in
            (event.ts <= write.observedAt && (event.op == "prompt" || event.op == "response")) ||
                (callID != nil && event.toolCallId == callID)
        }.sorted { $0.ts < $1.ts }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(address.map { "记忆写入与上下文 · IP \($0)" } ?? "长期记忆写入与上下文").font(.headline)
            Text("\(snapshot.task.agentID) · \(snapshot.conversation.userInputs.first ?? "任务描述未采集")")
            if writes.isEmpty {
                Text(matchingEvents.isEmpty
                     ? (address == nil ? "此任务没有关联到已保存的记忆写入记录。" : "此任务已载入，但没有找到该 IP 的原始证据。请继续核对其他匹配任务。")
                     : "此任务包含该 IP，但没有证据证明它被写入长期记忆；以下显示原始命中上下文，不把同任务内其他写操作误认为该 IP 的记忆写入。")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(writes, id: \.commitId) { write in
                    MemoryWriteCard(write: write,
                        mutationEvent: mutationEvent(for: write), evidenceEvents: associatedEvents(for: write),
                        contextEvents: contextEvents(for: write))
                }
            }
            if !otherWrites.isEmpty {
                DisclosureGroup("此任务的其他记忆写入（未证明包含该 IP）· \(otherWrites.count)") {
                    ForEach(otherWrites, id: \.commitId) { write in
                        VStack(alignment: .leading, spacing: 4) {
                            Text("\(write.observedAt.formatted(date: .abbreviated, time: .standard)) · \(write.changeKind.rawValue) · \(write.confidence.rawValue)")
                                .font(.subheadline.bold())
                            Text("\(write.storagePath ?? "路径未采集") · \(write.summary)")
                            Text("当前采集证据未显示此写入包含查询的 IP。")
                                .font(.caption).foregroundStyle(.secondary)
                        }.padding(.vertical, 5)
                    }
                }
            }
            let firstWriteAt = writes.map(\.observedAt).min()
            let laterRequests = snapshot.outboundRequests.filter { request in
                guard let address, let firstWriteAt, request.capturedAt > firstWriteAt else { return false }
                return request.body.contains(address)
            }
            if address == nil {
                Text("展开单次写入，可核对当时写入的证据事件与此前模型/工具上下文。")
                    .font(.caption).foregroundStyle(.secondary)
            } else if !laterRequests.isEmpty {
                Text("后续上下文：\(laterRequests.count) 条模型请求正文包含该 IP。")
                    .font(.subheadline.bold())
                ForEach(laterRequests, id: \.eventID) { request in
                    DisclosureGroup("\(request.capturedAt.formatted(date: .abbreviated, time: .standard)) · \(request.model ?? "模型未记录")") {
                        Text(request.body).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    }
                }
            } else {
                Text("此任务快照没有证明该 IP 随记忆进入后续模型请求。跨任务后续读取仍需打开其他匹配任务核对。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !matchingEvents.isEmpty {
                DisclosureGroup("该 IP 在本任务中的所有命中 · \(matchingEvents.count) 条") {
                    ForEach(matchingEvents, id: \.id) { event in
                        VStack(alignment: .leading, spacing: 4) {
                            Text("\(event.ts.formatted(date: .abbreviated, time: .standard)) · \(event.kind) / \(event.op) · \(event.source ?? "来源未采集")")
                                .font(.caption).foregroundStyle(.secondary)
                            Text(event.modelPrompt ?? event.modelResponse ?? event.command ?? event.fileDiff ?? event.afterContent ?? event.path)
                                .textSelection(.enabled)
                        }.padding(.vertical, 6)
                    }
                }
            }
        }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(TaskStoryStyle.panel, in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct MemoryWriteCard: View {
    let write: MemoryCommitEvidence
    let mutationEvent: GuardEvent?
    let evidenceEvents: [GuardEvent]
    let contextEvents: [GuardEvent]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("记忆写入 · \(write.observedAt.formatted(date: .abbreviated, time: .standard)) · \(write.confidence.rawValue)", systemImage: "externaldrive.badge.plus")
                .font(.subheadline.bold())
            Text("文件：\(write.storagePath ?? "路径未采集") · 方式：\(write.changeKind.rawValue)")
            if let mutationEvent {
                Text("写入工具：\(mutationEvent.toolName ?? mutationEvent.op) · \(mutationEvent.command ?? mutationEvent.path)")
                    .textSelection(.enabled)
            } else {
                Text("关联事件没有单独标记实际写入操作；下方上下文只作为关联证据，不据此推断工具执行")
                    .foregroundStyle(.secondary)
            }
            DisclosureGroup("写入前后内容与关联上下文 · \(write.evidenceEventIds.count) 条证据") {
                if !evidenceEvents.isEmpty {
                    ForEach(evidenceEvents, id: \.id) { event in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("证据事件 · \(event.ts.formatted(date: .abbreviated, time: .standard)) · \(event.source ?? "来源未采集")")
                                .font(.caption.bold()).foregroundStyle(.secondary)
                            if let before = event.beforeContent { Text("写入前：\n\(before)").textSelection(.enabled) }
                            if let after = event.afterContent { Text("写入后：\n\(after)").textSelection(.enabled) }
                            if let diff = event.fileDiff { Text("差异：\n\(diff)").textSelection(.enabled) }
                            Text("操作：\(event.toolName ?? event.op) · \(event.command ?? event.path)")
                                .textSelection(.enabled)
                        }.padding(.vertical, 5)
                    }
                } else if let diff = write.contentDiff {
                    Text("记忆内容：\n\(diff)").textSelection(.enabled)
                }
                ForEach(contextEvents, id: \.id) { event in
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(event.ts.formatted(date: .omitted, time: .standard)) · \(contextLabel(event))")
                            .font(.caption).foregroundStyle(.secondary)
                        Text(contextText(event)).textSelection(.enabled)
                    }.padding(.vertical, 5)
                }
            }
        }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
            .background(TaskStoryStyle.soft, in: RoundedRectangle(cornerRadius: 8))
    }

    private func contextText(_ event: GuardEvent) -> String {
        if let value = event.modelPrompt { return value }
        if let value = event.modelResponse { return value }
        if let value = event.command { return value }
        if let value = event.userIntent { return value }
        return event.path
    }

    private func contextLabel(_ event: GuardEvent) -> String {
        guard event.kind == "model" else { return "工具活动" }
        return event.op == "prompt" ? "发送给模型" : "模型响应"
    }
}
