import AppKit
import SwiftUI

/// Collectors remain independent of playback. Only UI snapshots are replayed.
struct CollectionLiveView: View {
    @EnvironmentObject private var processGuard: ProcessGuard
    @EnvironmentObject private var eventStore: EventStore
    @State private var registry = CollectionProcessRegistry()
    @State private var latest: [CollectionRecordPresentation] = []
    @State private var replay = CollectionReplayBuffer()
    @State private var selectedProcess: String?
    @State private var modeLive = true
    @State private var playing = false
    @State private var position = 0.0
    @State private var speed = 1
    @State private var dirty = true
    @State private var pulses: [String: Date] = [:]
    @State private var known = Set<UUID>()
    @State private var presentationCache: [UUID: CollectionRecordPresentation] = [:]
    private let clock = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    private let accent = TaskStoryStyle.accent
    private var frame: CollectionReplayFrame? { modeLive ? nil : replay.frame(at: Int(position)) }
    private var displayedRegistry: CollectionProcessRegistry { frame?.registry ?? registry }
    private var records: [CollectionRecordPresentation] { frame?.records ?? latest }
    private var visible: [CollectionRecordPresentation] {
        guard let key = selectedProcess, let node = displayedRegistry.nodes[key] else { return records }
        return records.filter { row in
            if let identity = row.processIdentity { return identity == key }
            guard row.pid.map(String.init) == node.process.pid, let birth = node.process.birthIdentity else { return false }
            return row.observedAt.timeIntervalSince1970 >= Double(birth) / 1_000_000 && row.observedAt <= node.lastSeen.addingTimeInterval(node.active ? 60 : 0)
        }
    }
    // Keep one representative record per kind on the overview; detail never replaces the main canvas.
    private var summaries: [CollectionRecordPresentation] {
        var seen = Set<String>()
        return visible.filter { seen.insert($0.category).inserted }.prefix(8).map { $0 }
    }
    var body: some View {
        VStack(spacing: 0) {
            heading
            HStack(alignment: .top, spacing: 0) {
                processPane.frame(minWidth: 240, idealWidth: 280, maxWidth: 320)
                Divider()
                collectorPane.frame(minWidth: 230, idealWidth: 250, maxWidth: 280)
                Divider()
                evidencePane.frame(minWidth: 360, maxWidth: .infinity)
            }.frame(maxHeight: .infinity)
            Divider()
            transport
        }
        .background(TaskStoryStyle.background)
        .onAppear { receiveProcesses(processGuard.processInventory); receiveEvidence(); captureFrame() }
        .onReceive(processGuard.$processInventory) { receiveProcesses($0) }
        .onReceive(eventStore.$revision) { _ in receiveEvidence() }
        .onReceive(clock) { date in
            pulses = pulses.filter { date.timeIntervalSince($0.value) < 1.2 }
            if dirty { captureFrame() }
            if playing && !modeLive {
                let next = Int(position) + speed
                position = Double(min(next, max(0, replay.frames.count - 1)))
                if Int(position) == replay.frames.count - 1 { playing = false }
                if let newest = frame?.records.first { pulses[newest.origin] = date }
            }
        }
    }
    private var heading: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("采集来源与内容，一眼看清").font(.system(size: 22, weight: .semibold))
                Text("本机 / WorkBuddy · 动态观察对象与数据管道").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                Text(modeLive ? "实时观察" : playing ? "采集回放 · 播放中" : "采集回放 · 已暂停")
                    .foregroundStyle(modeLive ? Color.green : accent)
                Text("\(displayedRegistry.nodes.values.filter(\.active).count) 个观察对象 · \(records.count) 条近期记录")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
        }.padding(20)
    }
    private var processPane: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack { section("OBSERVE", "动态进程树"); Spacer(); Button("全部") { selectedProcess = nil } }
            Text("实线：父子关系 · 点击查看职责依据").font(.caption).foregroundStyle(.secondary)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach(displayedRegistry.ordered, id: \.node.id) { item in
                        nodeCard(item.node, depth: item.depth)
                    }
                    if displayedRegistry.nodes.isEmpty { Text("等待发现 WorkBuddy 关联进程").foregroundStyle(.secondary) }
                }
            }
            Text("隔离状态尚未验证").font(.caption).foregroundStyle(.orange)
            Text("移出进程树的节点保留；不据此确认退出原因。").font(.caption).foregroundStyle(.secondary)
        }.padding(16)
    }
    private func nodeCard(_ node: CollectionProcessNode, depth: Int) -> some View {
        Button { selectedProcess = selectedProcess == node.id ? nil : node.id } label: {
            VStack(alignment: .leading, spacing: 5) {
                HStack(alignment: .top) {
                    Circle().fill(node.active ? Color.green : .secondary).frame(width: 5, height: 5).padding(.top, 6)
                    Text(node.role.title).font(.system(size: 12, weight: .semibold))
                    Spacer(minLength: 4)
                    Text(node.active ? "观察中" : "离开当前树").font(.system(size: 10)).foregroundStyle(.secondary)
                }
                Text("\(node.name) · PID \(node.process.pid)").font(.caption.monospaced()).lineLimit(2)
                Text("父进程 \(node.process.ppid)").font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(10)
                .background(selectedProcess == node.id ? accent.opacity(0.12) : TaskStoryStyle.soft, in: RoundedRectangle(cornerRadius: 6))
                .overlay(alignment: .leading) { Rectangle().fill(TaskStoryStyle.border).frame(width: 1) }
                .padding(.leading, CGFloat(min(depth, 4)) * 12)
        }.buttonStyle(.plain)
    }
    private var collectorPane: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                section("COLLECT", "采集触手与协调器")
                ForEach(["进程观察", "原生 Hook", "HTTPS 正文", "本地日志 / 其他"], id: \.self) { origin in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack { Text(origin).font(.subheadline); Spacer(); Text("\(records.filter { $0.origin == origin }.count) 条").font(.caption.monospacedDigit()) }
                        Text(sourceDescription(origin)).font(.caption).foregroundStyle(.secondary)
                        TimelineView(.animation(minimumInterval: 1 / 20, paused: pulses[origin] == nil)) { tick in
                            GeometryReader { geo in
                                Rectangle().fill(TaskStoryStyle.border).frame(height: 1).position(x: geo.size.width / 2, y: 4)
                                if let date = pulses[origin] {
                                    let t = min(1, max(0, tick.date.timeIntervalSince(date) / 1.2))
                                    Circle().fill(accent).frame(width: 5, height: 5).position(x: geo.size.width * t, y: 4)
                                }
                            }.frame(height: 8)
                        }
                    }
                }
                Text("↓ 原始记录进入统一证据管道").font(.caption).foregroundStyle(accent)
                VStack(alignment: .leading, spacing: 14) {
                    Text("采集协调器").font(.headline)
                    processing("1", "接收原文", "本页已收到 \(records.count) 条证据投影")
                    processing("2", "识别数据", "保留采集来源和数据类型，摘要不替代原文")
                    processing("3", "关联证据", "\(records.filter { $0.pid == nil }.count) 条无 PID；保留归属待确认")
                    processing("4", "保存记录", modeLive && eventStore.persistenceError != nil ? "保存异常：\(eventStore.persistenceError ?? "")" : "单条保存状态尚未接入；已收到不等于已保存")
                    Divider()
                    Text("待处理队列：状态未接入").font(.caption).foregroundStyle(.secondary)
                }.padding(14).background(TaskStoryStyle.soft, in: RoundedRectangle(cornerRadius: 10))
                Text("短进程覆盖存在缺口").font(.caption).foregroundStyle(.orange)
                Text("工具日志存在，不代表独立进程一定被采到。文件句柄和资源指标不代表读取了正文。").font(.caption).foregroundStyle(.secondary)
            }.padding(16)
        }
    }
    private var evidencePane: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 12) {
                section("EVIDENCE", "采集内容摘要")
                Text(selectedProcess == nil ? "全部来源 · 无 PID 的正文不强行归属" : "仅展示有该进程依据的记录")
                    .font(.caption).foregroundStyle(.secondary)
                if let key = selectedProcess, let node = displayedRegistry.nodes[key] {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("职责与采集依据").font(.subheadline.bold())
                        Text(node.role.basis).font(.caption)
                        Text("隔离：尚未验证 · 具体采集行为以下方记录为准").font(.caption).foregroundStyle(.secondary)
                    }.padding(10).background(TaskStoryStyle.soft, in: RoundedRectangle(cornerRadius: 6))
                }
                Text("先看摘要 · 详情按需展开 · \(summaries.count) 类近期内容")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(summaries) { record in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(alignment: .top) {
                            Text(record.title).font(.system(size: 13, weight: .semibold))
                            Spacer()
                            Text(record.state).font(.caption).foregroundStyle(record.state == "采集缺口" ? Color.orange : accent)
                        }
                        Text(record.summary).font(.system(size: 13)).textSelection(.enabled)
                        DisclosureGroup("查看详情与原文预览") {
                            VStack(alignment: .leading, spacing: 7) {
                                ForEach(Array(record.details.enumerated()), id: \.offset) { _, text in Text(text).font(.caption).textSelection(.enabled) }
                                Text("有界预览；完整原文保留在本地证据库。").font(.caption).foregroundStyle(.secondary)
                                Text(record.preview).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                                Button("复制本条预览") {
                                    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(record.preview, forType: .string)
                                }
                            }.padding(.top, 8)
                        }.font(.caption)
                        Text("\(record.origin) · \(record.observedAt.formatted(date: .omitted, time: .standard))")
                            .font(.caption).foregroundStyle(.secondary)
                        Divider()
                    }
                }
                if summaries.isEmpty { Text("等待该范围的真实采集记录").foregroundStyle(.secondary) }
            }.padding(16)
        }
    }
    private var transport: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button("回到实时") { modeLive = true; playing = false; selectedProcess = nil }
                    .disabled(modeLive)
                Button(playing ? "暂停" : "播放采集回放") {
                    if playing { playing = false }
                    else { modeLive = false; selectedProcess = nil; if Int(position) >= replay.frames.count - 1 { position = 0 }; playing = true }
                }.disabled(replay.frames.count < 2)
                Button("下一条快照") { modeLive = false; playing = false; position = Double(min(Int(position) + 1, replay.frames.count - 1)) }
                    .disabled(replay.frames.isEmpty || (!modeLive && Int(position) >= replay.frames.count - 1))
                Picker("速度", selection: $speed) { Text("1×").tag(1); Text("2×").tag(2); Text("4×").tag(4) }.frame(width: 100)
                Spacer()
                Text((frame?.time ?? replay.frames.last?.time ?? Date()).formatted(date: .omitted, time: .standard)).font(.caption.monospacedDigit())
            }
            Slider(value: $position, in: 0...Double(max(1, replay.frames.count - 1)), step: 1, onEditingChanged: { _ in modeLive = false; playing = false })
                .disabled(replay.frames.count < 2)
            Text("回放本页最近 60 个采集快照（1× 每秒一条）；不重新执行任务。切换页面或重启后重置，采集继续独立运行。")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(16)
    }
    private func section(_ eyebrow: String, _ title: String) -> some View {
        VStack(alignment: .leading, spacing: 3) { Text(eyebrow).font(.system(size: 10, weight: .medium)).foregroundStyle(accent); Text(title).font(.headline) }
    }
    private func processing(_ number: String, _ title: String, _ note: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(number).font(.caption.monospaced()).foregroundStyle(accent)
            VStack(alignment: .leading, spacing: 3) { Text(title).font(.subheadline); Text(note).font(.caption).foregroundStyle(.secondary) }
        }
    }
    private func sourceDescription(_ source: String) -> String {
        switch source {
        case "进程观察": return "父子关系、资源、文件句柄和连接快照"
        case "原生 Hook": return "工具参数、结果、来源进程证据"
        case "HTTPS 正文": return "模型上下文、响应、返回的 reasoning"
        default: return "应用记录及其他采集来源"
        }
    }
    private func receiveProcesses(_ inventory: [ProcessSnapshotRecord]) {
        registry.update(inventory, now: Date()); dirty = true
    }
    private func receiveEvidence() {
        var seen = Set<UUID>()
        let events = eventStore.events.filter { $0.agent?.lowercased() == "workbuddy" && $0.ts >= eventStore.liveSince }
            .sorted { $0.ts > $1.ts }.filter { seen.insert($0.id).inserted }.prefix(500)
        let now = Date()
        let projected = events.map { event -> CollectionRecordPresentation in
            if let cached = presentationCache[event.id], cached.pid == event.processId { return cached }
            let request = event.toolCallId.flatMap { call in
                events.first { $0.toolCallId == call && $0.sessionId == event.sessionId && $0.op == "hook_tool_start" }
            }
            return CollectionRecordPresentation(event, receivedAt: now, toolRequest: request)
        }
        presentationCache = Dictionary(uniqueKeysWithValues: projected.map { ($0.id, $0) })
        // Frequent resource samples must not immediately hide a captured model request.
        var categories = Set<String>()
        let representatives = projected.filter { categories.insert($0.category).inserted }
        var selectedIDs = Set<UUID>()
        latest = (representatives + Array(projected.prefix(32)))
            .filter { selectedIDs.insert($0.id).inserted }.sorted { $0.observedAt > $1.observedAt }

        if modeLive { for row in latest where !known.contains(row.id) { pulses[row.origin] = now } }
        known = Set(latest.map(\.id)); dirty = true
    }
    private func captureFrame() {
        // Freeze playback while collectors continue; avoid shifting the scrubber under the user.
        guard modeLive else { return }
        replay.append(.init(time: Date(), registry: registry, records: latest))
        position = Double(max(0, replay.frames.count - 1)); dirty = false
    }
}
