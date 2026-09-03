import SwiftUI

struct ContentView: View {
    @EnvironmentObject var store: RuleStore
    @EnvironmentObject var fileGuard: FileGuard
    @EnvironmentObject var processGuard: ProcessGuard
    @EnvironmentObject var memoryScan: MemoryScanManager
    @EnvironmentObject var memoryRuleStore: MemoryRuleStore

    @AppStorage("agr_useLLM") private var useLLM = false
    @AppStorage("agr_baseURL") private var baseURL = "https://openrouter.ai/api/v1"
    @AppStorage("agr_model") private var model = "tencent/hy4-preview"
    @AppStorage("agr_apiKey") private var apiKey = ""

    @State private var nlText = ""
    @State private var showConfig = false
    @State private var busy = false
    @State private var status = ""
    @State private var rightTab = "rules"          // 默认直接展示「拦截规则」，让用户一眼看到在拦什么
    @State private var banner: GuardEvent? = nil    // 拦截/还原时的强提示横幅

    // 添加自定义记忆体规则
    @State private var showAddMemoryRule = false
    @State private var newMemName = ""
    @State private var newMemPattern = ""
    @State private var newMemDesc = ""
    @State private var newMemSeverity = "high"

    // 记忆体 Inspector 选中状态
    @State private var selectedPath: String? = nil
    @State private var selectedFile: MemoryFile? = nil
    @State private var selectedContent: String? = nil
    @State private var selectedHit: MemoryFinding? = nil
    @State private var showingEditor = false

    private let df: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f
    }()

    private var appVersion: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "v\(v) (build \(b))"
    }
    private var buildDateText: String {
        Bundle.main.infoDictionary?["AGRBuiltDate"] as? String ?? ""
    }

    /// 文件层 + 命令层事件合并为统一时间线（按时间倒序）。
    private var timeline: [GuardEvent] {
        (fileGuard.events + processGuard.events).sorted { $0.ts > $1.ts }
    }

    // 状态栏计数
    private var protectedFiles: Int { store.rules.filter { $0.kind == "file" }.count }
    private var cmdRuleCount: Int { store.rules.filter { $0.kind == "cmd" }.count + ProcessGuard.builtin.count }
    private var eventCount: Int { fileGuard.events.count + processGuard.events.count }

    var body: some View {
        HSplitView {
            // 左：规则设置 + 列表
            VStack(alignment: .leading, spacing: 12) {
                Text("AgentReins · 编码智能体护栏").font(.headline)
                Text("用自然语言描述一条规则，例如：\n「agent 不允许 删除 修改 我项目中的 .env 文件」")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

                TextField("用自然语言描述规则…", text: $nlText, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .frame(minHeight: 48)

                Toggle("使用 LLM 解析（更准，需自己的模型 key）", isOn: $useLLM)
                DisclosureGroup("模型配置（可填任意 OpenAI 兼容服务）", isExpanded: $showConfig) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Base URL").font(.caption2).foregroundStyle(.secondary)
                        TextField("https://openrouter.ai/api/v1", text: $baseURL)
                            .textFieldStyle(.roundedBorder)
                        Text("模型名").font(.caption2).foregroundStyle(.secondary)
                        TextField("tencent/hy4-preview", text: $model)
                            .textFieldStyle(.roundedBorder)
                        Text("API Key").font(.caption2).foregroundStyle(.secondary)
                        SecureField("留空则用本地解析", text: $apiKey)
                            .textFieldStyle(.roundedBorder)
                        Text("支持 OpenRouter / OpenAI / DeepSeek / 本地 Ollama(/v1) 等任意 OpenAI 兼容接口。")
                            .font(.caption2).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                if useLLM && apiKey.isEmpty {
                    Text("已开启 LLM 但没填 Key，将自动用本地解析。").font(.caption2).foregroundStyle(.orange)
                }

                HStack {
                    Button(busy ? "解析中…" : "添加规则") { addRule() }
                        .disabled(busy || nlText.trimmingCharacters(in: .whitespaces).isEmpty)
                    Button(fileGuard.running ? "停止监控" : "启动监控") {
                        if fileGuard.running {
                            fileGuard.stop(); processGuard.stop()
                        } else {
                            fileGuard.start(); processGuard.start()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }

                if !status.isEmpty {
                    Text(status).font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                }

                Divider()
                HStack {
                    Text("规则库").font(.subheadline.bold())
                    Spacer()
                    Text("\(store.rules.count + memoryRuleStore.rules.count) 条")
                        .font(.caption).foregroundStyle(.secondary)
                }
                List {
                    Section("Agent 规则") {
                        if store.rules.isEmpty {
                            Text("暂无。用左侧自然语言添加，例如「保护 ~/Projects/.env 不被删除」")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        ForEach(store.rules) { r in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Circle().fill(Color.agrSeverity(r.severity.isEmpty ? "high" : r.severity))
                                        .frame(width: 8, height: 8)
                                    Text(r.message).font(.body)
                                }
                                HStack(spacing: 6) {
                                    Label(r.kindLabel, systemImage: "flag").foregroundStyle(.secondary)
                                    if let ops = r.ops { Label(ops.joined(separator: ","), systemImage: "bolt") }
                                    Label(r.action.agrActionLabel, systemImage: "shield")
                                }.font(.caption2).foregroundStyle(.secondary)
                                if let nl = r.naturalLanguage {
                                    Text("↳ \(nl)").font(.caption2).foregroundStyle(.tertiary)
                                }
                            }
                        }
                        .onDelete { indices in
                            for i in indices { store.remove(store.rules[i]) }
                        }
                    }

                    Section("记忆体规则") {
                        if memoryRuleStore.rules.isEmpty {
                            Text("暂无记忆体规则").font(.caption).foregroundStyle(.secondary)
                        }
                        ForEach(memoryRuleStore.rules) { r in
                            HStack(alignment: .top, spacing: 8) {
                                Toggle("", isOn: Binding(
                                    get: { r.enabled },
                                    set: { _ in memoryRuleStore.toggle(r) }
                                ))
                                .toggleStyle(.checkbox)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(r.name).font(.body)
                                    Text(r.description)
                                        .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                                    Text(r.pattern)
                                        .font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
                                }
                                Spacer()
                                if !isBuiltInMemoryRule(r) {
                                    Button { memoryRuleStore.remove(r) } label: {
                                        Image(systemName: "trash").foregroundStyle(.secondary)
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                        }

                        DisclosureGroup("添加自定义规则", isExpanded: $showAddMemoryRule) {
                            VStack(alignment: .leading, spacing: 6) {
                                TextField("规则名称", text: $newMemName)
                                TextField("描述", text: $newMemDesc)
                                TextField("正则表达式", text: $newMemPattern)
                                Picker("严重级", selection: $newMemSeverity) {
                                    Text("critical").tag("critical")
                                    Text("high").tag("high")
                                    Text("medium").tag("medium")
                                    Text("info").tag("info")
                                }
                                .pickerStyle(.segmented)
                                Button("添加") { addMemoryRule() }
                                    .disabled(newMemName.isEmpty || newMemPattern.isEmpty)
                            }
                            .textFieldStyle(.roundedBorder)
                            .padding(.top, 4)
                        }

                        Button("恢复默认规则") { memoryRuleStore.resetToDefaults() }
                            .font(.caption)
                    }
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))

                Divider()
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 4) {
                        Image(systemName: "shippingbox").foregroundStyle(.tertiary)
                        Text("\(appVersion) · 开发编译版（未公证，非发布版）").font(.caption2).foregroundStyle(.tertiary)
                    }
                    if !buildDateText.isEmpty {
                        Text("构建于 \(buildDateText) · 重新打包后会更新此时间，可据此判断是否最新")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
            .padding(14)
            .frame(minWidth: 380)

            // 右：状态栏 + 强提示横幅 + 分段视图
            VStack(alignment: .leading, spacing: 10) {
                // 状态栏
                HStack(spacing: 14) {
                    let active = fileGuard.running || processGuard.running
                    Label(active ? "监控中" : "未启动",
                          systemImage: active ? "dot.radiowaves.left.and.right" : "pause.circle")
                        .foregroundStyle(active ? .green : .secondary)
                        .font(.subheadline.bold())
                    Divider().frame(height: 18)
                    Label("受保护文件 \(protectedFiles)", systemImage: "doc.badge.lock")
                    Label("命令规则 \(cmdRuleCount)", systemImage: "terminal")
                    Label("记忆体规则 \(memoryRuleStore.enabledRules.count)", systemImage: "key")
                    Label("事件 \(eventCount)", systemImage: "list.bullet")
                    Label("密钥命中 \(memoryScan.findings.count)", systemImage: "key.fill")
                        .foregroundColor(memoryScan.findings.isEmpty ? Color.secondary : Color.red)
                }
                .font(.caption).foregroundStyle(.secondary)
                .padding(.vertical, 2)

                // 强提示横幅：拦截/还原时高亮
                if let b = banner {
                    HStack(spacing: 10) {
                        Image(systemName: b.kind == "cmd" ? "terminal.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(Color.agrSeverity(b.severity))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(" AgentReins 已处置：\(b.action.agrActionLabel)").font(.subheadline.bold())
                            Text(b.kind == "cmd" ? (b.command ?? "") : "\(b.op) · \(b.path)")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                        }
                        Spacer()
                        Button { banner = nil } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 8)
                        .fill(Color.agrSeverity(b.severity).opacity(0.12)))
                    .overlay(RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.agrSeverity(b.severity).opacity(0.5), lineWidth: 1))
                }

                Picker("视图", selection: $rightTab) {
                    Text("拦截规则").tag("rules")
                    Text("实时运行过程").tag("timeline")
                    Text("记忆体审计").tag("memory")
                }
                .pickerStyle(.segmented)
                .padding(.bottom, 4)

                if rightTab == "rules" {
                    rulesView
                } else if rightTab == "timeline" {
                    timelineView
                } else {
                    memoryView
                }
            }
            .padding(14)
            .frame(minWidth: 380)
        }
        .onReceive(fileGuard.$events) { list in
            if let e = list.first, e.action == "restored" || e.action == "alert" { banner = e }
        }
        .onReceive(processGuard.$events) { list in
            if let e = list.first, e.severity == "critical" { banner = e }
        }
    }

    // MARK: - 拦截规则面板
    private var rulesView: some View {
        List {
            Section("文件保护规则（\(store.rules.filter { $0.kind == "file" }.count)）") {
                if store.rules.filter({ $0.kind == "file" }).isEmpty {
                    Text("暂无。用左侧自然语言添加，例如「保护 ~/Projects/.env 不被删除」")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(store.rules.filter { $0.kind == "file" }) { r in
                    RuleRow(rule: r)
                }
            }
            Section("命令监测规则（\(store.rules.filter { $0.kind == "cmd" }.count + ProcessGuard.builtin.count)）") {
                ForEach(ProcessGuard.builtin, id: \.id) { cr in
                    HStack(alignment: .top, spacing: 8) {
                        Circle().fill(Color.agrSeverity(cr.severity)).frame(width: 8, height: 8).padding(.top, 5)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(cr.message).font(.body)
                            HStack(spacing: 6) {
                                Label("命令", systemImage: "flag").foregroundStyle(.secondary)
                                Label(cr.severity, systemImage: "exclamationmark.circle")
                                Label("实时监测（可视化）", systemImage: "eye")
                            }.font(.caption2).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                }
                ForEach(store.rules.filter { $0.kind == "cmd" }) { r in
                    RuleRow(rule: r)
                }
            }
            Section("记忆体检测规则（\(memoryRuleStore.enabledRules.count)/\(memoryRuleStore.rules.count)）") {
                if memoryRuleStore.enabledRules.isEmpty {
                    Text("未启用任何记忆体规则。去左侧「记忆体规则」打开开关或添加自定义规则。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(memoryRuleStore.enabledRules) { r in
                    HStack(alignment: .top, spacing: 8) {
                        Circle().fill(Color.agrSeverity(r.severity)).frame(width: 8, height: 8).padding(.top, 5)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(r.name).font(.body)
                            Text(r.pattern).font(.caption2).foregroundStyle(.tertiary).lineLimit(2)
                        }
                        Spacer()
                    }
                }
            }
        }
        .listStyle(.inset(alternatesRowBackgrounds: true))
    }

    // MARK: - 实时运行过程时间线
    private var timelineView: some View {
        VStack(alignment: .leading, spacing: 8) {
            let active = fileGuard.running || processGuard.running
            Text(active ? "● 监控中（文件改动 + agent 命令）" : "○ 未启动")
                .font(.caption).foregroundStyle(active ? .green : .secondary)
            List {
                if timeline.isEmpty {
                    Text("暂无事件").foregroundStyle(.secondary).font(.caption)
                }
                ForEach(timeline) { ev in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: ev.kind == "cmd" ? "terminal" : (ev.action == "restored" ? "arrow.uturn.backward" : "exclamationmark.triangle"))
                            .foregroundStyle(Color.agrSeverity(ev.severity))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(ev.kind == "cmd" ? "命令 · \(ev.action.agrActionLabel)" : "\(ev.action.agrActionLabel) · \(ev.op)").font(.body)
                            if ev.kind == "cmd" {
                                Text(ev.command ?? "").font(.caption).foregroundStyle(.secondary).lineLimit(3)
                            } else {
                                Text(ev.path).font(.caption).foregroundStyle(.secondary)
                            }
                            HStack(spacing: 6) {
                                if let ag = ev.agent { Label(ag, systemImage: "cpu") }
                                Label(ev.severity, systemImage: "exclamationmark.circle")
                            }.font(.caption2).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        Text(df.string(from: ev.ts)).font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
            Text("说明：文件改动自动还原（软拦截）；agent 命令实时展示（可视化，硬拦截需 ESF）。\n GUI agent 的 LLM 思考为黑盒，仅能看到其落地的文件/命令。")
                .font(.caption2).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - 记忆体 Inspector（结构树 + 内容 + 修正）
    private var memoryView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button(memoryScan.scanning ? "扫描中…" : "立即扫描") {
                    memoryScan.runScan(rules: memoryRuleStore.enabledRules)
                }
                .disabled(memoryScan.scanning)
                Toggle("每日自动", isOn: $memoryScan.autoScan)
                    .onChange(of: memoryScan.autoScan) { on in
                        if on {
                            memoryScan.startAuto { memoryRuleStore.enabledRules }
                        } else {
                            memoryScan.stopAuto()
                        }
                    }
                Spacer()
                if !memoryScan.files.isEmpty {
                    Label("\(memoryScan.files.count) 文件", systemImage: "doc")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if let last = memoryScan.lastScan {
                Text("上次 \(df.string(from: last)) · 命中 \(memoryScan.findings.count) 处")
                    .font(.caption).foregroundStyle(.secondary)
            }

            HSplitView {
                // 左：结构树（按 agent 分组）
                structureList
                    .frame(minWidth: 190, idealWidth: 220)
                // 右：内容 + 修正
                inspectorDetail
                    .frame(minWidth: 240)
            }

            Text("扫描 agent 记忆体（Kiro/Claude/Cursor/Codex）是否保存密钥/令牌。\n需「系统设置 → 隐私与安全性 → 完全磁盘访问权限」授权 AgentReins 才能读 ~/.kiro 等。修正会备份原文件为 .agentreins.bak。")
                .font(.caption2).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
        }
        .sheet(isPresented: $showingEditor) {
            if let p = selectedPath {
                EditorView(path: p, initial: selectedContent ?? "",
                    onSave: { newContent in
                        memoryScan.editFile(path: p, content: newContent) { reloadSelected() }
                        showingEditor = false
                    },
                    onCancel: { showingEditor = false })
            }
        }
    }

    private var structureList: some View {
        List {
            let groups = MemoryFile.groupByAgent(memoryScan.files)
            if groups.isEmpty {
                Text("暂无。点「立即扫描」后查看记忆体结构。")
                    .foregroundStyle(.secondary).font(.caption)
            }
            ForEach(groups, id: \.agent) { g in
                Section(g.agent) {
                    ForEach(g.files) { f in
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: f.kind == "sqlite" ? "database" : "doc.text")
                                .foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(f.rel).font(.caption).lineLimit(1)
                                HStack(spacing: 6) {
                                    if f.sensitiveCount > 0 {
                                        Label("\(f.sensitiveCount)", systemImage: "key.fill")
                                            .foregroundStyle(.red)
                                    } else {
                                        Label("干净", systemImage: "checkmark.shield")
                                            .foregroundStyle(.green)
                                    }
                                    Text("\(f.size)B").font(.caption2).foregroundStyle(.tertiary)
                                }
                            }
                            Spacer()
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { selectFile(f) }
                        .listRowBackground(selectedPath == f.path ? Color.accentColor.opacity(0.12) : nil)
                    }
                }
            }
        }
        .listStyle(.inset(alternatesRowBackgrounds: true))
    }

    @ViewBuilder
    private var inspectorDetail: some View {
        if let f = selectedFile {
            VStack(alignment: .leading, spacing: 6) {
                Text(f.rel).font(.subheadline.bold()).lineLimit(2)
                HStack(spacing: 6) {
                    Label(f.agent, systemImage: "cpu")
                    if f.kind == "sqlite" {
                        Label("二进制库·仅展示命中", systemImage: "eye")
                    }
                    Label("\(f.size)B", systemImage: "doc")
                }.font(.caption).foregroundStyle(.secondary)

                Divider()

                if f.kind == "sqlite" {
                    sqliteHits(f)
                } else if let content = selectedContent {
                    ScrollView { contentLines(content, file: f) }
                        .frame(maxHeight: 260)
                } else {
                    ProgressView("读取中…").font(.caption)
                }

                Divider()
                correctionPanel(f)
            }
            .padding(.leading, 4)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Image(systemName: "magnifyingglass").font(.title).foregroundStyle(.tertiary)
                Text("选择左侧文件查看内容；敏感行高亮，点敏感行可打码/删行。")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// 文本文件：逐行渲染，命中行高亮，点敏感行选中命中。
    private func contentLines(_ content: String, file: MemoryFile) -> some View {
        let lines = content.components(separatedBy: "\n")
        return VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(lines.enumerated()), id: \.offset) { idx, line in
                let ln = idx + 1
                HStack(alignment: .top, spacing: 6) {
                    Text("\(ln)").font(.caption2).foregroundStyle(.tertiary)
                        .frame(width: 30, alignment: .trailing)
                    Text(line.isEmpty ? " " : line)
                        .font(.system(.caption, design: .monospaced))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                }
                .padding(.vertical, 1)
                .background(file.hitLines.contains(ln) ? Color.agrSeverity("high").opacity(0.16) : nil)
                .onTapGesture {
                    if let h = file.hits.first(where: { $0.line == ln }) { selectedHit = h }
                }
            }
        }
    }

    /// SQLite 二进制库：不内联编辑，仅列命中（脱敏预览）。
    private func sqliteHits(_ f: MemoryFile) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                if f.hits.isEmpty {
                    Text("该库无文本命中。").font(.caption).foregroundStyle(.secondary)
                }
                ForEach(f.hits) { h in
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "key.fill").foregroundStyle(Color.agrSeverity(h.severity))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(h.type).font(.caption)
                            Text(h.preview).font(.caption2).foregroundStyle(.tertiary)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { selectedHit = h }
                }
            }
        }
        .frame(maxHeight: 260)
    }

    /// 修正面板：选中命中→打码/删行/忽略；否则文件级编辑/还原。
    @ViewBuilder
    private func correctionPanel(_ f: MemoryFile) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            if let h = selectedHit {
                HStack(spacing: 6) {
                    Image(systemName: "key.fill").foregroundStyle(.red)
                    Text(h.type).font(.subheadline.bold())
                }
                Text("行 \(h.line) · \(h.preview)")
                    .font(.caption).foregroundStyle(.secondary)
                if f.isTextEditable {
                    HStack {
                        Button("打码") { memoryScan.redact(h) { reloadSelected() } }
                            .buttonStyle(.bordered)
                        Button("删行") { memoryScan.deleteLine(h) { reloadSelected() } }
                            .buttonStyle(.bordered)
                        Button("忽略") { selectedHit = nil }
                            .buttonStyle(.borderless)
                    }
                } else {
                    Text("二进制库不支持内联打码/删行，请手动编辑或用「还原」撤销。")
                        .font(.caption2).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Text("选中敏感行可精确打码/删行；或整文件编辑（改前自动备份）。")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("编辑全文") { showingEditor = true }
                        .buttonStyle(.bordered)
                    if memoryScan.hasBackup(f.path) {
                        Button("还原 .bak") { memoryScan.restoreBackup(path: f.path) { reloadSelected() } }
                            .buttonStyle(.bordered)
                    }
                }
            }
        }
    }

    private func selectFile(_ f: MemoryFile) {
        selectedFile = f
        selectedPath = f.path
        selectedHit = nil
        selectedContent = nil
        memoryScan.loadContent(path: f.path) { c in selectedContent = c }
    }

    private func reloadSelected() {
        guard let p = selectedPath else { return }
        memoryScan.loadContent(path: p) { c in selectedContent = c }
        selectedFile = memoryScan.files.first { $0.path == p }
    }

    private func addRule() {
        let text = nlText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        busy = true; status = ""
        Task {
            var rule: Rule? = nil
            var warn: String? = nil
            if useLLM, !apiKey.isEmpty {
                let cfg = NLParser.LLMConfig(baseURL: baseURL, apiKey: apiKey, model: model)
                do {
                    rule = try await NLParser.parseLLM(text, config: cfg)
                } catch {
                    rule = NLParser.parseLocal(text)
                    warn = "云端解析失败（\(error.localizedDescription)），已使用本地解析。"
                }
            } else {
                rule = NLParser.parseLocal(text)
            }
            if let r = rule {
                await MainActor.run {
                    store.add(r)
                    fileGuard.setRules(store.rules)
                    processGuard.setRules(store.rules)
                    nlText = ""
                    status = (warn ?? "") + (warn == nil ? "" : "\n") + "已添加：\(r.message)"
                }
            }
            await MainActor.run { busy = false }
        }
    }

    private func addMemoryRule() {
        let name = newMemName.trimmingCharacters(in: .whitespaces)
        let pat = newMemPattern.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty && !pat.isEmpty else { return }
        let rid = "custom_\(UUID().uuidString.prefix(8))"
        let rule = MemoryRule(id: rid, name: name, description: newMemDesc,
                              pattern: pat, severity: newMemSeverity, enabled: true)
        memoryRuleStore.add(rule)
        newMemName = ""; newMemPattern = ""; newMemDesc = ""; newMemSeverity = "high"
        showAddMemoryRule = false
    }

    private func isBuiltInMemoryRule(_ r: MemoryRule) -> Bool {
        MemoryRuleStore.builtInRules().contains(where: { $0.id == r.id })
    }
}

/// 单条规则行（拦截规则面板复用）。
private struct RuleRow: View {
    let rule: Rule
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Circle().fill(Color.agrSeverity(rule.severity.isEmpty ? "high" : rule.severity))
                .frame(width: 8, height: 8).padding(.top, 5)
            VStack(alignment: .leading, spacing: 2) {
                Text(rule.message).font(.body)
                HStack(spacing: 6) {
                    Label(rule.kindLabel, systemImage: "flag").foregroundStyle(.secondary)
                    Label(rule.severity, systemImage: "exclamationmark.circle")
                    Label(rule.enforceSummary, systemImage: "shield")
                }.font(.caption2).foregroundStyle(.secondary)
                Text(rule.triggerSummary).font(.caption2).foregroundStyle(.tertiary).lineLimit(2)
            }
            Spacer()
        }
    }
}

/// 全文件编辑 sheet：加载原文，用户改后保存（改前自动备份由 MemoryScanManager 处理）。
private struct EditorView: View {
    let path: String
    let initial: String
    let onSave: (String) -> Void
    let onCancel: () -> Void
    @State private var text: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("编辑文件").font(.headline)
            Text(URL(fileURLWithPath: path).lastPathComponent)
                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Text("保存会先备份原文件为 .agentreins.bak，可一键还原。")
                .font(.caption2).foregroundStyle(.tertiary)
            TextEditor(text: $text)
                .font(.system(.caption, design: .monospaced))
                .frame(minWidth: 480, minHeight: 320)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.gray.opacity(0.4)))
            HStack {
                Spacer()
                Button("取消", role: .cancel) { onCancel() }
                Button("保存") {
                    onSave(text)
                }
                .buttonStyle(.borderedProminent)
                .disabled(text == initial)
            }
        }
        .padding(16)
        .frame(minWidth: 520, minHeight: 440)
        .onAppear { text = initial }
    }
}
