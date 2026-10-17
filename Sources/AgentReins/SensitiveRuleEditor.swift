import SwiftUI

struct SensitiveRuleDraft: Codable {
    var name: String
    var kind: String
    var value: String
    var explanation: String
    var limitation: String
    var supported: Bool
    func validate() throws {
        guard supported, ["keyword", "secret"].contains(kind), (3...4096).contains(value.count), !name.isEmpty, name.count <= 120 else {
            throw NSError(domain: "SensitiveRule", code: 1, userInfo: [NSLocalizedDescriptionKey: "该描述不能直接转换为本机字面量规则，请补充具体标记或敏感值。"])
        }
    }
}

struct SensitiveRuleEditor: View {
    @EnvironmentObject private var analyzer: SemanticAnalyzer
    @Environment(\.dismiss) private var dismiss
    @State private var description = ""
    @State private var draft: SensitiveRuleDraft?
    @State private var rules: [[String: Any]] = []
    @State private var document: [String: Any] = [:]
    @State private var error: String?
    @State private var busy = false
    @State private var settings = false
    @State private var loadFailed = false
    @State private var editing: Int?
    private var url: URL { FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/AgentReins/security-policy.json") }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Text("敏感数据规则").font(.title2); Spacer(); Button("模型设置") { settings = true }; Button("完成") { dismiss() } }
            Text("用一句话描述要保护的数据。仅发送这段描述给规则理解模型；请用示例占位符描述密钥，具体值可在确认前本机填写。")
            TextEditor(text: $description).frame(height: 80).border(Color.secondary.opacity(0.3)).disabled(busy)
            Button(busy ? "正在理解…" : "理解规则") {
                busy = true; draft = nil; editing = nil; error = nil
                Task { draft = await analyzer.understandSensitiveRule(description); error = draft == nil ? analyzer.lastError : nil; busy = false }
            }.disabled(busy || description.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            if draft != nil {
                TextField("规则名称", text: Binding(get: { draft?.name ?? "" }, set: { draft?.name = $0 }))
                TextField("本机匹配的具体文本", text: Binding(get: { draft?.value ?? "" }, set: { draft?.value = $0 }))
                Text(draft?.explanation ?? "")
                Text(draft?.limitation ?? "").foregroundStyle(.secondary)
                Button("确认并启用") { saveDraft() }.disabled(draft?.supported != true)
            }
            if let error { Text(error).foregroundStyle(.red) }
            Divider()
            Text("已保存规则 · 匹配已采发送正文，不代表语义分类或自动拦截")
            ScrollView {
                ForEach(rules.indices, id: \.self) { index in
                    HStack {
                        Text(rules[index]["name"] as? String ?? "规则")
                        Spacer()
                        Button((rules[index]["enabled"] as? Bool ?? true) ? "停用" : "启用") { mutate { rules[index]["enabled"] = !(rules[index]["enabled"] as? Bool ?? true) } }
                        Button("编辑") {
                            editing = index
                            draft = SensitiveRuleDraft(name: rules[index]["name"] as? String ?? "", kind: rules[index]["kind"] as? String ?? "keyword", value: rules[index]["value"] as? String ?? "", explanation: "编辑本机字面量规则", limitation: "不理解上下文；匹配词出现即告警。", supported: true)
                        }
                        Button("删除") { mutate { rules.remove(at: index); editing = nil; draft = nil } }
                    }.padding(.vertical, 5)
                }
            }
        }.padding(22).frame(width: 720, height: 650)
        .sheet(isPresented: $settings) { AnalysisModelSettingsView().environmentObject(analyzer) }
        .onAppear { load() }
    }
    private func load() {
        do {
            if FileManager.default.fileExists(atPath: url.path) {
                document = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any] ?? [:]
                guard let loaded = document["rules"] as? [[String: Any]] else { throw CocoaError(.fileReadCorruptFile) }
                rules = loaded
            } else { document = ["approvedModelHosts": [], "rules": []] }
        } catch { loadFailed = true; self.error = "无法读取策略文件，未覆盖原数据。" }
    }
    private func persist() throws {
        guard !loadFailed else { throw CocoaError(.fileReadCorruptFile) }
        guard rules.count <= 100 else { throw CocoaError(.fileWriteOutOfSpace) }
        document["rules"] = rules
        let data = try JSONSerialization.data(withJSONObject: document, options: [.prettyPrinted, .sortedKeys])
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    private func mutate(_ change: () -> Void) {
        let old = rules; change()
        do { try persist(); error = nil } catch { rules = old; self.error = "保存失败，规则未更新。" }
    }
    private func saveDraft() {
        guard let draft else { return }
        do {
            try draft.validate()
            let entry: [String: Any] = ["name": draft.name, "kind": draft.kind, "value": draft.value, "enabled": true]
            mutate { if let editing, rules.indices.contains(editing) { rules[editing] = entry } else { rules.append(entry) } }
            if error == nil { self.draft = nil; editing = nil; description = "" }
        } catch { self.error = error.localizedDescription }
    }
}
