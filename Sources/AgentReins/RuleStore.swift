import Foundation
import SwiftUI

/// 规则仓库：读写 ~/Library/Application Support/AgentReins/rules.json。
/// 每次启动也会把空的 AgentGuard/rules.json 种上同一份默认拒绝，customized == true 不动。
@MainActor
final class RuleStore: ObservableObject {
    @Published var rules: [Rule] = []
    private var customized = false
    let fileURL: URL

    init() {
        let appSup = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = appSup.appendingPathComponent("AgentReins", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.fileURL = dir.appendingPathComponent("rules.json")
        HardGateStore.seedInstalledRules()
        HardGateStore.seedDefaults()
        load()
    }

    func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        if let doc = try? JSONDecoder().decode(RuleDocument.self, from: data) {
            rules = doc.rules
            customized = doc.customized == true
        } else if let w = try? JSONDecoder().decode(RuleWrapper.self, from: data) {
            rules = w.rules
        }
    }

    func save() {
        let doc = RuleDocument(version: 1, customized: customized, rules: rules)
        if let data = try? JSONEncoder().encode(doc) {
            try? data.write(to: fileURL)
        }
    }

    func add(_ r: Rule) {
        customized = true
        rules.removeAll { $0.id == r.id }
        rules.append(r)
        save()
    }

    func remove(_ r: Rule) {
        customized = true
        rules.removeAll { $0.id == r.id }
        save()
    }
}
