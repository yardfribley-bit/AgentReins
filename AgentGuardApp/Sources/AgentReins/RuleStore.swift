import Foundation
import SwiftUI

/// 规则仓库：持久化到 ~/Library/Application Support/AgentGuard/rules.json，
/// 与 agentguard 生态共用同一 schema。
@MainActor
final class RuleStore: ObservableObject {
    @Published var rules: [Rule] = []
    let fileURL: URL

    init() {
        let appSup = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = appSup.appendingPathComponent("AgentReins", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.fileURL = dir.appendingPathComponent("rules.json")
        load()
    }

    func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        if let doc = try? JSONDecoder().decode(RuleDocument.self, from: data) {
            rules = doc.rules
        } else if let w = try? JSONDecoder().decode(RuleWrapper.self, from: data) {
            rules = w.rules
        }
    }

    func save() {
        let doc = RuleDocument(rules: rules)
        if let data = try? JSONEncoder().encode(doc) {
            try? data.write(to: fileURL)
        }
    }

    func add(_ r: Rule) {
        // 同 id 覆盖
        rules.removeAll { $0.id == r.id }
        rules.append(r)
        save()
    }

    func remove(_ r: Rule) {
        rules.removeAll { $0.id == r.id }
        save()
    }
}
