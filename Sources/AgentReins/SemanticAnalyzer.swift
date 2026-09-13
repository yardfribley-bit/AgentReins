import Foundation
import Security

struct TurnAnalysis: Codable {
    let goal: String
    let actions: String
    let risk: String
    let nextStep: String
}

struct AnalysisUsage {
    let inputTokens: Int
    let outputTokens: Int
    let totalTokens: Int
}

@MainActor
final class SemanticAnalyzer: ObservableObject {
    @Published private(set) var results: [String: TurnAnalysis] = [:]
    @Published private(set) var usage: [String: AnalysisUsage] = [:]
    @Published private(set) var analyzing = Set<String>()
    @Published var lastError: String?
    // Never touch Keychain from a SwiftUI/StateObject initializer. SwiftUI may
    // evaluate the initializer expression more than once while rebuilding its
    // graph, and SecItemCopyMatching can block for seconds on macOS. Persist
    // only the non-sensitive presence flag here; the secret itself is read
    // solely after an explicit Analyze action.
    @Published private(set) var configured: Bool
    @Published var baseURL: String {
        didSet { UserDefaults.standard.set(baseURL, forKey: "agr_openai_compatible_base_url") }
    }
    @Published var model: String {
        didSet { UserDefaults.standard.set(model, forKey: "agr_openai_compatible_model") }
    }

    init() {
        let defaults = UserDefaults.standard
        let legacyConfigured = defaults.bool(forKey: "agr_openrouter_configured")
        baseURL = defaults.string(forKey: "agr_openai_compatible_base_url")
            ?? (legacyConfigured ? "https://openrouter.ai/api/v1" : "https://api.openai.com/v1")
        model = defaults.string(forKey: "agr_openai_compatible_model")
            ?? defaults.string(forKey: "agr_openrouter_model")
            ?? (legacyConfigured ? "openai/gpt-4o-mini" : "gpt-4o-mini")
        configured = defaults.bool(forKey: "agr_openai_compatible_configured") || legacyConfigured
    }

    func configure(baseURL: String, key: String, model: String) -> Bool {
        let cleanBaseURL = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanModel = model.trimmingCharacters(in: .whitespacesAndNewlines)
        let keyReady = cleanKey.isEmpty ? KeychainStore.analysisAPIKey() != nil
                                        : KeychainStore.saveAnalysisAPIKey(cleanKey)
        guard Self.chatCompletionsURL(baseURL: cleanBaseURL) != nil,
              !cleanModel.isEmpty, keyReady else {
            lastError = "Base URL, API key, or model is invalid."
            return false
        }
        self.baseURL = cleanBaseURL
        self.model = cleanModel
        configured = true
        UserDefaults.standard.set(true, forKey: "agr_openai_compatible_configured")
        lastError = nil
        return true
    }

    func removeConfiguration() {
        KeychainStore.deleteAnalysisAPIKey()
        configured = false
        UserDefaults.standard.set(false, forKey: "agr_openai_compatible_configured")
    }

    func analyze(_ turn: AgentTurn) async {
        guard !analyzing.contains(turn.id) else { return }
        guard let key = KeychainStore.analysisAPIKey(),
              let endpoint = Self.chatCompletionsURL(baseURL: baseURL) else {
            lastError = "Analysis model is not configured."
            return
        }
        analyzing.insert(turn.id)
        defer { analyzing.remove(turn.id) }

        let toolSummary = turn.toolCalls.map { "\($0.name): \($0.arguments ?? "无参数") → \($0.status)" }.joined(separator: "\n")
        let raw = """
        用户输入：\(turn.userInput ?? "未采集")
        Agent 向模型发送：\(turn.exchanges.compactMap(\.prompt).joined(separator: "\n").prefix(20_000))
        模型返回：\(turn.exchanges.compactMap(\.response).joined(separator: "\n").prefix(20_000))
        工具执行：\(toolSummary.prefix(12_000))
        """
        let safeInput = redact(raw)
        let instruction = """
        你是个人 AI Agent 安全分析器。根据证据生成普通用户能立即理解的中文结论。
        严禁猜测未提供的信息。输出严格 JSON，字段为 goal、actions、risk、nextStep；每项不超过120字。
        risk 必须区分正常活动、值得注意和明确危险；nextStep 无需处理时明确写“无需处理”。
        """
        let body: [String: Any] = [
            "model": model,
            "temperature": 0.1,
            "response_format": ["type": "json_object"],
            "messages": [
                ["role": "system", "content": instruction],
                ["role": "user", "content": safeInput]
            ]
        ]
        do {
            var request = URLRequest(url: endpoint)
            request.httpMethod = "POST"
            request.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            if endpoint.host?.lowercased().hasSuffix("openrouter.ai") == true {
                request.setValue("AgentReins", forHTTPHeaderField: "X-OpenRouter-Title")
            }
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                throw NSError(domain: "AgentReins.AnalysisModel",
                              code: (response as? HTTPURLResponse)?.statusCode ?? -1,
                              userInfo: [NSLocalizedDescriptionKey: "OpenAI-compatible request failed."])
            }
            let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let choices = envelope?["choices"] as? [[String: Any]]
            let message = choices?.first?["message"] as? [String: Any]
            guard let content = message?["content"] as? String,
                  let json = content.data(using: .utf8) else { throw URLError(.cannotParseResponse) }
            results[turn.id] = try JSONDecoder().decode(TurnAnalysis.self, from: json)
            if let value = envelope?["usage"] as? [String: Any] {
                let input = (value["prompt_tokens"] as? NSNumber)?.intValue ?? 0
                let output = (value["completion_tokens"] as? NSNumber)?.intValue ?? 0
                let total = (value["total_tokens"] as? NSNumber)?.intValue ?? input + output
                usage[turn.id] = AnalysisUsage(inputTokens: input, outputTokens: output, totalTokens: total)
            }
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    nonisolated static func chatCompletionsURL(baseURL: String) -> URL? {
        let trimmed = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard var components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(), ["http", "https"].contains(scheme),
              components.host != nil else { return nil }
        if !components.path.hasSuffix("/chat/completions") {
            components.path += "/chat/completions"
        }
        return components.url
    }

    private func redact(_ text: String) -> String {
        let patterns = [
            #"sk-[A-Za-z0-9_-]{16,}"#,
            #"gh[pousr]_[A-Za-z0-9_]{20,}"#,
            #"AKIA[0-9A-Z]{16}"#,
            #"(?i)(password|passwd|token|api[_-]?key)\s*[:=]\s*[^\s,;}]+"#,
            #"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"#
        ]
        return patterns.reduce(text) { value, pattern in
            value.replacingOccurrences(of: pattern, with: "[已打码]", options: .regularExpression)
        }
    }
}

enum KeychainStore {
    static func analysisAPIKey() -> String? {
        read(service: "com.agentspec.agentreins.analysis", account: "openai-compatible")
            ?? read(service: "com.agentspec.agentreins.openrouter", account: "openrouter")
    }

    private static func read(service: String, account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func saveAnalysisAPIKey(_ key: String) -> Bool {
        guard let data = key.data(using: .utf8) else { return false }
        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.agentspec.agentreins.analysis",
            kSecAttrAccount as String: "openai-compatible"
        ]
        let update = SecItemUpdate(identity as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return true }
        guard update == errSecItemNotFound else { return false }
        var item = identity
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
    }

    static func deleteAnalysisAPIKey() {
        for (service, account) in [
            ("com.agentspec.agentreins.analysis", "openai-compatible"),
            ("com.agentspec.agentreins.openrouter", "openrouter")
        ] {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account
            ]
            SecItemDelete(query as CFDictionary)
        }
    }
}
