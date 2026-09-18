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

struct LLMSelfExamination: Codable, Hashable, Sendable {
    let verdict: String
    let confidence: Double
    let evidenceSufficient: Bool
    let falsePositiveRisk: String
    let counterEvidence: String
    let rationale: String

    enum CodingKeys: String, CodingKey {
        case verdict, confidence, rationale
        case evidenceSufficient = "evidence_sufficient"
        case falsePositiveRisk = "false_positive_risk"
        case counterEvidence = "counter_evidence"
    }
}

struct AIHistoricalFinding: Codable, Hashable, Identifiable, Sendable {
    let id: String
    let title: String
    let severity: String
    let summary: String
    let recommendedAction: String
    let evidenceEventIds: [String]
    let ruleId: String
    let llmSelfExamine: LLMSelfExamination

    enum CodingKeys: String, CodingKey {
        case id, title, severity, summary
        case recommendedAction = "recommended_action"
        case evidenceEventIds = "evidence_event_ids"
        case ruleId = "rule_id"
        case llmSelfExamine = "llm_self_examine"
    }
}

struct AIRuleExamination: Codable, Hashable, Identifiable, Sendable {
    let id: String
    let name: String
    let origin: String
    let severity: String
    let condition: String
    let llmSelfExamine: LLMSelfExamination

    enum CodingKeys: String, CodingKey {
        case id, name, origin, severity, condition
        case llmSelfExamine = "llm_self_examine"
    }
}

struct HistoricalSecurityAnalysis: Codable, Sendable {
    let findings: [AIHistoricalFinding]
    let rules: [AIRuleExamination]
    let generatedAt: String?
    let model: String?
    let examinationPasses: Int?

    enum CodingKeys: String, CodingKey {
        case findings, rules, model
        case generatedAt = "generated_at"
        case examinationPasses = "examination_passes"
    }
}

struct FeatureQueryUnderstanding: Codable, Sendable {
    let canonicalName: String
    let searchTerms: [String]
    let intent: String

    enum CodingKeys: String, CodingKey {
        case intent
        case canonicalName = "canonical_name"
        case searchTerms = "search_terms"
    }
}

@MainActor
final class SemanticAnalyzer: ObservableObject {
    @Published private(set) var results: [String: TurnAnalysis] = [:]
    @Published private(set) var usage: [String: AnalysisUsage] = [:]
    @Published private(set) var analyzing = Set<String>()
    @Published var lastError: String?
    @Published private(set) var historicalAnalysis: HistoricalSecurityAnalysis?
    @Published private(set) var analyzingHistory = false
    @Published private(set) var testingConnection = false
    @Published private(set) var connectionVerified = false
    /// Process-memory cache only. This avoids repeated Keychain authorization
    /// prompts during one run without ever persisting the secret outside Keychain.
    private var cachedAnalysisAPIKey: String?
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
        historicalAnalysis = Self.loadHistoricalAnalysis()
    }

    func canStartHistoricalAnalysis() -> Bool {
        let key = cachedAnalysisAPIKey ?? KeychainStore.analysisAPIKey()
        guard configured, let key,
              Self.chatCompletionsURL(baseURL: baseURL) != nil else {
            configured = false
            connectionVerified = false
            UserDefaults.standard.set(false, forKey: "agr_openai_compatible_configured")
            lastError = "The analysis API key is missing. Open AI Rule Analyst and run Test & Save again."
            return false
        }
        cachedAnalysisAPIKey = key
        return true
    }

    func analyzeHistory(_ events: [GuardEvent], policies: [AlertPolicy]) async {
        guard !analyzingHistory else { return }
        guard let key = cachedAnalysisAPIKey ?? KeychainStore.analysisAPIKey(),
              let endpoint = Self.chatCompletionsURL(baseURL: baseURL) else {
            lastError = "The saved analysis model configuration has no accessible API key. Save the key again."
            return
        }
        cachedAnalysisAPIKey = key
        analyzingHistory = true
        defer { analyzingHistory = false }

        let relevant = events.filter { event in
            ["tool", "file", "memory", "network", "external-content", "alert", "model"].contains(event.kind)
        }
        // Select by security value, not merely recency. A credential event from
        // yesterday must outrank hundreds of harmless process/tool records.
        let selected = Dictionary(grouping: relevant, by: { $0.agent ?? "unknown" }).values
            .flatMap { rows in
                rows.sorted {
                    let lhs = Self.historicalRiskScore($0), rhs = Self.historicalRiskScore($1)
                    return lhs == rhs ? $0.ts > $1.ts : lhs > rhs
                }.prefix(35)
            }
            .sorted {
                let lhs = Self.historicalRiskScore($0), rhs = Self.historicalRiskScore($1)
                return lhs == rhs ? $0.ts > $1.ts : lhs > rhs
            }.prefix(180)
        let evidence = selected.map { event in
            let detail = event.command ?? event.modelResponse ?? event.modelPrompt ?? event.path
            return [
                "event_id": event.id.uuidString,
                "time": ISO8601DateFormatter().string(from: event.ts),
                "agent": event.agent ?? "unknown",
                "kind": event.kind, "operation": event.op, "rule_id": event.ruleId,
                "severity": event.severity, "action": event.action,
                "detail": String(redact(detail).prefix(700))
            ]
        }
        let existingRules = policies.map { policy in
            ["id": policy.id, "name": policy.name, "severity": policy.severity,
             "condition": policy.explanation, "origin": "built_in"]
        }
        do {
            let evidenceData = try JSONSerialization.data(withJSONObject: evidence)
            let rulesData = try JSONSerialization.data(withJSONObject: existingRules)
            let draftInstruction = """
            You are the first-pass security analyst for a personal AI-Agent monitor.
            Review historical evidence without inventing facts. Return strict JSON with keys findings and rules.
            Every finding and every rule MUST contain llm_self_examine with: verdict (confirmed|needs_review|rejected),
            confidence (0...1), evidence_sufficient (boolean), false_positive_risk, counter_evidence, rationale.
            Include every supplied built-in rule in rules with origin=built_in. New rules use origin=ai_proposed.
            Findings must cite only supplied event IDs. Reject a finding when evidence is insufficient.
            Never claim data exfiltration from a connection alone. Do not reproduce credentials or secrets.
            Severity is info|medium|high|critical. recommended_action must be concrete and concise.
            """
            let input = "Existing rules:\n\(String(decoding: rulesData, as: UTF8.self))\nHistorical evidence:\n\(String(decoding: evidenceData, as: UTF8.self))"
            let draftBody: [String: Any] = [
                "model": model, "temperature": 0.0,
                "response_format": ["type": "json_object"],
                "messages": [["role": "system", "content": draftInstruction],
                             ["role": "user", "content": input]]
            ]
            let draft = try await requestJSON(body: draftBody, endpoint: endpoint, key: key)
            let examinationInstruction = """
            You are a second, independent LLM security examiner. Challenge the first-pass analysis against the
            supplied evidence. Remove unsupported findings, correct severity, and examine every built-in and
            AI-proposed rule. Return the same strict JSON schema with findings and rules. Every item MUST include
            llm_self_examine: verdict, confidence, evidence_sufficient, false_positive_risk, counter_evidence,
            rationale. Findings may cite only supplied event IDs. A socket alone never proves exfiltration.
            Never reproduce credentials. Include every built-in rule even when its verdict is rejected.
            """
            let examinationInput = "Evidence:\n\(String(decoding: evidenceData, as: UTF8.self))\nExisting rules:\n\(String(decoding: rulesData, as: UTF8.self))\nFirst-pass draft:\n\(String(decoding: draft, as: UTF8.self))"
            let examinationBody: [String: Any] = [
                "model": model, "temperature": 0.0,
                "response_format": ["type": "json_object"],
                "messages": [["role": "system", "content": examinationInstruction],
                             ["role": "user", "content": examinationInput]]
            ]
            let data = try await requestJSON(body: examinationBody, endpoint: endpoint, key: key)
            let decoded = try JSONDecoder().decode(HistoricalSecurityAnalysis.self, from: data)
            let validIDs = Set(selected.map { $0.id.uuidString })
            let safeFindings = decoded.findings.filter { finding in
                !finding.evidenceEventIds.isEmpty && finding.evidenceEventIds.allSatisfy(validIDs.contains)
                    && finding.llmSelfExamine.verdict != "rejected"
            }
            let requiredRules = Set(policies.map(\.id))
            let returnedRules = Set(decoded.rules.filter { $0.origin == "built_in" }.map(\.id))
            guard requiredRules.isSubset(of: returnedRules) else {
                throw NSError(domain: "AgentReins.AnalysisModel", code: -2,
                              userInfo: [NSLocalizedDescriptionKey: "AI self-examination omitted one or more active rules."])
            }
            let result = HistoricalSecurityAnalysis(findings: safeFindings, rules: decoded.rules,
                generatedAt: ISO8601DateFormatter().string(from: Date()), model: model, examinationPasses: 2)
            historicalAnalysis = result
            try Self.saveHistoricalAnalysis(result)
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func configureAndTest(baseURL: String, key: String, model: String) async -> Bool {
        let cleanBaseURL = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanModel = model.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedKey: String?
        if cleanKey.isEmpty {
            resolvedKey = cachedAnalysisAPIKey ?? KeychainStore.analysisAPIKey()
        } else {
            resolvedKey = KeychainStore.saveAndVerifyAnalysisAPIKey(cleanKey) ? cleanKey : nil
        }
        let keyReady = resolvedKey != nil
        guard Self.chatCompletionsURL(baseURL: cleanBaseURL) != nil,
              !cleanModel.isEmpty, keyReady else {
            lastError = "Base URL, API key, or model is invalid."
            return false
        }
        self.baseURL = cleanBaseURL
        self.model = cleanModel
        cachedAnalysisAPIKey = resolvedKey
        testingConnection = true
        defer { testingConnection = false }
        do {
            guard let savedKey = cachedAnalysisAPIKey,
                  let endpoint = Self.chatCompletionsURL(baseURL: cleanBaseURL) else { throw URLError(.userAuthenticationRequired) }
            let body: [String: Any] = [
                "model": cleanModel, "temperature": 0, "max_tokens": 8,
                "response_format": ["type": "json_object"],
                "messages": [["role": "user", "content": "Return {\"status\":\"ok\"} and nothing else."]]
            ]
            _ = try await requestJSON(body: body, endpoint: endpoint, key: savedKey)
            configured = true
            connectionVerified = true
            UserDefaults.standard.set(true, forKey: "agr_openai_compatible_configured")
            lastError = nil
            return true
        } catch {
            configured = false
            connectionVerified = false
            UserDefaults.standard.set(false, forKey: "agr_openai_compatible_configured")
            lastError = "Connection test failed: \(error.localizedDescription)"
            return false
        }
    }

    func removeConfiguration() {
        KeychainStore.deleteAnalysisAPIKey()
        cachedAnalysisAPIKey = nil
        configured = false
        connectionVerified = false
        UserDefaults.standard.set(false, forKey: "agr_openai_compatible_configured")
    }

    func analyze(_ turn: AgentTurn) async {
        guard !analyzing.contains(turn.id) else { return }
        guard let key = cachedAnalysisAPIKey ?? KeychainStore.analysisAPIKey(),
              let endpoint = Self.chatCompletionsURL(baseURL: baseURL) else {
            lastError = "Analysis model is not configured."
            return
        }
        cachedAnalysisAPIKey = key
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

    /// Uses the configured analysis model only to understand the user's
    /// feature name. No project evidence is uploaded at this stage, and the
    /// returned words are only search hints—not historical facts.
    func understandFeatureQuery(_ query: String) async -> FeatureQueryUnderstanding? {
        guard let key = cachedAnalysisAPIKey ?? KeychainStore.analysisAPIKey(),
              let endpoint = Self.chatCompletionsURL(baseURL: baseURL) else { return nil }
        cachedAnalysisAPIKey = key
        let instruction = """
        You translate a user's software-feature question into evidence-search terms.
        Return strict JSON with canonical_name, search_terms, and intent.
        search_terms must contain at most 12 concise Chinese or English synonyms, domain terms,
        likely code symbols, and filenames. Do not claim that any feature, prompt, agent, tool,
        file, or commit exists. You are creating search hints only.
        """
        let body: [String: Any] = [
            "model": model, "temperature": 0,
            "response_format": ["type": "json_object"],
            "messages": [["role": "system", "content": instruction],
                         ["role": "user", "content": String(query.prefix(1_000))]]
        ]
        do {
            let data = try await requestJSON(body: body, endpoint: endpoint, key: key)
            let value = try JSONDecoder().decode(FeatureQueryUnderstanding.self, from: data)
            return FeatureQueryUnderstanding(canonicalName: String(value.canonicalName.prefix(160)),
                searchTerms: Array(value.searchTerms.prefix(12)).map { String($0.prefix(100)) },
                intent: String(value.intent.prefix(300)))
        } catch {
            lastError = "Feature query analysis failed; local evidence search was used: \(error.localizedDescription)"
            return nil
        }
    }

    func generateRequirementDocument(changeSet: IndexedChangeSet,
                                     events: [AgentEventEnvelope],
                                     changes: [IndexedCodeChange],
                                     version: Int) async -> GeneratedRequirementDocument? {
        guard let key = cachedAnalysisAPIKey ?? KeychainStore.analysisAPIKey(),
              let endpoint = Self.chatCompletionsURL(baseURL: baseURL) else {
            lastError = "Analysis model is not configured."
            return nil
        }
        cachedAnalysisAPIKey = key
        let allowed = Set(changeSet.evidenceIDs)
        let eventRows: [[String: Any]] = events.filter { allowed.contains($0.id) }.map { event in
            var text = ""
            var type = "event"
            switch event.payload {
            case .userPrompt(let value): type = "user_prompt"; text = value.rawText
            case .modelMessage(let value): type = "model_response"; text = value.text
            case .toolCall(let value): type = "tool_call"; text = "\(value.toolName) \(value.arguments ?? "")"
            case .toolOutput(let value): type = "tool_output"; text = value.output ?? ""
            case .verification(let value): type = "verification"; text = value.summary
            default: text = ""
            }
            return ["evidence_id": event.id, "type": type, "text": String(redact(text).prefix(4_000))]
        }
        let changeRows: [[String: Any]] = changes.filter { changeSet.codeChangeIDs.contains($0.id) }.map { change in
            ["evidence_id": change.id, "type": "code_change",
             "text": "\(change.operation.rawValue) \(change.path) \(String((change.patch ?? "").prefix(2_000)))"]
        }
        let evidence = eventRows + changeRows
        guard !evidence.isEmpty, let evidenceData = try? JSONSerialization.data(withJSONObject: evidence) else { return nil }
        let instruction = """
        Build a living software requirement document from one Change Set. Return strict JSON with:
        title, original_requirement, final_requirements, evolution, acceptance_criteria, implementation,
        gaps, status. Every statement is {"text":string,"evidence_ids":[string]} and must cite only supplied
        evidence IDs. Do not invent requirements, tools, code, completion, or verification. User refinements and
        corrections update final_requirements; acknowledgements such as OK are not requirements. Agent claims do
        not prove completion. A requirement is complete only when code and independent verification support it.
        status is active|accepted|verified|failed|cancelled|unknown.
        """
        let body: [String: Any] = [
            "model": model, "temperature": 0,
            "response_format": ["type": "json_object"],
            "messages": [["role": "system", "content": instruction],
                         ["role": "user", "content": String(decoding: evidenceData, as: UTF8.self)]]
        ]
        do {
            let data = try await requestJSON(body: body, endpoint: endpoint, key: key)
            let draft = try JSONDecoder().decode(RequirementDocumentDraft.self, from: data)
            let cited = [draft.originalRequirement] + draft.finalRequirements + draft.evolution
                + draft.acceptanceCriteria + draft.implementation + draft.gaps
            guard cited.allSatisfy({ !$0.evidenceIDs.isEmpty && $0.evidenceIDs.allSatisfy(allowed.contains) }) else {
                throw NSError(domain: "AgentReins.Requirements", code: -3,
                    userInfo: [NSLocalizedDescriptionKey: "Requirement document cited unavailable evidence."])
            }
            lastError = nil
            return GeneratedRequirementDocument(id: "\(changeSet.id):v\(version)",
                changeSetID: changeSet.id, version: version, generatedAt: Date(), model: model,
                document: draft, sourceEvidenceIDs: allowed.sorted())
        } catch {
            lastError = error.localizedDescription
            return nil
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
            #"(?i)(password|passwd|pwd|sshpass|token|api[_-]?key)\s*[:=]\s*[^\s,;}]+"#,
            #"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"#
        ]
        return patterns.reduce(text) { value, pattern in
            value.replacingOccurrences(of: pattern, with: "[已打码]", options: .regularExpression)
        }
    }

    nonisolated static func historicalRiskScore(_ event: GuardEvent) -> Int {
        var score = ["critical": 100, "high": 80, "medium": 45][event.severity.lowercased()] ?? 0
        if event.kind == "alert" || event.kind == "external-content" { score += 100 }
        if ["blocked", "restored", "needs_review"].contains(event.action.lowercased()) { score += 70 }
        let detail = (event.command ?? event.modelResponse ?? event.modelPrompt ?? event.path).lowercased()
        if !SensitiveContextExposure.scan(text: detail, source: "history priority").isEmpty { score += 140 }
        if detail.contains("sshpass") || detail.contains("id_rsa") || detail.contains("private key") { score += 100 }
        if event.kind == "memory" || (event.kind == "file" && event.op == "read") { score += 35 }
        if event.kind == "tool" && event.op == "call" { score += 20 }
        if event.kind == "network" { score += 5 }
        return score
    }

    private func requestJSON(body: [String: Any], endpoint: URL, key: String) async throws -> Data {
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
                          userInfo: [NSLocalizedDescriptionKey: "AI historical security analysis request failed."])
        }
        let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let choices = envelope?["choices"] as? [[String: Any]]
        let message = choices?.first?["message"] as? [String: Any]
        guard let content = message?["content"] as? String,
              let json = content.data(using: .utf8) else { throw URLError(.cannotParseResponse) }
        return json
    }

    private nonisolated static func analysisURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("AgentGuard/ai-security-analysis.json")
    }

    private nonisolated static func loadHistoricalAnalysis() -> HistoricalSecurityAnalysis? {
        guard let data = try? Data(contentsOf: analysisURL()) else { return nil }
        return try? JSONDecoder().decode(HistoricalSecurityAnalysis.self, from: data)
    }

    private nonisolated static func saveHistoricalAnalysis(_ value: HistoricalSecurityAnalysis) throws {
        let url = analysisURL()
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(value).write(to: url, options: .atomic)
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

    static func saveAndVerifyAnalysisAPIKey(_ key: String) -> Bool {
        guard let data = key.data(using: .utf8) else { return false }
        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.agentspec.agentreins.analysis",
            kSecAttrAccount as String: "openai-compatible"
        ]
        let update = SecItemUpdate(identity as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update != errSecSuccess {
            guard update == errSecItemNotFound else { return false }
            var item = identity
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { return false }
        }
        return analysisAPIKey() == key
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
