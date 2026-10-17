import Foundation

struct OpenRouterModel: Codable, Hashable, Identifiable, Sendable {
    struct Pricing: Codable, Hashable, Sendable {
        let prompt: String?
        let completion: String?
    }

    let id: String
    let name: String
    let contextLength: Int?
    let pricing: Pricing?
    let description: String?

    enum CodingKeys: String, CodingKey {
        case id, name, pricing, description
        case contextLength = "context_length"
    }

    var contextLabel: String {
        guard let contextLength else { return "Context unknown" }
        if contextLength >= 1_000_000 { return String(format: "%.1fM context", Double(contextLength) / 1_000_000) }
        return "\(contextLength / 1_000)K context"
    }

    var priceLabel: String {
        let input = perMillion(pricing?.prompt)
        let output = perMillion(pricing?.completion)
        guard input != nil || output != nil else { return "Pricing unavailable" }
        return "Input $\(format(input)) · Output $\(format(output)) / 1M"
    }

    private func perMillion(_ value: String?) -> Double? {
        value.flatMap(Double.init).map { $0 * 1_000_000 }
    }

    private func format(_ value: Double?) -> String {
        guard let value else { return "—" }
        if value == 0 { return "0" }
        if value < 0.01 { return String(format: "%.4f", value) }
        if value < 1 { return String(format: "%.3f", value) }
        return String(format: "%.2f", value)
    }
}

@MainActor
final class OpenRouterModelCatalog: ObservableObject {
    @Published private(set) var models: [OpenRouterModel] = []
    @Published private(set) var loading = false
    @Published private(set) var error: String?

    func load(apiKey: String?, baseURL: String = "https://openrouter.ai/api/v1") async {
        guard !loading else { return }
        loading = true
        defer { loading = false }
        do {
            guard let endpoint = SemanticAnalyzer.chatCompletionsURL(baseURL: baseURL),
                  var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false) else { throw URLError(.badURL) }
            components.path = components.path.replacingOccurrences(of: "/chat/completions", with: "/models")
            components.queryItems = components.host == "openrouter.ai" ? [
                URLQueryItem(name: "output_modalities", value: "text"),
                URLQueryItem(name: "sort", value: "most-popular")
            ] : nil
            var request = URLRequest(url: components.url!, timeoutInterval: 20)
            let cleanKey = apiKey?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !cleanKey.isEmpty { request.setValue("Bearer \(cleanKey)", forHTTPHeaderField: "Authorization") }
            request.setValue("AgentReins", forHTTPHeaderField: "X-OpenRouter-Title")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                throw NSError(domain: "AgentReins.OpenRouterCatalog",
                              code: (response as? HTTPURLResponse)?.statusCode ?? -1,
                              userInfo: [NSLocalizedDescriptionKey: "OpenRouter model catalog request failed."])
            }
            models = try Self.decode(data)
            error = nil
        } catch {
            models = []
            self.error = "无法获取模型列表，可重试或手动填写模型名称。"
        }
    }

    nonisolated static func decode(_ data: Data) throws -> [OpenRouterModel] {
        struct Item: Decodable { let id: String; let name: String?; let context_length: Int?; let pricing: OpenRouterModel.Pricing?; let description: String? }
        struct Envelope: Decodable { let data: [Item] }
        return try JSONDecoder().decode(Envelope.self, from: data).data.map {
            OpenRouterModel(id: $0.id, name: $0.name ?? $0.id, contextLength: $0.context_length, pricing: $0.pricing, description: $0.description)
        }
    }
}
