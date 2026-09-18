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

    func load(apiKey: String?) async {
        guard !loading else { return }
        loading = true
        defer { loading = false }
        do {
            var components = URLComponents(string: "https://openrouter.ai/api/v1/models")!
            components.queryItems = [
                URLQueryItem(name: "output_modalities", value: "text"),
                URLQueryItem(name: "sort", value: "most-popular")
            ]
            var request = URLRequest(url: components.url!)
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
            self.error = error.localizedDescription
        }
    }

    nonisolated static func decode(_ data: Data) throws -> [OpenRouterModel] {
        struct Envelope: Codable { let data: [OpenRouterModel] }
        return try JSONDecoder().decode(Envelope.self, from: data).data
    }
}
