import Combine
import Foundation

struct IPGeolocation: Codable, Equatable {
    let ip: String
    let country: String?
    let region: String?
    let city: String?
    let asn: Int?
    let organization: String?
    let isp: String?
    let fetchedAt: Date

    var locationLabel: String {
        let parts = [city, region, country].compactMap { value in
            value.flatMap { $0.isEmpty ? nil : $0 }
        }
        return parts.isEmpty ? "Location unavailable" : parts.joined(separator: ", ")
    }

    var ownerLabel: String? {
        let owner = [organization, isp].compactMap { value -> String? in
            guard let value, !value.isEmpty else { return nil }
            return value
        }.first
        if let asn, let owner { return "AS\(asn) · \(owner)" }
        if let asn { return "AS\(asn)" }
        return owner
    }
}

@MainActor
final class IPGeolocationStore: ObservableObject {
    @Published private(set) var records: [String: IPGeolocation] = [:]
    @Published private(set) var pending: Set<String> = []
    private let defaultsKey = "agentreins.ip-geolocation-cache.v1"
    private let lifetime: TimeInterval = 30 * 86_400

    init() {
        if let data = UserDefaults.standard.data(forKey: defaultsKey),
           let decoded = try? JSONDecoder().decode([String: IPGeolocation].self, from: data) {
            records = decoded.filter { Date().timeIntervalSince($0.value.fetchedAt) < lifetime }
        }
    }

    func resolve(_ hosts: [String]) {
        for host in Set(hosts.map { $0.lowercased() }) where Self.isPublicIPAddress(host) {
            guard records[host] == nil, pending.insert(host).inserted else { continue }
            guard let url = URL(string: "https://ipwho.is/\(host)?fields=success,ip,country,region,city,connection") else {
                pending.remove(host); continue
            }
            Task {
                defer { pending.remove(host) }
                do {
                    let (data, response) = try await URLSession.shared.data(from: url)
                    guard (response as? HTTPURLResponse)?.statusCode == 200,
                          let record = Self.decode(data, fallbackIP: host) else { return }
                    records[host] = record
                    persist()
                } catch { return }
            }
        }
    }

    nonisolated static func decode(_ data: Data, fallbackIP: String) -> IPGeolocation? {
        struct Response: Decodable {
            struct Connection: Decodable { let asn: Int?; let org: String?; let isp: String? }
            let success: Bool?
            let ip: String?
            let country: String?
            let region: String?
            let city: String?
            let connection: Connection?
        }
        guard let value = try? JSONDecoder().decode(Response.self, from: data), value.success != false else { return nil }
        return IPGeolocation(ip: value.ip ?? fallbackIP, country: value.country, region: value.region,
            city: value.city, asn: value.connection?.asn, organization: value.connection?.org,
            isp: value.connection?.isp, fetchedAt: Date())
    }

    nonisolated static func isPublicIPAddress(_ value: String) -> Bool {
        if value.contains(":") {
            let lower = value.lowercased()
            return lower != "::1" && !lower.hasPrefix("fe80:") && !lower.hasPrefix("fc") && !lower.hasPrefix("fd")
        }
        let parts = value.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4, parts.allSatisfy({ (0...255).contains($0) }) else { return false }
        if parts[0] == 10 || parts[0] == 127 || parts[0] == 0 { return false }
        if parts[0] == 192 && parts[1] == 168 { return false }
        if parts[0] == 172 && (16...31).contains(parts[1]) { return false }
        if parts[0] == 169 && parts[1] == 254 { return false }
        return true
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(records) else { return }
        UserDefaults.standard.set(data, forKey: defaultsKey)
    }
}
