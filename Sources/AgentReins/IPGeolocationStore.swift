import Combine
import Foundation
import Darwin

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
    @Published private(set) var failures: [String: String] = [:]
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
            failures.removeValue(forKey: host)
            guard let url = URL(string: "https://ipwho.is/\(host)?fields=success,ip,country,region,city,connection") else {
                pending.remove(host); failures[host] = "IP 查询地址无效"; continue
            }
            Task {
                defer { pending.remove(host) }
                do {
                    var request = URLRequest(url: url); request.timeoutInterval = 15
                    let (data, response) = try await URLSession.shared.data(for: request)
                    guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                        failures[host] = "位置服务 HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)"; return
                    }
                    guard let record = Self.decode(data, fallbackIP: host) else {
                        failures[host] = "位置服务未返回有效位置与归属"; return
                    }
                    records[host] = record
                    persist()
                } catch { failures[host] = error.localizedDescription }
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

    nonisolated static func isIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return value.withCString { inet_pton(AF_INET, $0, &ipv4) == 1 || inet_pton(AF_INET6, $0, &ipv6) == 1 }
    }

    nonisolated static func isPublicIPAddress(_ value: String) -> Bool {
        guard isIPAddress(value) else { return false }
        if value.contains(":") {
            var address = in6_addr()
            guard value.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return false }
            let bytes = withUnsafeBytes(of: address) { Array($0) }
            // Only global unicast, excluding documentation space; rejects mapped private IPv4 too.
            return (bytes[0] & 0xe0) == 0x20
                && !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
        }
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4, components.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) else { return false }
        let parts = components.compactMap { Int($0) }
        guard parts.count == 4, parts.allSatisfy({ (0...255).contains($0) }) else { return false }
        if parts[0] == 10 || parts[0] == 127 || parts[0] == 0 { return false }
        if parts[0] == 192 && parts[1] == 168 { return false }
        if parts[0] == 172 && (16...31).contains(parts[1]) { return false }
        if parts[0] == 169 && parts[1] == 254 { return false }
        if parts[0] >= 224 || (parts[0] == 100 && (64...127).contains(parts[1])) { return false }
        if parts[0] == 192 && parts[1] == 0 { return false }
        if parts[0] == 198 && (parts[1] == 18 || parts[1] == 19 || (parts[1] == 51 && parts[2] == 100)) { return false }
        if parts[0] == 203 && parts[1] == 0 && parts[2] == 113 { return false }
        return true
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(records) else { return }
        UserDefaults.standard.set(data, forKey: defaultsKey)
    }
}
