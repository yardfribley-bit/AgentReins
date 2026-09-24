import Foundation
import Darwin

/// A point-in-time observation, not an authenticated corporate employee identity.
struct AuditDeviceIdentity: Codable {
    let localUser: String
    let deviceName: String
    let localIPs: [String]
    let observedAt: Date

    static func isPrivateIPv4(_ address: String) -> Bool {
        let parts = address.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4, parts.allSatisfy({ (0...255).contains($0) }) else { return false }
        return parts[0] == 10 || (parts[0] == 172 && (16...31).contains(parts[1])) ||
            (parts[0] == 192 && parts[1] == 168)
    }

    static func capture() -> AuditDeviceIdentity {
        var addresses = Set<String>()
        var head: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&head) == 0 {
            defer { freeifaddrs(head) }
            var current = head
            while let entry = current {
                defer { current = entry.pointee.ifa_next }
                let item = entry.pointee
                guard item.ifa_flags & UInt32(IFF_UP) != 0,
                      item.ifa_flags & UInt32(IFF_LOOPBACK) == 0,
                      let address = item.ifa_addr, address.pointee.sa_family == UInt8(AF_INET) else { continue }
                var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(address, socklen_t(address.pointee.sa_len), &buffer,
                               socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let ip = String(cString: buffer)
                    if isPrivateIPv4(ip) { addresses.insert(ip) }
                }
            }
        }
        return AuditDeviceIdentity(localUser: NSUserName(),
            deviceName: Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
            localIPs: addresses.sorted(), observedAt: Date())
    }
}
