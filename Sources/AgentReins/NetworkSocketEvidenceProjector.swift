import CryptoKit
import Darwin
import Foundation

/// Projects already sampled socket ownership into network evidence without OS
/// reads or task attribution. The caller must validate PID birth identities
/// against the live process before passing its snapshot here.
enum NetworkSocketEvidenceProjector {
    static let maximumProxySampleDistance: TimeInterval = 15

    static func project(processes: [ProcessSnapshotRecord],
                        connections: [NetworkConnectionRecord],
                        proxyDestinations: [ProxyDestinationRecord],
                        observedAt: Date,
                        source: String = "lsof-network") -> [GuardEvent] {
        let byPID = Dictionary(grouping: processes, by: \.pid)
        var seen = Set<UUID>()
        var events: [GuardEvent] = []
        for socket in connections {
            guard !socket.isListener, !isClosing(socket.state),
                  (1...65_535).contains(socket.remotePort),
                  let candidates = byPID[socket.pid],
                  let process = candidates.first,
                  let birth = process.birthIdentity,
                  candidates.allSatisfy({ $0.birthIdentity == birth }),
                  let pid = Int32(process.pid) else { continue }

            let identity = "\(process.pid):\(birth)"
            let loopback = isLoopback(socket.remoteHost)
            let route = loopback ? matchingRoute(socket: socket, processBirth: birth,
                                                 records: proxyDestinations, observedAt: observedAt) : nil
            let host = route?.remoteHost ?? socket.remoteHost
            let port = route?.remotePort ?? socket.remotePort
            let domain = route.flatMap { isIPAddress($0.remoteHost) ? nil : $0.remoteHost.lowercased() }
            let id = stableID(["network-socket-v1", identity, socket.localAddress,
                socket.remoteHost, String(socket.remotePort), route?.proxyName ?? "",
                route?.remoteHost ?? "", route.map { String($0.remotePort) } ?? ""])
            guard seen.insert(id).inserted else { continue }

            var metadata: [String: Any] = [
                "schemaVersion": 1,
                "processIdentity": identity,
                "birthIdentity": birth,
                "executable": process.executablePath ?? "",
                "socket": ["localAddress": socket.localAddress,
                    "remoteHost": socket.remoteHost, "remotePort": socket.remotePort,
                    "state": socket.state ?? "unknown"],
                "destinationStatus": route != nil ? "proxy_route_observed" : (loopback ? "unknown" : "socket_endpoint_only"),
                "observedAt": observedAt.timeIntervalSince1970,
                "limitation": "sampled connection metadata; payload and task are not established"
            ]
            if let route {
                metadata["proxy"] = [
                    "endpoint": ["host": socket.remoteHost, "port": socket.remotePort],
                    "clientPort": route.clientPort,
                    "source": route.proxyName,
                    "observedAt": route.timestamp.timeIntervalSince1970,
                    "sampleDistanceSeconds": abs(observedAt.timeIntervalSince(route.timestamp)),
                    "destinationHost": route.remoteHost,
                    "destinationPort": route.remotePort
                ]
            }
            let command = (try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]))
                .flatMap { String(data: $0, encoding: .utf8) }
            let assessment = NetworkDestinationAssessment.assess(domain: domain, host: host)
            let method = route.map { " + exact client-port and time join via \($0.proxyName) access log" } ?? ""
            events.append(GuardEvent(id: id, kind: "network", ruleId: "network_connection", path: "-",
                command: command, agent: process.agent, op: "connect",
                severity: assessment.needsAttention ? "medium" : "info", ts: observedAt,
                action: "observed", source: source, attributionConfidence: .inferred,
                attributionMethod: "sampled socket owner + PID birth identity\(method); task unassigned",
                processId: pid, parentProcessId: Int32(process.ppid),
                localAddress: socket.localAddress, remoteHost: host, remotePort: port,
                remoteDomain: domain, startedAt: observedAt))
        }
        return events.sorted { $0.id.uuidString < $1.id.uuidString }
    }

    private static func matchingRoute(socket: NetworkConnectionRecord, processBirth: UInt64,
                                      records: [ProxyDestinationRecord], observedAt: Date) -> ProxyDestinationRecord? {
        guard let clientPort = socket.localAddress.split(separator: ":").last.flatMap({ Int($0) }) else { return nil }
        // Access-log timestamps have second precision. A record from an earlier
        // process must not follow a reused client port into a new PID identity.
        let earliestProcessSecond = floor(Double(processBirth) / 1_000_000)
        let matching = records.filter {
            $0.clientPort == clientPort && (1...65_535).contains($0.remotePort)
                && validHost($0.remoteHost)
                && abs(observedAt.timeIntervalSince($0.timestamp)) <= maximumProxySampleDistance
                && $0.timestamp.timeIntervalSince1970 >= earliestProcessSecond
        }
        guard let newest = matching.map(\.timestamp).max() else { return nil }
        let latest = matching.filter { $0.timestamp == newest }
        // Conflicting destinations at the same log timestamp are ambiguous.
        guard let route = latest.first,
              latest.allSatisfy({ $0.remoteHost == route.remoteHost && $0.remotePort == route.remotePort
                  && $0.proxyName == route.proxyName }) else { return nil }
        return route
    }

    private static func isClosing(_ state: String?) -> Bool {
        let closing: Set<String> = ["CLOSED", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT",
            "FIN_WAIT_1", "FIN_WAIT_2", "FIN_WAIT1", "FIN_WAIT2"]
        return state.map { closing.contains($0.uppercased()) } ?? false
    }

    private static func validHost(_ host: String) -> Bool {
        // Host metadata cannot contain URL user-info, paths, or headers.
        !host.isEmpty && host.unicodeScalars.allSatisfy {
            CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:_").contains($0)
        }
    }

    private static func isIPAddress(_ host: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return host.withCString { inet_pton(AF_INET, $0, &ipv4) == 1 || inet_pton(AF_INET6, $0, &ipv6) == 1 }
    }

    private static func isLoopback(_ host: String) -> Bool {
        if host.lowercased() == "localhost" { return true }
        var ipv4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return UInt32(bigEndian: ipv4.s_addr) >> 24 == 127
        }
        var ipv6 = in6_addr()
        guard host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return false }
        return withUnsafeBytes(of: ipv6) { bytes in
            let value = Array(bytes)
            return value.prefix(15).allSatisfy { $0 == 0 } && value[15] == 1
                || value.prefix(10).allSatisfy { $0 == 0 } && value[10] == 255
                    && value[11] == 255 && value[12] == 127
        }
    }

    private static func stableID(_ fields: [String]) -> UUID {
        let data = (try? JSONSerialization.data(withJSONObject: fields)) ?? Data()
        let bytes = Array(SHA256.hash(data: data).prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            (bytes[6] & 0x0F) | 0x50, bytes[7], (bytes[8] & 0x3F) | 0x80, bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
