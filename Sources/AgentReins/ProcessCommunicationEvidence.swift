import Foundation

/// Connections are undirected. Transport ownership does not establish an RPC caller,
/// transferred content, or membership in the current task.
struct ProcessCommunicationRelation: Equatable {
    let firstIdentity: String
    let secondIdentity: String
    let transport: String
    let endpoints: [String]
    let basis: String
    var identity: String { "\(transport)|\(firstIdentity)|\(secondIdentity)|\(endpoints.joined(separator: "|"))" }
}

enum ProcessCommunicationEvidence {
    static func tcp(processes: [ProcessSnapshotRecord], connections: [NetworkConnectionRecord]) -> [ProcessCommunicationRelation] {
        let owners = identities(processes)
        let eligible = connections.filter {
            owners[$0.pid] != nil && $0.state == "ESTABLISHED" && !$0.isListener &&
            endpoint($0.localAddress).map { loopback($0.host) } == true && loopback($0.remoteHost)
        }
        var result: [String: ProcessCommunicationRelation] = [:]
        for socket in eligible {
            guard let local = endpoint(socket.localAddress), let first = owners[socket.pid] else { continue }
            let ownPIDs = Set(eligible.filter { $0.localAddress == socket.localAddress && $0.remoteHost == socket.remoteHost && $0.remotePort == socket.remotePort }.map(\.pid))
            guard ownPIDs.count == 1 else { continue }
            let peers = eligible.filter {
                $0.pid != socket.pid && endpoint($0.localAddress)?.host == socket.remoteHost &&
                endpoint($0.localAddress)?.port == socket.remotePort && $0.remoteHost == local.host && $0.remotePort == local.port
            }
            // Shared or inherited ownership is not a unique peer attribution.
            guard Set(peers.map(\.pid)).count == 1, let peer = peers.first, let second = owners[peer.pid] else { continue }
            let pair = [first, second].sorted()
            let edge = ProcessCommunicationRelation(firstIdentity: pair[0], secondIdentity: pair[1], transport: "tcp",
                endpoints: [socket.localAddress, peer.localAddress].sorted(), basis: "reciprocal established loopback endpoints in one scoped sample")
            result[edge.identity] = edge
        }
        return result.values.sorted { $0.identity < $1.identity }
    }

    static func unix(processes: [ProcessSnapshotRecord], records: [UnixSocketRecord]) -> [ProcessCommunicationRelation] {
        let owners = identities(processes)
        let eligible = records.filter { owners[$0.pid] == $0.processIdentity && $0.socketHandle != nil && $0.peerSocketHandle != nil }
        var result: [String: ProcessCommunicationRelation] = [:]
        for socket in eligible {
            guard let own = socket.socketHandle, let other = socket.peerSocketHandle,
                  own != 0, other != 0, let first = owners[socket.pid] else { continue }
            let ownPIDs = Set(eligible.filter { $0.socketHandle == own }.map(\.pid))
            let peers = eligible.filter { $0.socketHandle == other && $0.peerSocketHandle == own }
            guard ownPIDs.count == 1, Set(peers.map(\.pid)).count == 1,
                  let peer = peers.first, peer.pid != socket.pid, let second = owners[peer.pid] else { continue }
            let pair = [first, second].sorted()
            let edge = ProcessCommunicationRelation(firstIdentity: pair[0], secondIdentity: pair[1], transport: "unix",
                endpoints: [String(own, radix: 16), String(other, radix: 16)].sorted(),
                basis: "reciprocal libproc socket handles; owners validated by PID + birth identity")
            result[edge.identity] = edge
        }
        return result.values.sorted { $0.identity < $1.identity }
    }

    private static func identities(_ processes: [ProcessSnapshotRecord]) -> [String: String] {
        let grouped = Dictionary(grouping: processes.filter { $0.birthIdentity != nil }, by: \.pid)
        return grouped.compactMapValues { values in
            let keys = Set(values.map(ProcessObservationCoordinator.identity))
            return keys.count == 1 ? keys.first : nil
        }
    }
    private static func loopback(_ host: String) -> Bool { host == "::1" || host.split(separator: ".").count == 4 && host.hasPrefix("127.") }
    private static func endpoint(_ text: String) -> (host: String, port: Int)? {
        guard let colon = text.lastIndex(of: ":"), let port = Int(text[text.index(after: colon)...]) else { return nil }
        let host = String(text[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return (host, port)
    }
}
