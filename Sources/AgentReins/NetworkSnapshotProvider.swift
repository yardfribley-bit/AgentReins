import Foundation

struct NetworkConnectionRecord: Sendable, Equatable {
    let pid: String
    let localAddress: String
    let remoteHost: String
    let remotePort: Int
    let route: String?

    init(pid: String, localAddress: String, remoteHost: String, remotePort: Int,
         route: String? = nil) {
        self.pid = pid
        self.localAddress = localAddress
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.route = route
    }

    /// Local ephemeral ports change frequently for the same logical destination.
    /// Preserve them as evidence, but deduplicate on the owning process and remote endpoint.
    var identity: String { "\(pid)|\(remoteHost)|\(remotePort)" }
}

protocol NetworkSnapshotting: Sendable {
    var sourceID: String { get }
    func snapshot(pids: [String]) -> [NetworkConnectionRecord]
}

struct LsofNetworkSnapshotProvider: NetworkSnapshotting {
    let sourceID = "lsof-network"

    func snapshot(pids: [String]) -> [NetworkConnectionRecord] {
        let targets = Array(Set(pids.compactMap(Int.init))).sorted()
        guard !targets.isEmpty else { return [] }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        // `-a` intersects the PID and TCP selectors. Without it lsof scans all
        // machine sockets and filters later, causing a visible CPU spike.
        process.arguments = ["-a", "-p", targets.map(String.init).joined(separator: ","),
                             "-iTCP", "-n", "-P", "-F", "pn"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do { try process.run() } catch { return [] }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard let output = String(data: data, encoding: .utf8) else { return [] }
        return Self.parse(output)
    }

    static func parse(_ output: String) -> [NetworkConnectionRecord] {
        var currentPID: String?
        var result: [NetworkConnectionRecord] = []
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            if line.hasPrefix("p") {
                currentPID = String(line.dropFirst())
                continue
            }
            guard line.hasPrefix("n"), let pid = currentPID else { continue }
            let connection = String(line.dropFirst()).components(separatedBy: " (").first ?? ""
            let endpoints = connection.components(separatedBy: "->")
            guard endpoints.count == 2,
                  let remote = endpoint(endpoints[1]), !remote.host.isEmpty else { continue }
            result.append(NetworkConnectionRecord(pid: pid, localAddress: endpoints[0],
                                                  remoteHost: remote.host, remotePort: remote.port))
        }
        return result
    }

    private static func endpoint(_ value: String) -> (host: String, port: Int)? {
        guard let separator = value.lastIndex(of: ":"),
              let port = Int(value[value.index(after: separator)...]) else { return nil }
        var host = String(value[..<separator])
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        return (host, port)
    }
}
