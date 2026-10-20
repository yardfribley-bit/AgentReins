import Darwin
import Foundation

struct NetworkConnectionRecord: Sendable, Equatable {
    let pid: String
    let localAddress: String
    let remoteHost: String
    let remotePort: Int
    let route: String?
    let state: String?
    var isListener: Bool { state == "LISTEN" || remoteHost.isEmpty }

    init(pid: String, localAddress: String, remoteHost: String, remotePort: Int,
         route: String? = nil, state: String? = nil) {
        self.pid = pid
        self.localAddress = localAddress
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.route = route
        self.state = state
    }

    /// Local ephemeral ports change frequently for the same logical destination.
    /// Preserve them as evidence, but deduplicate on the owning process and remote endpoint.
    var identity: String {
        "\(pid)|\(Self.stableLocalEndpoint(localAddress))|\(remoteHost)|\(remotePort)|\(state ?? "unknown")"
    }

    /// Drop the ephemeral local port while keeping IPv6 bracketed hosts intact.
    static func stableLocalEndpoint(_ address: String) -> String {
        if address.hasPrefix("["), let close = address.firstIndex(of: "]") {
            return String(address[...close])
        }
        if let colon = address.lastIndex(of: ":"),
           address[address.index(after: colon)...].allSatisfy(\.isNumber) {
            return String(address[..<colon])
        }
        return address
    }
}

struct NetworkSnapshotResult: Sendable {
    let connections: [NetworkConnectionRecord]
    let failure: String?
}

protocol NetworkSnapshotting: Sendable {
    var sourceID: String { get }
    func snapshot(pids: [String]) -> [NetworkConnectionRecord]
    func capture(pids: [String]) -> NetworkSnapshotResult
}

extension NetworkSnapshotting {
    func capture(pids: [String]) -> NetworkSnapshotResult {
        NetworkSnapshotResult(connections: snapshot(pids: pids), failure: nil)
    }
}

struct LsofNetworkSnapshotProvider: NetworkSnapshotting {
    let sourceID = "lsof-network"

    func snapshot(pids: [String]) -> [NetworkConnectionRecord] {
        capture(pids: pids).connections
    }

    func capture(pids: [String]) -> NetworkSnapshotResult {
        let targets = Array(Set(pids.compactMap(Int.init))).sorted()
        guard !targets.isEmpty else { return .init(connections: [], failure: nil) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        // Intersect selectors: never enumerate unrelated machine traffic.
        process.arguments = ["-a", "-p", targets.map(String.init).joined(separator: ","),
                             "-iTCP", "-n", "-P", "-F", "pfnT"]
        let pipe = Pipe()
        // A file avoids stderr pipe backpressure. Never persist diagnostic contents.
        let errorURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        guard FileManager.default.createFile(atPath: errorURL.path, contents: nil,
                                            attributes: [.posixPermissions: 0o600]),
              let errorFile = try? FileHandle(forUpdating: errorURL) else {
            return .init(connections: [], failure: "Unable to prepare network collector diagnostics")
        }
        defer { try? errorFile.close(); try? FileManager.default.removeItem(at: errorURL) }
        process.standardOutput = pipe
        process.standardError = errorFile
        do { try process.run() } catch {
            return .init(connections: [], failure: "Unable to launch network snapshot collector")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let diagnosticSize = (try? errorFile.offset()) ?? 0
        return Self.classify(output: String(decoding: data, as: UTF8.self),
                             exitCode: process.terminationStatus, hasDiagnostics: diagnosticSize > 0)
    }

    static func classify(output: String, exitCode: Int32, hasDiagnostics: Bool) -> NetworkSnapshotResult {
        // lsof returns 1 when no selected sockets exist. Diagnostics or other
        // failures must not become a healthy empty snapshot or a socket closure.
        let clean = !hasDiagnostics && (exitCode == 0 || (exitCode == 1 && output.isEmpty))
        return .init(connections: parse(output),
                     failure: clean ? nil : "Network snapshot incomplete (collector exit \(exitCode)); coverage unknown")
    }

    static func parse(_ output: String) -> [NetworkConnectionRecord] {
        var currentPID: String?
        var result: [NetworkConnectionRecord] = []
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            if line.hasPrefix("p") {
                currentPID = String(line.dropFirst())
                continue
            }
            if line.hasPrefix("TST="), let last = result.last, last.pid == currentPID {
                result[result.count - 1] = NetworkConnectionRecord(pid: last.pid,
                    localAddress: last.localAddress, remoteHost: last.remoteHost,
                    remotePort: last.remotePort, route: last.route, state: String(line.dropFirst(4)))
                continue
            }
            guard line.hasPrefix("n"), let pid = currentPID else { continue }
            let connection = String(line.dropFirst()).components(separatedBy: " (").first ?? ""
            let endpoints = connection.components(separatedBy: "->")
            if endpoints.count == 2, let remote = endpoint(endpoints[1]), !remote.host.isEmpty {
                result.append(NetworkConnectionRecord(pid: pid, localAddress: endpoints[0],
                    remoteHost: remote.host, remotePort: remote.port))
            } else if endpoints.count == 1, endpoint(connection) != nil {
                result.append(NetworkConnectionRecord(pid: pid, localAddress: connection,
                    remoteHost: "", remotePort: 0))
            }
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

struct UnixSocketRecord: Sendable, Equatable {
    let pid: String
    let descriptor: String
    let endpoint: String
    var processIdentity: String? = nil
    var socketHandle: UInt64? = nil
    var peerSocketHandle: UInt64? = nil
}

struct LsofUnixSocketSnapshotProvider: Sendable {
    func snapshot(pids: [String]) -> [UnixSocketRecord] {
        let targets = Array(Set(pids.compactMap(Int.init))).sorted()
        guard !targets.isEmpty else { return [] }
        let births = Dictionary(uniqueKeysWithValues: targets.compactMap { target -> (Int, UInt64)? in
            guard let birth = LibprocProcessActivitySampler.birthIdentity(Int32(target)) else { return nil }
            return (target, birth)
        })
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-a", "-p", targets.map(String.init).joined(separator: ","), "-U", "-n", "-P", "-F", "pfn"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return [] }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let parsed = Self.parse(String(decoding: data, as: UTF8.self))
        // Query only descriptors already discovered for the target application.
        // Opaque handles establish ownership; paths alone never establish peers.
        var result: [UnixSocketRecord] = []
        for (pidText, rows) in Dictionary(grouping: parsed, by: \.pid) {
            guard let pid = Int32(pidText), let birth = births[Int(pid)], LibprocProcessActivitySampler.birthIdentity(pid) == birth else { continue }
            var sampled: [UnixSocketRecord] = []
            for var row in rows.prefix(256) {
                let numericFD = row.descriptor.prefix { $0.isNumber }
                if let fd = Int32(numericFD) {
                    var info = socket_fdinfo()
                    let size = MemoryLayout<socket_fdinfo>.size
                    let read = withUnsafeMutablePointer(to: &info) { proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, $0, Int32(size)) }
                    if read == size && info.psi.soi_kind == SOCKINFO_UN {
                        row.socketHandle = info.psi.soi_so
                        row.peerSocketHandle = info.psi.soi_proto.pri_un.unsi_conn_so
                    }
                }
                row.processIdentity = "\(pid):\(birth)"
                sampled.append(row)
            }
            guard LibprocProcessActivitySampler.birthIdentity(pid) == birth else { continue }
            result += sampled
        }
        return result
    }

    static func parse(_ output: String) -> [UnixSocketRecord] {
        var pid: String?
        var descriptor: String?
        var records: [UnixSocketRecord] = []
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            if line.hasPrefix("p") { pid = String(line.dropFirst()); descriptor = nil }
            else if line.hasPrefix("f") { descriptor = String(line.dropFirst()) }
            else if line.hasPrefix("n"), let pid, let descriptor {
                records.append(.init(pid: pid, descriptor: descriptor, endpoint: String(line.dropFirst())))
            }
        }
        return records
    }
}
