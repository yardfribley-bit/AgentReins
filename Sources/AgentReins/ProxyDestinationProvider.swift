import Foundation

struct ProxyDestinationRecord: Sendable, Equatable {
    let clientPort: Int
    let remoteHost: String
    let remotePort: Int
    let timestamp: Date
    let proxyName: String
}

protocol ProxyDestinationSnapshotting: Sendable {
    func snapshot() -> [ProxyDestinationRecord]
}

/// Reads only destination metadata from V2rayU's local access log. Request
/// paths, headers, payloads, and response bodies are never collected.
final class V2rayUProxyDestinationProvider: ProxyDestinationSnapshotting, @unchecked Sendable {
    let logURL: URL
    let maximumBytes: UInt64
    private let lock = NSLock()
    private var offset: UInt64?
    private var remainder = ""

    init(logURL: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".V2rayU/v2ray-core.log"), maximumBytes: UInt64 = 131_072) {
        self.logURL = logURL
        self.maximumBytes = maximumBytes
    }

    func snapshot() -> [ProxyDestinationRecord] {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = try? FileHandle(forReadingFrom: logURL) else { return [] }
        defer { try? handle.close() }
        guard let end = try? handle.seekToEnd() else { return [] }
        let isInitialRead = offset == nil || offset! > end
        let start = isInitialRead ? (end > maximumBytes ? end - maximumBytes : 0) : offset!
        guard start < end else { return [] }
        try? handle.seek(toOffset: start)
        guard let data = try? handle.readToEnd(),
              let text = String(data: data, encoding: .utf8) else { return [] }
        offset = end
        var aligned = remainder + text
        if isInitialRead, start > 0 {
            aligned = String(aligned.dropFirst(aligned.firstIndex(of: "\n").map {
            text.distance(from: text.startIndex, to: $0) + 1
            } ?? aligned.count))
        }
        guard let lastNewline = aligned.lastIndex(of: "\n") else {
            remainder = aligned
            return []
        }
        remainder = String(aligned[aligned.index(after: lastNewline)...])
        return Self.parse(String(aligned[...lastNewline]))
    }

    static func parse(_ text: String) -> [ProxyDestinationRecord] {
        let expression = try! NSRegularExpression(
            pattern: #"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? from (?:tcp:)?(?:127\.0\.0\.1|\[::1\]):(\d+) accepted //(?:tcp:)?([^:\s]+):(\d+)"#,
            options: [.anchorsMatchLines])
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        formatter.dateFormat = "yyyy/MM/dd HH:mm:ss"
        let range = NSRange(text.startIndex..., in: text)
        return expression.matches(in: text, range: range).compactMap { match in
            guard let timeRange = Range(match.range(at: 1), in: text),
                  let portRange = Range(match.range(at: 2), in: text),
                  let hostRange = Range(match.range(at: 3), in: text),
                  let remotePortRange = Range(match.range(at: 4), in: text),
                  let timestamp = formatter.date(from: String(text[timeRange])),
                  let clientPort = Int(text[portRange]),
                  let remotePort = Int(text[remotePortRange]) else { return nil }
            return ProxyDestinationRecord(clientPort: clientPort,
                                          remoteHost: String(text[hostRange]).lowercased(),
                                          remotePort: remotePort, timestamp: timestamp,
                                          proxyName: "V2rayU")
        }
    }
}
