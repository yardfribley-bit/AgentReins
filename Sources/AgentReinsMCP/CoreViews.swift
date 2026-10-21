import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

// MARK: - Destination (evidence.py destination_fields; one definition for get_execution and list_network)

enum Destination {
    static let loopbackNames: Set<String> = ["localhost", "::1", "[::1]"]
    static let proxyValueOptions: Set<String> = ["-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5",
        "--socks5-hostname", "--proxy1.0", "--connect-to", "--resolve", "-e", "--referer", "-H", "--header"]
    static let evidence: [String: String] = [
        "proxy_observed": "Observed", "connection_observed": "Observed",
        "argv_parsed": "Inferred", "transport_peer_only": "Unknown",
    ]

    static func isLoopback(_ host: String?) -> Bool {
        let h = (host ?? "").trimmingCharacters(in: .whitespaces).lowercased()
        return loopbackNames.contains(h) || h.hasPrefix("127.")
    }

    static func urlHost(_ s: String) -> String? {
        guard let comps = URLComponents(string: s), let host = comps.host, !host.isEmpty else { return nil }
        return host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
    }

    static func argvDestination(_ args: [Any]) -> String? {
        var skip = false
        for arg in args {
            let s = str(arg) ?? ""
            if skip { skip = false; continue }
            if proxyValueOptions.contains(s) { skip = true; continue }
            if s.hasPrefix("-") { continue }
            if s.contains("://") {
                if let host = urlHost(s), !isLoopback(host) { return host }
                continue
            }
            if let m = Re.first(#"^(?:[^@\s/]+@)([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::|$)"#, s), let h = Re.group(m, 1, s) {
                return h.lowercased()
            }
        }
        return nil
    }

    static func hostOf(_ record: [String: Any]) -> String? {
        for case let conn as [String: Any] in (record["connections"] as? [Any] ?? []) {
            if let detail = conn["detail"] as? [Any], let first = detail.first {
                var token = String((str(first) ?? "").split(separator: "/", omittingEmptySubsequences: false).first ?? "")
                if token.contains(":") && !token.hasPrefix("["), let r = token.range(of: ":", options: .backwards) {
                    token = String(token[..<r.lowerBound])
                }
                return token.lowercased()
            }
        }
        for arg in record["args"] as? [Any] ?? [] {
            let s = str(arg) ?? ""
            if s.contains("://"), let h = urlHost(s) { return h }
        }
        return nil
    }

    static func real(_ record: [String: Any]) -> (String?, String?, String?) {
        var peer: String?, real: String?, source: String?
        var proxied = false
        for case let conn as [String: Any] in (record["connections"] as? [Any] ?? []) {
            let kind = str(conn["kind"])
            if str(conn["source"]) == "argv" { continue }  // auto.py pseudo-connection for untraced tools
            if let kind, !["attempt", "connected", "proxyTunnel", "reuse"].contains(kind) { continue }
            for detail in conn["detail"] as? [Any] ?? [] {
                let d = str(detail) ?? ""
                var hostport = String(d.split(separator: " ").first ?? "")
                while hostport.hasSuffix(".") { hostport.removeLast() }
                if Re.first("[.:]", hostport) == nil && hostport.lowercased() != "localhost" { break }
                var host = hostport
                if hostport.filter({ $0 == ":" }).count == 1, let r = hostport.range(of: ":", options: .backwards) {
                    host = String(hostport[..<r.lowerBound])
                }
                host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
                if isLoopback(host) {
                    if peer == nil {
                        if let m = Re.first(#"port (\d+)"#, d), let port = Re.group(m, 1, d), !hostport.contains(":") {
                            peer = "\(host):\(port)"
                        } else {
                            peer = hostport.isEmpty ? host : hostport
                        }
                    }
                    proxied = true
                } else if !host.isEmpty && real == nil {
                    real = host
                    source = (kind == "proxyTunnel" || proxied) ? "proxy_observed" : "connection_observed"
                }
                break  // only the first detail item names the endpoint
            }
        }
        if real != nil && peer != nil { source = "proxy_observed" }
        if real == nil {
            let audit = record["securityAudit"] as? [String: Any] ?? [:]
            var argvConn: String?
            for case let c as [String: Any] in (record["connections"] as? [Any] ?? []) where str(c["source"]) == "argv" {
                if let d = (c["detail"] as? [Any])?.first {
                    argvConn = String((str(d) ?? "").split(separator: " ").first ?? "")
                    break
                }
            }
            let cand = str(audit["destinationHost"]) ?? str(record["destinationHost"])
                ?? argvDestination(record["args"] as? [Any] ?? []) ?? argvConn
            if let cand, !cand.isEmpty, !isLoopback(cand) {
                real = String(cand.split(separator: ":", omittingEmptySubsequences: false).first ?? "").lowercased()
                source = "argv_parsed"
            }
        }
        if peer != nil && real == nil { source = "transport_peer_only" }
        return (real, peer, source)
    }

    static func fields(_ record: [String: Any]) -> [String: Any] {
        let (real, peer, source) = Self.real(record)
        var host = real ?? (source == "transport_peer_only" ? nil : hostOf(record))
        if let h = host, isLoopback(h), peer != nil { host = nil }
        return [
            "destination": nn(host), "realDestination": nn(real), "transportPeer": nn(peer),
            "destinationSource": nn(source), "destinationEvidence": evidence[source ?? ""] ?? "Unknown",
            "viaProxy": source == nil ? NSNull() : (peer != nil) as Any,
        ]
    }
}

// MARK: - INB (instruction-override-inbound) match context

enum Inb {
    static let ruleIds: Set<String> = ["INB", "instruction-override-inbound"]
    static let pattern = #"(?i)(?:ignore (?:all |the )?(?:previous|prior|system) instructions|忽略(?:之前|上述|系统)(?:的)?(?:指令|规则))"#

    static func normalize(_ rule: Any?) -> Any {
        if let r = rule as? String, ruleIds.contains(r) { return "INB" }
        return nn(rule)
    }

    static func isInb(_ rule: Any?) -> Bool { (normalize(rule) as? String) == "INB" }

    /// Python slices by code point; count unicode scalars so the window matches.
    static func window(_ text: String, _ m: NSTextCheckingResult, _ w: Int = 80) -> String {
        let ns = text as NSString
        let scalars = Array(text.unicodeScalars)
        let start = ns.substring(to: m.range.location).unicodeScalars.count
        let end = start + ns.substring(with: m.range).unicodeScalars.count
        var out = String.UnicodeScalarView()
        out.append(contentsOf: scalars[max(0, start - w)..<min(scalars.count, end + w)])
        return String(out)
    }

    static func storedContext(_ finding: [String: Any], _ w: Int = 80) -> String? {
        var raw = str(finding["matchContext"])
        if raw?.isEmpty ?? true { raw = str(finding["context"]) }
        guard let text = raw, !text.isEmpty else { return nil }
        if let m = Re.first(pattern, text) {
            let hitLen = (text as NSString).substring(with: m.range).unicodeScalars.count
            if text.unicodeScalars.count > 2 * w + hitLen { return Redact.text(window(text, m, w)) }
        }
        return Redact.text(text)
    }

    static func rescan(_ record: [String: Any], _ w: Int = 80, maxBytes: Int = 2_000_000) -> String? {
        guard let path = str(record["evidencePath"]) else { return nil }
        let run = URL(fileURLWithPath: path).deletingLastPathComponent().resolvingSymlinksInPath().standardizedFileURL
        var budget = maxBytes
        for case let block as [String: Any] in (record["blocks"] as? [Any] ?? []) {
            guard str(block["direction"]) == "receive", let rel = str(block["bodyFile"]), !rel.isEmpty else { continue }
            let body = run.appendingPathComponent(rel).resolvingSymlinksInPath().standardizedFileURL
            guard body.path.hasPrefix(run.path + "/"), let data = try? Data(contentsOf: body) else { continue }
            let text = String(decoding: data.prefix(budget), as: UTF8.self)
            budget -= text.unicodeScalars.count
            if let m = Re.first(pattern, text) { return Redact.text(window(text, m, w)) }
            if budget <= 0 { break }
        }
        return nil
    }

    /// evidence.py credential_finding_summary
    static func summary(_ finding: [String: Any], _ record: [String: Any]?) -> [String: Any] {
        let rule = finding["rule"]
        var out: [String: Any] = [
            "rule": nn(rule), "direction": nn(finding["direction"]), "severity": nn(finding["severity"]),
            "count": nn(finding["count"]), "characterOffset": nn(finding["characterOffset"]),
            "label": isNull(finding["label"]) ? nn(rule) : nn(finding["label"]), "matchedText": NSNull(),
            "ruleId": nn(rule), "note": "原始匹配文本不通过 MCP 返回", "confidence": "Observed",
        ]
        if isInb(rule) {
            var snippet = storedContext(finding)
            var source: String? = snippet != nil ? "stored_match_context" : nil
            if snippet == nil, let record {
                snippet = rescan(record)
                source = snippet != nil ? "rescan_stored_response_body" : nil
            }
            out["matchContextRedacted"] = nn(snippet)
            out["matchContextSource"] = nn(source)
            out["note"] = snippet != nil
                ? "MCP 仅返回脱敏上下文片段（命中处前后约 80 字符）；完整内容见本机详情页。"
                : "这次采集没有保存命中上下文，存下来的返回正文里也没有再次命中（可能是压缩或分块传输）；只有规则和字符位置。"
        }
        return out
    }

    static func findingFor(_ record: [String: Any]?) -> [String: Any]? {
        let audit = record?["securityAudit"] as? [String: Any] ?? [:]
        for case let f as [String: Any] in (audit["findings"] as? [Any] ?? []) where isInb(f["rule"]) { return f }
        return nil
    }
}

// MARK: - Keychain (through the packaged helper: one key for Python MCP, sampler and Swift MCP)

protocol KeychainStore: AnyObject {
    /// ("found", data) | ("missing", nil) | ("error", nil) | ("no_helper", nil)
    func lookup(_ account: String) -> (String, Data?)
    func set(_ account: String, _ value: Data) -> Bool
    var backend: String { get }
    var helperPath: String? { get }
}

/// Per-request cache in front of the helper (each lookup is a process launch).
final class CachedKeychain: KeychainStore {
    let inner: KeychainStore
    private var cache: [String: (String, Data?)] = [:]
    init(_ inner: KeychainStore) { self.inner = inner }
    func lookup(_ account: String) -> (String, Data?) {
        if let hit = cache[account] { return hit }
        let v = inner.lookup(account)
        cache[account] = v
        return v
    }
    func set(_ account: String, _ value: Data) -> Bool {
        let ok = inner.set(account, value)
        cache[account] = nil
        return ok
    }
    var backend: String { inner.backend }
    var helperPath: String? { inner.helperPath }
}

final class HelperKeychain: KeychainStore {
    let helper: URL?
    init(helper: URL?) { self.helper = helper }
    var backend: String { "security" }
    var helperPath: String? { helper?.path }

    /// Contents/MacOS/AgentReinsKeychainHelper next to this executable.
    static func packaged() -> URL? {
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let url = exe.deletingLastPathComponent().appendingPathComponent("AgentReinsKeychainHelper")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    private func run(_ args: [String], stdin: Data? = nil) -> (Int32, Data)? {
        guard let helper else { return nil }
        let p = Process()
        p.executableURL = helper
        p.arguments = args
        let out = Pipe(), inp = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.standardInput = inp
        do { try p.run() } catch { return (-1, Data()) }
        if let stdin { inp.fileHandleForWriting.write(stdin) }
        try? inp.fileHandleForWriting.close()
        // Same 15 s limit as evidence.py: a Keychain prompt nobody answers must not hang the MCP.
        // A timeout is reported as "error" (never as "missing", which would mint a new key).
        let deadline = Date().addingTimeInterval(15)
        while p.isRunning && Date() < deadline { usleep(20_000) }
        if p.isRunning {
            p.terminate()
            return (-2, Data())
        }
        return (p.terminationStatus, out.fileHandleForReading.readDataToEndOfFile())
    }

    func lookup(_ account: String) -> (String, Data?) {
        guard let (code, data) = run(["get", account]) else { return ("no_helper", nil) }
        if code == 3 { return ("missing", nil) }
        let raw = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard code == 0, !raw.isEmpty else { return ("error", nil) }
        var bytes = Hex.decode(raw) ?? Data(raw.utf8)
        // Legacy `security -A -w <hex>` stored ASCII hex digits as the secret.
        if bytes.count == 64, let s = String(data: bytes, encoding: .ascii),
           s.allSatisfy({ "0123456789abcdef".contains($0) }), let inner = Hex.decode(s) {
            bytes = inner
        }
        return ("found", bytes)
    }

    func set(_ account: String, _ value: Data) -> Bool {
        let hex = value.map { String(format: "%02x", $0) }.joined()
        guard let (code, _) = run(["set", account], stdin: Data(hex.utf8)) else { return false }
        return code == 0
    }
}

struct KeyUnavailable: Error { let reason: String }
