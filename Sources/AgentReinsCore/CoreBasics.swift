import Foundation

// Pure-Foundation core of the Swift MCP (CoreBasics/CoreViews/CoreIntegrity/CoreSocketLedger).
// Everything mirrors tools/agentreins-mcp/evidence.py rule-for-rule so the packaged MCP and the Python
// MCP give the same answers. Crypto and the Keychain are injected (CryptoKit + the packaged
// AgentReinsKeychainHelper in main.swift), so the same files also build in the Linux parity harness
// (Tests/SwiftMCPParity).

// MARK: - JSON (must byte-match Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False))

public enum JSON {
    public static func string(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]),
              let s = String(data: data, encoding: .utf8) else { return "{}" }
        return s
    }

    public static func pretty(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value,
                                                     options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]),
              let s = String(data: data, encoding: .utf8) else { return "\(value)" }
        return s
    }

    public static func parse(_ data: Data?) -> Any? {
        guard let data else { return nil }
        return try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    public static func object(_ text: String) -> [String: Any]? { parse(Data(text.utf8)) as? [String: Any] }

    public static func objectAt(_ url: URL) -> [String: Any]? { parse(try? Data(contentsOf: url)) as? [String: Any] }
}

public func isNull(_ v: Any?) -> Bool { v == nil || v is NSNull }
public func str(_ v: Any?) -> String? {
    guard let v, !(v is NSNull) else { return nil }
    return (v as? String) ?? "\(v)"
}
public func intValue(_ v: Any?) -> Int? {
    // Note: no `is Bool` test: on Linux every JSON NSNumber also matches `is Bool` (and Python int(True) == 1).
    if let i = v as? Int { return i }
    if let d = v as? Double { return Int(d) }
    if let s = v as? String { return Int(s) }
    return nil
}
public func nn(_ v: Any?) -> Any {
    guard let v, !(v is NSNull) else { return NSNull() }
    return v
}

// MARK: - Crypto (injected)

public struct CryptoBox {
    public let hmacSHA256: (_ key: Data, _ message: Data) -> Data
    public let sha256: (_ data: Data) -> Data
    public let random: (_ count: Int) -> Data

    public init(hmacSHA256: @escaping (_ key: Data, _ message: Data) -> Data,
                sha256: @escaping (_ data: Data) -> Data,
                random: @escaping (_ count: Int) -> Data) {
        self.hmacSHA256 = hmacSHA256; self.sha256 = sha256; self.random = random
    }

    public func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    public func hmacHex(_ key: Data, _ text: String) -> String { hex(hmacSHA256(key, Data(text.utf8))) }
    public func hmacHex(_ key: Data, data: Data) -> String { hex(hmacSHA256(key, data)) }
    public func shaHex(_ text: String) -> String { hex(sha256(Data(text.utf8))) }
    public func shaHex(data: Data) -> String { hex(sha256(data)) }
    /// evidence.py entry_hmac(body, key)
    public func entryMac(_ body: [String: Any], _ key: Data) -> String { hmacHex(key, JSON.string(body)) }
}

/// hmac.compare_digest
public func constantTimeEqual(_ a: String, _ b: String) -> Bool {
    let x = Array(a.utf8), y = Array(b.utf8)
    var diff: UInt8 = x.count == y.count ? 0 : 1
    for i in 0..<min(x.count, y.count) { diff |= x[i] ^ y[i] }
    return diff == 0
}

// MARK: - Time

public enum Clock {
    public static func iso(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return f.string(from: date)
    }

    /// Python datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    public static func parse(_ value: Any?) -> Double? {
        guard var s = str(value), !s.isEmpty else { return nil }
        if s.hasSuffix("Z") { s = String(s.dropLast()) + "+00:00" }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone.current  // naive timestamps are local time in Python
        for format in ["yyyy-MM-dd'T'HH:mm:ss.SSSSSSxxx", "yyyy-MM-dd'T'HH:mm:ss.SSSxxx", "yyyy-MM-dd'T'HH:mm:ssxxx",
                       "yyyy-MM-dd'T'HH:mm:ss.SSSSSS", "yyyy-MM-dd'T'HH:mm:ss.SSS", "yyyy-MM-dd'T'HH:mm:ss"] {
            f.dateFormat = format
            if let d = f.date(from: s) { return d.timeIntervalSince1970 }
        }
        return nil
    }
}

public func round1(_ v: Double) -> Double { (v * 10).rounded() / 10 }

// MARK: - Regex

public enum Re {
    public static func first(_ pattern: String, _ text: String) -> NSTextCheckingResult? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        return re.firstMatch(in: text, range: NSRange(text.startIndex..., in: text))
    }

    public static func group(_ m: NSTextCheckingResult, _ i: Int, _ text: String) -> String? {
        guard i < m.numberOfRanges, let r = Range(m.range(at: i), in: text) else { return nil }
        return String(text[r])
    }
}

public enum Hex {
    public static func decode(_ hex: String) -> Data? {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(decoding: chars[i...i + 1], as: UTF8.self), radix: 16) else { return nil }
            out.append(b)
            i += 2
        }
        return out
    }
}
