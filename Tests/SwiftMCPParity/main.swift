import Foundation

// Linux/macOS parity harness for Sources/AgentReinsMCP/Core*.swift (test-only binary, not shipped).
// Driven by tools/agentreins-mcp/test_swift_parity.py, which builds the same fixture worlds with
// evidence.py and compares answers. The Keychain is a JSON file of hex values ({account: hex}),
// standing in for the packaged helper; it exists only in this harness.

final class FileKeychain: KeychainStore {
    let url: URL
    var items: [String: String]
    init(_ url: URL) {
        self.url = url
        items = (JSON.objectAt(url) as? [String: String]) ?? [:]
    }
    var backend: String { "memory" }
    var helperPath: String? { nil }
    func lookup(_ account: String) -> (String, Data?) {
        guard let hex = items[account] else { return ("missing", nil) }
        return ("found", Hex.decode(hex))
    }
    func set(_ account: String, _ value: Data) -> Bool {
        items[account] = value.map { String(format: "%02x", $0) }.joined()
        try? JSON.string(items).write(to: url, atomically: true, encoding: .utf8)
        return true
    }
}

let crypto = CryptoBox(hmacSHA256: PureSHA256.hmac, sha256: PureSHA256.hash, random: { n in
    var g = SystemRandomNumberGenerator()
    return Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &g) })
})

func selfCheck() {
    let abc = crypto.shaHex("abc")
    precondition(abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 vector")
    let mac = crypto.hmacHex(Data("key".utf8), "The quick brown fox jumps over the lazy dog")
    precondition(mac == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", "hmac vector")
}

var opts: [String: String] = [:]
let argv = Array(CommandLine.arguments.dropFirst())
let command = argv.first ?? ""
var i = 1
while i + 1 < argv.count {
    opts[String(argv[i].drop(while: { $0 == "-" }))] = argv[i + 1]
    i += 2
}
func url(_ k: String) -> URL { URL(fileURLWithPath: opts[k]!) }
func emit(_ v: Any) { print(JSON.string(v)) }

selfCheck()
switch command {
case "canon":
    emit(["canonical": JSON.string(JSON.parse(Data(opts["json"]!.utf8)) ?? [:])])
case "validate", "append":
    let integrity = Integrity(auditDir: url("audit"), integrityDir: url("integrity"), transport: url("transport"),
                              keychain: FileKeychain(url("keychain")), crypto: crypto)
    if command == "append" {
        let key = try! integrity.loadKey()
        let args = JSON.parse(Data((opts["args"] ?? "{}").utf8)) as? [String: Any] ?? [:]
        integrity.append(actor: opts["actor"]!, tool: opts["tool"]!, arguments: args, key: key)
        emit(["appended": true])
    } else {
        emit(integrity.validate())
    }
case "ledger":
    let key = opts["keyhex"].flatMap { Hex.decode($0) }
    emit(SocketLedgerCore.load(ledger: url("ledger"), seal: url("seal"), key: key, crypto: crypto,
                               agent: opts["agent"], since: opts["since"]))
case "verify-ledger":
    let key = opts["keyhex"].flatMap { Hex.decode($0) }
    let data = try? Data(contentsOf: url("ledger"))
    let side = JSON.parse(try? Data(contentsOf: url("side")))
    let seal = JSON.parse(try? Data(contentsOf: url("seal")))
    emit(SocketLedgerCore.verify(data, side, seal, key, crypto))
case "record":
    // destination fields + finding summaries for one record (same shape evidence.py loads)
    let rec = JSON.objectAt(url("record")) ?? [:]
    let audit = rec["securityAudit"] as? [String: Any] ?? [:]
    let findings = (audit["findings"] as? [Any] ?? []).compactMap { $0 as? [String: Any] }.map { Inb.summary($0, rec) }
    emit(["destination": Destination.fields(rec), "findings": findings])
case "helper-lookups":
    // Shipped HelperKeychain against a given helper executable: n lookups, each timed.
    let kc = HelperKeychain(helper: URL(fileURLWithPath: opts["helper"]!))
    let integrity = Integrity(auditDir: url("audit"), integrityDir: url("integrity"), transport: url("transport"),
                              keychain: kc, crypto: crypto)
    var out: [[String: Any]] = []
    for _ in 0..<(Int(opts["n"] ?? "1") ?? 1) {
        let t0 = Date()
        var reason: Any = NSNull()
        do { _ = try integrity.loadKey(create: false) } catch { reason = (error as? KeyUnavailable)?.reason ?? "\(error)" }
        out.append(["seconds": Date().timeIntervalSince(t0), "reason": reason])
    }
    emit(["calls": out, "keyFileExists": FileManager.default.fileExists(atPath: url("audit").appendingPathComponent("mcp-supervisor-hmac.key").path)])
case "redact-vectors":
    let rows = JSON.parse(try? Data(contentsOf: url("vectors"))) as? [[String: Any]] ?? []
    let (n, fails) = Redact.runVectors(rows) { FileHandle.standardError.write(Data(($0 + "\n").utf8)) }
    emit(["cases": n, "failures": fails])
default:
    FileHandle.standardError.write(Data("unknown command \(command)\n".utf8))
    exit(2)
}
