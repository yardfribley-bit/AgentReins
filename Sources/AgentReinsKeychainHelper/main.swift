import Foundation
import Security

/// Trusted Keychain helper for MCP integrity keys (en_26fd4180).
/// Shipped as AgentReins.app/Contents/MacOS/AgentReinsKeychainHelper (SwiftPM target
/// AgentReinsKeychainHelper). The Python MCP, the socket sampler and the Swift MCP all read
/// the integrity key through this one binary, so there is exactly one key.
/// Uses Security.framework (no `security -A` CLI). ACL is limited to this
/// helper binary's code signature / path — other apps must prompt or fail.

let service = "com.agentreins.mcp-integrity"

func usage() -> Never {
    fputs("usage: keychain_helper get|set|delete <account>  (set reads hex secret from stdin)\n", stderr)
    exit(2)
}

guard CommandLine.arguments.count >= 3 else { usage() }
let op = CommandLine.arguments[1]
let account = CommandLine.arguments[2]

func access() -> SecAccess? {
    // Trusted apps: this helper only. Expanding requires re-storing the item.
    var trusted: [SecTrustedApplication] = []
    var selfApp: SecTrustedApplication?
    let selfPath = CommandLine.arguments[0]
    if SecTrustedApplicationCreateFromPath(selfPath, &selfApp) == errSecSuccess, let selfApp {
        trusted.append(selfApp)
    }
    // Prefer signed app bundle when present next to Resources.
    let selfDir = URL(fileURLWithPath: selfPath).deletingLastPathComponent()
    let appCandidates = [
        // Packaged: helper and app live side by side in Contents/MacOS.
        selfDir.appendingPathComponent("AgentReins").path,
        "/Applications/AgentReins.app/Contents/MacOS/AgentReins",
        "/Applications/AgentReins.app/Contents/MacOS/AgentReinsKeychainHelper",
    ].filter { $0 != selfPath }
    for path in appCandidates {
        var app: SecTrustedApplication?
        if FileManager.default.isExecutableFile(atPath: path),
           SecTrustedApplicationCreateFromPath(path, &app) == errSecSuccess,
           let app {
            trusted.append(app)
        }
    }
    var accessRef: SecAccess?
    let status = SecAccessCreate("AgentReins MCP integrity" as CFString, trusted as CFArray, &accessRef)
    guard status == errSecSuccess else { return nil }
    return accessRef
}

switch op {
case "delete":
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound { exit(0) }
    fputs("delete failed: \(status)\n", stderr)
    exit(1)

case "get":
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var out: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &out)
    guard status == errSecSuccess, let data = out as? Data else {
        exit(status == errSecItemNotFound ? 3 : 1)
    }
    FileHandle.standardOutput.write(Data(data.map { String(format: "%02x", $0) }.joined().utf8))
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(0)

case "set":
    let hex = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard !hex.isEmpty, hex.count % 2 == 0,
          let secret = Data(hexEncoded: hex) else {
        fputs("set requires even-length hex on stdin\n", stderr)
        exit(2)
    }
    let del: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    SecItemDelete(del as CFDictionary)
    var attrs: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: secret,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    if let access = access() {
        attrs[kSecAttrAccess as String] = access
    }
    let status = SecItemAdd(attrs as CFDictionary, nil)
    guard status == errSecSuccess else {
        fputs("set failed: \(status)\n", stderr)
        exit(1)
    }
    exit(0)

default:
    usage()
}

private extension Data {
    init?(hexEncoded hex: String) {
        let chars = Array(hex)
        guard chars.count % 2 == 0 else { return nil }
        var data = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            let byte = String(chars[i...i+1])
            guard let b = UInt8(byte, radix: 16) else { return nil }
            data.append(b)
            i += 2
        }
        self = data
    }
}
