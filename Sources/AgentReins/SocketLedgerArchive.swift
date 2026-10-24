import AgentReinsCore
import CryptoKit
import Foundation
import Security

/// Read-only bridge from tools/socket-sampler's ledger to the 首页 / 外网访问 pages.
/// The sampler owns collection. This goes through the same AgentReinsCore code as the packaged MCP
/// (seal/sidecar verification, freshness judged now, tampered rows downgraded to Unknown), so the page
/// never says "sampling" or "signed" unless that is what the ledger proves.
enum SocketLedgerArchive {
    static var support: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/AgentGuard")
    }
    static var integrityDir: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/AgentReinsIntegrity")
    }
    static var defaultURL: URL { support.appendingPathComponent("socket-ledger.json") }
    static var url: URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_SOCKET_LEDGER"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return defaultURL
    }

    static let crypto = CryptoBox(
        hmacSHA256: { key, message in Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))) },
        sha256: { Data(SHA256.hash(data: $0)) },
        random: { count in
            var bytes = [UInt8](repeating: 0, count: count)
            precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess, "SecRandomCopyBytes failed")
            return Data(bytes)
        })

    /// The packaged AgentReinsKeychainHelper (Contents/MacOS, next to the app executable).
    static var helper: HelperKeychain { HelperKeychain(helper: HelperKeychain.packaged()) }

    static func pagePayload(limit: Int = 300) -> [String: Any] {
        let keychain = helper
        let integrity = Integrity(auditDir: support, integrityDir: integrityDir,
                                  transport: support.appendingPathComponent("transport-audit"),
                                  keychain: CachedKeychain(keychain), crypto: crypto)
        let seal = SocketLedgerCore.sealPath(ledger: url, defaultLedger: defaultURL, integrityDir: integrityDir)
        return SocketLedgerCore.page(integrity: integrity, keychainStatus: { keychain.status() },
                                     ledger: url, seal: seal, limit: limit)
    }
}
