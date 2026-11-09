import Foundation

/// Copies the PATH wrappers out of the app bundle into Application Support and
/// points `~/.agentreins/audit.sh` at that copy. The AgentSpec checkout is not
/// a runtime dependency.
enum TransportWrapperInstall {
    struct Result: Equatable {
        var copied: Bool
        var auditUpdated: Bool
        var shellHookAdded: Bool
    }

    static func installFromBundleIfNeeded() {
        guard let bundled = Bundle.main.resourceURL?.appendingPathComponent("transport-audit", isDirectory: true),
              FileManager.default.fileExists(atPath: bundled.appendingPathComponent("auto.py").path) else { return }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let destination = home
            .appendingPathComponent("Library/Application Support/AgentReins/transport-audit", isDirectory: true)
        _ = install(bundleRoot: bundled, destination: destination, home: home)
    }

    static func install(bundleRoot: URL, destination: URL, home: URL) -> Result {
        let sourceVersion = readVersion(bundleRoot)
        let installedVersion = readVersion(destination)
        var copied = false
        if sourceVersion.isEmpty || sourceVersion != installedVersion || !FileManager.default.fileExists(atPath: destination.appendingPathComponent("auto.py").path) {
            copied = (try? copyTree(from: bundleRoot, to: destination)) != nil
        }
        let binDir = destination.appendingPathComponent("bin").path
        let audit = home.appendingPathComponent(".agentreins/audit.sh")
        var auditUpdated = false
        if !FileManager.default.fileExists(atPath: audit.path) {
            let script = auditScript(binDir: binDir, home: home.path)
            try? FileManager.default.createDirectory(at: audit.deletingLastPathComponent(), withIntermediateDirectories: true)
            if (try? Data(script.utf8).write(to: audit, options: .atomic)) != nil {
                try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: audit.path)
                auditUpdated = true
            }
        } else if var text = try? String(contentsOf: audit, encoding: .utf8) {
            let updated = retarget(text, binDir: binDir)
            if updated != text {
                text = updated
                if (try? Data(text.utf8).write(to: audit, options: .atomic)) != nil {
                    auditUpdated = true
                }
            }
        }
        let hook = spliceHooks(home: home, auditPath: audit.path)
        return Result(copied: copied, auditUpdated: auditUpdated, shellHookAdded: hook)
    }

    static func retarget(_ text: String, binDir: String) -> String {
        guard let regex = try? NSRegularExpression(pattern: #"(/[^'\"\s]*?/transport-audit/bin)(/[A-Za-z0-9._+-]+)?"#) else {
            return text
        }
        let source = text as NSString
        let mutable = NSMutableString(string: text)
        let matches = regex.matches(in: text, range: NSRange(location: 0, length: source.length))
        for match in matches.reversed() {
            let dir = source.substring(with: match.range(at: 1))
            if dir == binDir { continue }
            let tool = match.range(at: 2).location != NSNotFound ? source.substring(with: match.range(at: 2)) : ""
            mutable.replaceCharacters(in: match.range, with: binDir + tool)
        }
        return mutable as String
    }

    static func auditScript(binDir: String, home: String) -> String {
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: binDir)) ?? []).filter { name in
            name != "auto.py" && !name.hasPrefix(".") && name.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "+" }
        }.sorted()
        let functions = names.map { tool in
            "\(tool)() { AGENTREINS_TRANSPORT_AGENT=\"$AGENTREINS_TRANSPORT_AGENT\" \(shellQuote(binDir + "/" + tool)) \"$@\"; }"
        }.joined(separator: "\n")
        let quotedBin = shellQuote(binDir)
        let ca = shellQuote((home as NSString).appendingPathComponent(".mitmproxy/mitmproxy-ca-cert.pem"))
        return """
        # AgentReins transport wrappers, installed from the app bundle.
        # A normal terminal does not enter this branch.
        if [ -z "${AGENTREINS_TRANSPORT_AGENT:-}" ]; then
          if [ -n "${CODEX_THREAD_ID:-}" ] && [ -n "${CODEX_CLI_PATH:-}" ]; then
            AGENTREINS_TRANSPORT_AGENT=Codex
          elif [ -n "${CODEBUDDY_SESSION_ID:-}" ] || [ -n "${CODEBUDDY_CONVERSATION_REQUEST_ID:-}" ]; then
            AGENTREINS_TRANSPORT_AGENT=WorkBuddy
          elif [ "${CURSOR_AGENT:-}" = "1" ]; then
            AGENTREINS_TRANSPORT_AGENT=Cursor
          fi
        fi
        if [ "$AGENTREINS_TRANSPORT_AGENT" != "WorkBuddy" ] && [ "$AGENTREINS_TRANSPORT_AGENT" != "Codex" ] && [ "$AGENTREINS_TRANSPORT_AGENT" != "Cursor" ]; then
          return 0 2>/dev/null || exit 0
        fi
        export AGENTREINS_TRANSPORT_AGENT
        if /usr/bin/nc -z -G 1 127.0.0.1 18891 >/dev/null 2>&1; then
          export HTTP_PROXY=http://127.0.0.1:18891 HTTPS_PROXY=http://127.0.0.1:18891 ALL_PROXY=http://127.0.0.1:18891
          export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" all_proxy="$ALL_PROXY"
          export NO_PROXY=localhost,127.0.0.1,::1 no_proxy="$NO_PROXY"
          if [ -f \(ca) ]; then
            export CURL_CA_BUNDLE=\(ca) SSL_CERT_FILE="$CURL_CA_BUNDLE" GIT_SSL_CAINFO="$CURL_CA_BUNDLE"
            export NODE_EXTRA_CA_CERTS="$CURL_CA_BUNDLE" REQUESTS_CA_BUNDLE="$CURL_CA_BUNDLE"
          fi
          if [ -z "${GIT_CONFIG_COUNT:-}" ]; then
            export GIT_CONFIG_COUNT=2
            export GIT_CONFIG_KEY_0=http.proxy GIT_CONFIG_VALUE_0="$HTTP_PROXY"
            export GIT_CONFIG_KEY_1=http.sslCAInfo GIT_CONFIG_VALUE_1="${CURL_CA_BUNDLE:-}"
          fi
        fi
        case ":$PATH:" in
          *:\(quotedBin):*) ;;
          *) export PATH=\(quotedBin):$PATH ;;
        esac
        \(functions)

        """
    }

    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func readVersion(_ root: URL) -> String {
        let url = root.appendingPathComponent("VERSION")
        return ((try? String(contentsOf: url, encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func copyTree(from source: URL, to destination: URL) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: destination.path) {
            try fm.removeItem(at: destination)
        }
        try fm.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        try copyContents(from: source, to: destination)
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: destination.path)
        let auto = destination.appendingPathComponent("auto.py")
        if fm.fileExists(atPath: auto.path) {
            try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: auto.path)
        }
    }

    private static func copyContents(from source: URL, to destination: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: destination, withIntermediateDirectories: true)
        let items = try fm.contentsOfDirectory(at: source, includingPropertiesForKeys: [.isSymbolicLinkKey, .isDirectoryKey], options: [.skipsHiddenFiles])
        for item in items {
            let dest = destination.appendingPathComponent(item.lastPathComponent)
            let values = try item.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
            if values.isSymbolicLink == true {
                let target = try fm.destinationOfSymbolicLink(atPath: item.path)
                try fm.createSymbolicLink(atPath: dest.path, withDestinationPath: target)
            } else if values.isDirectory == true {
                try copyContents(from: item, to: dest)
            } else {
                try fm.copyItem(at: item, to: dest)
            }
        }
    }

    private static func spliceHooks(home: URL, auditPath: String) -> Bool {
        var added = false
        for name in [".zshenv", ".bashrc", ".bash_profile"] {
            if spliceHook(into: home.appendingPathComponent(name), auditPath: auditPath) {
                added = true
            }
        }
        return added
    }

    private static func spliceHook(into path: URL, auditPath: String) -> Bool {
        let start = "# BEGIN AgentReins transport\n"
        let end = "# END AgentReins transport\n"
        let oldStart = "# BEGIN AgentReins Codex transport\n"
        let oldEnd = "# END AgentReins Codex transport\n"
        let hook = start + "[ -f \(shellQuote(auditPath)) ] && . \(shellQuote(auditPath))\n" + end
        var original = (try? String(contentsOf: path, encoding: .utf8)) ?? ""
        if original.contains(start) && original.contains(end) { return false }
        if let a = original.range(of: oldStart), let b = original.range(of: oldEnd) {
            original.removeSubrange(a.lowerBound..<b.upperBound)
        }
        let existed = FileManager.default.fileExists(atPath: path.path)
        if existed && !original.isEmpty {
            let backup = path.appendingPathExtension("agentreins-backup")
            if !FileManager.default.fileExists(atPath: backup.path) {
                try? original.write(to: backup, atomically: true, encoding: .utf8)
            }
        }
        let body = original.trimmingCharacters(in: .whitespacesAndNewlines)
        let next = (body.isEmpty ? "" : body + "\n\n") + hook
        do {
            try next.write(to: path, atomically: true, encoding: .utf8)
            return true
        } catch {
            return false
        }
    }
}
