import Foundation

/// Installed app identity from Info.plist. Missing or unsafe values stay absent
/// so the About page can say 本机安装包 instead of a made-up build.
enum InstallIdentity {
    struct Label: Equatable {
        var version: String?
        var build: String?
    }

    static func label(version: String?, build: String?) -> Label? {
        let version = sanitize(version)
        let build = sanitize(build)
        guard version != nil || build != nil else { return nil }
        return Label(version: version, build: build)
    }

    static func label(from bundle: Bundle) -> Label? {
        label(
            version: bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
            build: bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        )
    }

    /// Document-start assignment. Values are charset-limited, so the script cannot close the string.
    static func pageScript(for label: Label?) -> String {
        guard let label else { return "window.agentreinsInstall=null;" }
        var fields: [String] = []
        if let version = label.version { fields.append("\"version\":\"\(version)\"") }
        if let build = label.build { fields.append("\"build\":\"\(build)\"") }
        guard !fields.isEmpty else { return "window.agentreinsInstall=null;" }
        return "window.agentreinsInstall={" + fields.joined(separator: ",") + "};"
    }

    static func pageScript(bundle: Bundle = .main) -> String {
        pageScript(for: label(from: bundle))
    }

    private static func sanitize(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...40).contains(value.count) else { return nil }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
        guard value.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        return value
    }
}
