import AppKit
import Foundation
import SwiftUI

enum BrowserProtectionInstaller {
    static let extensionID = "hcmoeaheokpfbbggdmkdeaiokakiampk"
    static let stagedExtensionURL = FileManager.default.urls(for: .applicationSupportDirectory,
        in: .userDomainMask)[0].appendingPathComponent("AgentReins/BrowserExtension")

    /// Chrome must never point inside a replaceable `.app` bundle. The app
    /// owns a stable staged copy and refreshes it whenever AgentReins launches.
    static func installBundledAssets() {
        stageExtension()
        installNativeHostManifests()
    }

    static func stageExtension() {
        guard let bundled = Bundle.main.resourceURL?.appendingPathComponent("BrowserExtension"),
              FileManager.default.fileExists(atPath: bundled.path) else { return }
        let fm = FileManager.default
        try? fm.createDirectory(at: stagedExtensionURL, withIntermediateDirectories: true)
        let names = ["manifest.json", "service-worker.js", "web-agent-content.js"]
        for name in names {
            let source = bundled.appendingPathComponent(name)
            let destination = stagedExtensionURL.appendingPathComponent(name)
            guard fm.fileExists(atPath: source.path) else { continue }
            try? fm.removeItem(at: destination)
            try? fm.copyItem(at: source, to: destination)
        }
        try? fm.removeItem(at: stagedExtensionURL.appendingPathComponent("grok-content.js"))
    }

    static func installNativeHostManifests() {
        guard let executable = Bundle.main.executableURL?.deletingLastPathComponent()
                .appendingPathComponent("AgentReinsNativeHost"),
              FileManager.default.isExecutableFile(atPath: executable.path) else { return }
        let body: [String: Any] = [
            "name": "com.agentspec.agentreins.web",
            "description": "AgentReins local Web AI evidence bridge",
            "path": executable.path,
            "type": "stdio",
            "allowed_origins": ["chrome-extension://\(extensionID)/"]
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.prettyPrinted, .sortedKeys]) else { return }
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        for relative in ["Google/Chrome/NativeMessagingHosts", "Microsoft Edge/NativeMessagingHosts"] {
            let directory = support.appendingPathComponent(relative)
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try? data.write(to: directory.appendingPathComponent("com.agentspec.agentreins.web.json"), options: .atomic)
        }
    }
}

struct BrowserProtectionView: View {
    let extensionConnected: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var status = BrowserProtectionStatus.inspect()

    private let cyan = Color(red: 48/255, green: 211/255, blue: 229/255)
    private let green = Color(red: 57/255, green: 214/255, blue: 117/255)
    private let amber = Color(red: 255/255, green: 177/255, blue: 45/255)
    private let panel = Color(red: 8/255, green: 27/255, blue: 45/255)
    private let raised = Color(red: 13/255, green: 36/255, blue: 59/255)
    private let border = Color(red: 27/255, green: 66/255, blue: 96/255)

    private var protected: Bool { extensionConnected && status.hasAllHosts && status.nativeHostInstalled }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: protected ? "checkmark.shield.fill" : "shield.lefthalf.filled")
                    .font(.system(size: 28)).foregroundStyle(protected ? green : cyan)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Browser Protection").font(.system(size: 22, weight: .bold))
                    Text("See what Web AI receives, returns, searches, and exposes.")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer()
                Text(protected ? "PROTECTED" : status.extensionInstalled ? "ACTION REQUIRED" : "NOT INSTALLED")
                    .font(.system(size: 9, weight: .bold)).foregroundStyle(protected ? green : amber)
                    .padding(.horizontal, 10).padding(.vertical, 5)
                    .background((protected ? green : amber).opacity(0.12), in: Capsule())
                Button("Done") { dismiss() }.buttonStyle(.bordered)
            }.padding(20).background(raised)

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 10) {
                        statusCell("CHROME", status.chromeInstalled, status.chromeInstalled ? "Detected" : "Not found")
                        statusCell("EXTENSION", status.extensionInstalled,
                                   status.extensionInstalled ? "Profile \(status.profileName ?? "detected")" : "Install required")
                        statusCell("LOCAL BRIDGE", status.nativeHostInstalled,
                                   status.nativeHostInstalled ? "Ready" : "Repair required")
                        statusCell("LIVE LINK", extensionConnected,
                                   extensionConnected ? "Heartbeat received" : "Waiting for AI tab")
                    }

                    section("SUPPORTED WEB AI", "Permission is limited to these four AI websites.") {
                        HStack(spacing: 8) {
                            site("Gemini", "gemini.google.com")
                            site("ChatGPT", "chatgpt.com")
                            site("Claude", "claude.ai")
                            site("Grok", "grok.com")
                        }
                    }

                    if !protected {
                        section("FINISH SETUP", setupExplanation) {
                            VStack(alignment: .leading, spacing: 12) {
                                setupRow(1, "Open Chrome extensions", "Enable Developer mode in the top-right corner.") {
                                    open("chrome://extensions/?id=hcmoeaheokpfbbggdmkdeaiokakiampk")
                                }
                                setupRow(2, status.extensionInstalled ? "Reload AgentReins" : "Load unpacked extension",
                                         status.extensionInstalled
                                            ? "Click Reload on AgentReins Web AI Monitor to grant the new site permissions."
                                            : "Choose the BrowserExtension folder AgentReins reveals in Finder.") {
                                    revealExtension(); copyExtensionPath()
                                }
                                setupRow(3, "Verify the live connection", "Open Gemini and send a test prompt. AgentReins should receive a heartbeat and turn evidence.") {
                                    open("https://gemini.google.com/app")
                                }
                            }
                        }
                    } else {
                        section("PROTECTION ACTIVE", "Browser evidence remains on this Mac and is linked to the corresponding Web AI turn.") {
                            Label("Prompts, rendered responses, visible reasoning/search progress, URLs, timestamps, and upload hashes are being observed.",
                                  systemImage: "checkmark.circle.fill")
                                .font(.system(size: 11)).foregroundStyle(green)
                        }
                    }

                    section("EVIDENCE BOUNDARY", "AgentReins labels what it can and cannot prove.") {
                        VStack(alignment: .leading, spacing: 7) {
                            boundary("Confirmed", "Content rendered in the AI tab and delivered through the authenticated local bridge.", green)
                            boundary("Not available", "Server-side hidden reasoning or encrypted payloads never rendered by the website.", amber)
                            boundary("Local only", "Captured evidence is written to the local AgentReins evidence store.", cyan)
                        }
                    }
                }.padding(20)
            }
        }
        .frame(width: 920, height: 680)
        .background(panel).environment(\.colorScheme, .dark)
        .onAppear { status = BrowserProtectionStatus.inspect() }
    }

    private var setupExplanation: String {
        if status.extensionInstalled && !status.hasAllHosts { return "The existing Grok-only extension must be reloaded once to approve Gemini, ChatGPT, and Claude." }
        return "Chrome requires one explicit user action before a local extension can monitor AI tabs."
    }

    private func statusCell(_ title: String, _ okay: Bool, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 8, weight: .bold)).foregroundStyle(.secondary)
            Label(detail, systemImage: okay ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                .font(.system(size: 10, weight: .semibold)).foregroundStyle(okay ? green : amber).lineLimit(1)
        }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(raised, in: RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(border))
    }

    private func section<Content: View>(_ title: String, _ subtitle: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 11) {
            Text(title).font(.system(size: 10, weight: .bold)).foregroundStyle(cyan)
            Text(subtitle).font(.system(size: 10)).foregroundStyle(.secondary)
            content()
        }.padding(15).frame(maxWidth: .infinity, alignment: .leading)
            .background(raised.opacity(0.7), in: RoundedRectangle(cornerRadius: 11))
            .overlay(RoundedRectangle(cornerRadius: 11).stroke(border))
    }

    private func site(_ name: String, _ host: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(name).font(.system(size: 11, weight: .semibold))
            Text(host).font(.system(size: 8, design: .monospaced)).foregroundStyle(.secondary)
        }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
            .background(panel, in: RoundedRectangle(cornerRadius: 8))
    }

    private func setupRow(_ number: Int, _ title: String, _ detail: String, action: @escaping () -> Void) -> some View {
        HStack(spacing: 11) {
            Text("\(number)").font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
                .frame(width: 26, height: 26).background(cyan.opacity(0.12), in: Circle())
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 11, weight: .semibold))
                Text(detail).font(.system(size: 9)).foregroundStyle(.secondary)
            }
            Spacer()
            Button(number == 1 ? "Open" : number == 2 ? "Show folder" : "Test") { action() }
                .buttonStyle(.borderedProminent).tint(cyan)
        }
    }

    private func boundary(_ title: String, _ detail: String, _ color: Color) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Circle().fill(color).frame(width: 7, height: 7).padding(.top, 4)
            Text(title).font(.system(size: 10, weight: .semibold)) +
            Text(" — \(detail)").font(.system(size: 10)).foregroundColor(.secondary)
        }
    }

    private func open(_ value: String) {
        guard let url = URL(string: value) else { return }
        NSWorkspace.shared.open(url)
    }

    private func revealExtension() {
        BrowserProtectionInstaller.stageExtension()
        NSWorkspace.shared.activateFileViewerSelecting([BrowserProtectionStatus.extensionURL])
    }

    private func copyExtensionPath() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(BrowserProtectionStatus.extensionURL.path, forType: .string)
    }
}

private struct BrowserProtectionStatus {
    static let extensionID = BrowserProtectionInstaller.extensionID
    static var extensionURL: URL {
        BrowserProtectionInstaller.stagedExtensionURL
    }

    let chromeInstalled: Bool
    let extensionInstalled: Bool
    let nativeHostInstalled: Bool
    let profileName: String?
    let grantedHosts: Set<String>
    var hasAllHosts: Bool {
        Set(["grok.com", "gemini.google.com", "chatgpt.com", "claude.ai"]).isSubset(of: grantedHosts)
    }

    static func inspect() -> BrowserProtectionStatus {
        BrowserProtectionInstaller.installBundledAssets()
        let fm = FileManager.default
        let support = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Google/Chrome")
        let profiles = (try? fm.contentsOfDirectory(at: support, includingPropertiesForKeys: nil)) ?? []
        var foundProfile: String?
        var hosts = Set<String>()
        for profile in profiles {
            let preferences = profile.appendingPathComponent("Secure Preferences")
            guard let data = try? Data(contentsOf: preferences),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let extensions = root["extensions"] as? [String: Any],
                  let settings = extensions["settings"] as? [String: Any],
                  let item = settings[extensionID] as? [String: Any] else { continue }
            foundProfile = profile.lastPathComponent
            let active = item["active_permissions"] as? [String: Any]
            for pattern in active?["explicit_host"] as? [String] ?? [] {
                if let host = URL(string: pattern.replacingOccurrences(of: "*", with: "x"))?.host {
                    hosts.insert(host)
                }
            }
        }
        let hostManifest = support.appendingPathComponent("NativeMessagingHosts/com.agentspec.agentreins.web.json")
        return BrowserProtectionStatus(
            chromeInstalled: fm.fileExists(atPath: "/Applications/Google Chrome.app"),
            extensionInstalled: foundProfile != nil,
            nativeHostInstalled: fm.fileExists(atPath: hostManifest.path),
            profileName: foundProfile, grantedHosts: hosts)
    }
}
