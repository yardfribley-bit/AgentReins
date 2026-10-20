import AppKit
import Foundation
import WebKit

@main
enum SnapshotRiskAlerts {
    static func main() async {
        _ = NSApplication.shared
        let env = ProcessInfo.processInfo.environment
        let resourceDir = URL(fileURLWithPath: env["AGENTREINS_WORKSPACE_DIR"]!)
        let outDir = URL(fileURLWithPath: env["AGENTREINS_SNAPSHOT_DIR"]!)
        let transportJSON = URL(fileURLWithPath: env["AGENTREINS_TRANSPORT_JSON"]!)
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
        let transportString = String(data: try! Data(contentsOf: transportJSON), encoding: .utf8)!
        let payload: [String: Any] = [
            "tasks": [], "collected": [], "processes": [],
            "health": [["source": "transport-audit", "state": "healthy", "accepted": 4, "detail": "en_f27b746b"]],
            "observing": true, "publishedAt": ISO8601DateFormatter().string(from: Date()),
            "contexts": [], "artifacts": [], "readTaskIDs": [], "ipGeolocations": [],
            "continuityNotice": "en_f27b746b native snapshot"
        ]
        let payloadString = String(data: try! JSONSerialization.data(withJSONObject: payload), encoding: .utf8)!
        // Taller window so detail is in view
        let web = WKWebView(frame: NSRect(x: 0, y: 0, width: 1500, height: 1400), configuration: WKWebViewConfiguration())
        let window = NSWindow(contentRect: NSRect(x: 20, y: 20, width: 1500, height: 1400), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "AgentReins Realtime · en_f27b746b"
        window.contentView = web
        window.makeKeyAndOrderFront(nil)
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        web.loadFileURL(resourceDir.appendingPathComponent("index.html"), allowingReadAccessTo: resourceDir)
        for _ in 0..<80 {
            try? await Task.sleep(nanoseconds: 100_000_000)
            if ((try? await web.evaluateJavaScript("!!window.AgentReinsRisk")) as? Bool) == true { break }
        }
        _ = try? await web.callAsyncJavaScript("window.agentreinsReceive(JSON.parse(payload))", arguments: ["payload": payloadString], in: nil, contentWorld: .page)
        try? await Task.sleep(nanoseconds: 200_000_000)

        func show(rule: String, file: String) async {
            _ = try? await web.callAsyncJavaScript("""
                const records = JSON.parse(raw);
                window.AgentReinsNetwork.setLocalTransports(records);
                const payload = {tasks:[],collected:[],health:[]};
                const alerts = window.AgentReinsRisk.buildAlerts(payload);
                const a = alerts.find(x => x.rule===rule);
                const holder = document.getElementById('alerts-view');
                const state = {filter:{sev:'all',rule:rule,agent:'all',q:''}, selected: a?a.id:null, decisions:[], alerts:alerts};
                window.AgentReinsRisk.renderList(holder, payload, state);
                const detail = document.querySelector('.risk-detail');
                if (detail) detail.scrollIntoView({block:'start'});
                return detail ? detail.querySelector('h2')?.textContent : 'missing';
                """, arguments: ["raw": transportString, "rule": rule], in: nil, contentWorld: .page)
            try? await Task.sleep(nanoseconds: 500_000_000)
            let image = try! await web.takeSnapshot(configuration: nil)
            let png = NSBitmapImageRep(data: image.tiffRepresentation!)!.representation(using: .png, properties: [:])!
            try! png.write(to: outDir.appendingPathComponent(file))
            fputs("wrote \(file) bytes=\(png.count)\n", stderr)
        }

        // Home all alerts
        _ = try? await web.callAsyncJavaScript("""
            const records = JSON.parse(raw);
            window.AgentReinsNetwork.setLocalTransports(records);
            const payload = {tasks:[],collected:[],health:[]};
            const holder = document.getElementById('alerts-view');
            window.AgentReinsRisk.renderList(holder, payload, {filter:{sev:'all',rule:'all',agent:'all',q:''}, selected:null, decisions:[]});
            """, arguments: ["raw": transportString], in: nil, contentWorld: .page)
        try? await Task.sleep(nanoseconds: 400_000_000)
        let home = try! await web.takeSnapshot(configuration: nil)
        try! NSBitmapImageRep(data: home.tiffRepresentation!)!.representation(using: .png, properties: [:])!
            .write(to: outDir.appendingPathComponent("01-alerts-home.png"))

        await show(rule: "S03", file: "02-s03-alert-detail.png")
        await show(rule: "S07", file: "03-s07-alert-detail.png")
        exit(0)
    }
}
