import AppKit
import Foundation
import WebKit

/// `--snapshot-alerts <outdir>`: after the live window loads real transport evidence,
/// select S03/S07 alerts in-app and write titled-window PNGs via `screencapture -l`.
enum NativeAlertSnapshot {
    static var requestedOutDir: URL? {
        let args = ProcessInfo.processInfo.arguments
        guard let idx = args.firstIndex(of: "--snapshot-alerts"), args.indices.contains(idx + 1) else { return nil }
        return URL(fileURLWithPath: args[idx + 1], isDirectory: true)
    }

    static func scheduleIfRequested() {
        guard let out = requestedOutDir else { return }
        try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
            Task { @MainActor in await run(outDir: out) }
        }
    }

    @MainActor
    private static func run(outDir: URL) async {
        guard let window = NSApp.windows.first(where: { $0.title.contains("AgentReins") || $0.canBecomeMain }),
              let web = findWebView(in: window.contentView) else {
            fputs("snapshot: no AgentReins WKWebView yet\n", stderr)
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                Task { @MainActor in await run(outDir: outDir) }
            }
            return
        }
        window.setContentSize(NSSize(width: 1400, height: 900))
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        try? await Task.sleep(nanoseconds: 500_000_000)
        // Wait until risk module + transports are ready.
        for _ in 0..<40 {
            let ready = (try? await web.evaluateJavaScript("!!(window.AgentReinsRisk && window.AgentReinsNetwork)")) as? Bool
            if ready == true { break }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        // Feed the same live transport records the app reads (user Application Support), not fixtures.
        let records = NativeTransportAudit.liveRecords()
        let recordsJSON = String(data: (try? JSONSerialization.data(withJSONObject: records)) ?? Data("[]".utf8), encoding: .utf8) ?? "[]"
        _ = try? await web.callAsyncJavaScript(
            "window.AgentReinsNetwork.setLocalTransports(JSON.parse(raw)); return (window.AgentReinsNetwork.localExchanges()||[]).length;",
            arguments: ["raw": recordsJSON],
            in: nil,
            contentWorld: .page
        )
        _ = try? await web.evaluateJavaScript("document.querySelector('[data-view=alerts]')?.click()")
        try? await Task.sleep(nanoseconds: 500_000_000)
        _ = try? await web.evaluateJavaScript("""
        (function(){
          const api=window.AgentReinsRisk; const holder=document.getElementById('alerts-view');
          const payload={tasks:[],collected:[],health:[{source:'transport-audit',state:'healthy',detail:'live'}]};
          api.renderList(holder,payload,{filter:{sev:'all',rule:'all',agent:'all',q:''},selected:null,decisions:[]});
          return api.buildAlerts(payload).length;
        })()
        """)
        try? await Task.sleep(nanoseconds: 600_000_000)
        await capture(window: window, to: outDir.appendingPathComponent("01-alerts-home-native.png"))

        let s03Info = (try? await web.evaluateJavaScript("""
        (function(){
          const api=window.AgentReinsRisk; if(!api) return 'no-api';
          const payload={tasks:[],collected:[],health:[]};
          const alerts=api.buildAlerts(payload);
          const s03=alerts.find(a=>a.rule==='S03');
          const holder=document.getElementById('alerts-view');
          api.renderList(holder,payload,{filter:{sev:'all',rule:'S03',agent:'all',q:''},selected:s03?s03.id:null,decisions:[]});
          document.querySelector('.risk-detail')?.scrollIntoView({block:'start'});
          const detail=document.querySelector('.risk-detail h2');
          return s03?('S03:'+s03.confidence+':'+(detail?detail.textContent:'')+':'+s03.id):'no-s03 count='+alerts.length;
        })()
        """)) as? String
        fputs("snapshot: \(s03Info ?? "nil")\n", stderr)
        try? await Task.sleep(nanoseconds: 900_000_000)
        await capture(window: window, to: outDir.appendingPathComponent("02-s03-alert-detail-native.png"))

        let s07Info = (try? await web.evaluateJavaScript("""
        (function(){
          const api=window.AgentReinsRisk; if(!api) return 'no-api';
          const payload={tasks:[],collected:[],health:[]};
          const alerts=api.buildAlerts(payload);
          const s07=alerts.find(a=>a.rule==='S07');
          const holder=document.getElementById('alerts-view');
          api.renderList(holder,payload,{filter:{sev:'all',rule:'S07',agent:'all',q:''},selected:s07?s07.id:null,decisions:[]});
          document.querySelector('.risk-detail')?.scrollIntoView({block:'start'});
          return s07?('S07:'+s07.id+':'+(document.querySelector('.risk-detail')?'has-detail':'no-detail')):'no-s07';
        })()
        """)) as? String
        fputs("snapshot: \(s07Info ?? "nil")\n", stderr)
        try? await Task.sleep(nanoseconds: 900_000_000)
        await capture(window: window, to: outDir.appendingPathComponent("03-s07-alert-detail-native.png"))

        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        let meta: [String: Any] = [
            "method": "AgentReins.app titled window + screencapture -l",
            "version": version,
            "build": build,
            "note": "Live transport evidence; UI selection only — no injected payload/banner",
        ]
        if let data = try? JSONSerialization.data(withJSONObject: meta, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: outDir.appendingPathComponent("native-screenshots.json"))
        }
        fputs("snapshot: done version=\(version) build=\(build)\n", stderr)
        NSApp.terminate(nil)
    }

    private static func findWebView(in view: NSView?) -> WKWebView? {
        guard let view else { return nil }
        if let web = view as? WKWebView { return web }
        for child in view.subviews {
            if let found = findWebView(in: child) { return found }
        }
        return nil
    }

    private static func capture(window: NSWindow, to url: URL) async {
        let wid = CGWindowID(window.windowNumber)
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        proc.arguments = ["-l", String(wid), "-o", "-x", url.path]
        try? proc.run()
        proc.waitUntilExit()
        fputs("snapshot: wrote \(url.lastPathComponent) bytes=\((try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)\n", stderr)
    }
}
