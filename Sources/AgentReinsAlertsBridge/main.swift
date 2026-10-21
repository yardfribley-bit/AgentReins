import Foundation
import JavaScriptCore

/// Packaged alerts bridge: runs the same RealtimeWorkspace JS via JavaScriptCore.
/// No system `node` required. stdin JSON → stdout {alerts, engine}.
@main
enum AgentReinsAlertsBridge {
    static func main() {
        let env = ProcessInfo.processInfo.environment
        let candidates: [URL] = [
            env["AGENTREINS_WORKSPACE_JS"].map { URL(fileURLWithPath: $0) },
            Bundle.main.resourceURL?.appendingPathComponent("RealtimeWorkspace"),
            URL(fileURLWithPath: CommandLine.arguments[0])
                .deletingLastPathComponent() // MacOS
                .deletingLastPathComponent() // Contents
                .appendingPathComponent("Resources/RealtimeWorkspace"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("Sources/AgentReins/Resources/RealtimeWorkspace"),
            URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Sources/AgentReins/Resources/RealtimeWorkspace"),
        ].compactMap { $0 }

        guard let root = candidates.first(where: {
            FileManager.default.fileExists(atPath: $0.appendingPathComponent("risk-alerts.js").path)
                && FileManager.default.fileExists(atPath: $0.appendingPathComponent("network-view.js").path)
        }) else {
            fputs("AgentReinsAlertsBridge: RealtimeWorkspace JS not found\n", stderr)
            exit(2)
        }

        let inputData = FileHandle.standardInput.readDataToEndOfFile()
        let inputText = String(data: inputData, encoding: .utf8) ?? "{}"

        let context = JSContext()!
        context.exceptionHandler = { _, exc in
            fputs("JSC exception: \(exc?.toString() ?? "?")\n", stderr)
        }
        context.evaluateScript("var window = {};")
        for name in ["network-view.js", "risk-alerts.js"] {
            let src = try! String(contentsOf: root.appendingPathComponent(name), encoding: .utf8)
            context.evaluateScript(src)
        }

        let script = """
        (function(raw){
          const input = JSON.parse(raw || '{}');
          const net = window.AgentReinsNetwork;
          const risk = window.AgentReinsRisk;
          net.setLocalTransports(input.transports || []);
          const payload = {tasks: input.tasks || [], collected: [], health: input.health || []};
          const alerts = risk.buildAlerts(payload).map(a => ({
            id: a.id, rule: a.rule, title: a.title, sub: a.sub, agent: a.agent,
            session: a.session, call: a.call, confidence: a.confidence,
            timestamp: a.timestamp, why: a.why, evidence: a.evidence || null
          }));
          return JSON.stringify({alerts: alerts, engine: 'swift-jsc-bridge', workspace: '\(root.path.replacingOccurrences(of: "'", with: "\\'"))'});
        })
        """
        guard let fn = context.evaluateScript(script), fn.isObject else {
            fputs("AgentReinsAlertsBridge: failed to compile runner\n", stderr)
            exit(3)
        }
        guard let result = fn.call(withArguments: [inputText]), let out = result.toString() else {
            fputs("AgentReinsAlertsBridge: evaluation failed\n", stderr)
            exit(4)
        }
        fputs(out, stdout)
    }
}
