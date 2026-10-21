import JavaScriptCore
import XCTest

/// Item-3 XSS checks against the app's own risk-alerts.js (no local esc copy).
final class AppRiskEscapeTests: XCTestCase {
    func testAppEscAndRenderListEscapeXSSWithoutLocalEscCopy() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentReins/Resources/RealtimeWorkspace")
        let network = try String(contentsOf: root.appendingPathComponent("network-view.js"), encoding: .utf8)
        let risk = try String(contentsOf: root.appendingPathComponent("risk-alerts.js"), encoding: .utf8)
        func context(_ riskSource: String) throws -> JSContext {
            let ctx = try XCTUnwrap(JSContext())
            ctx.exceptionHandler = { _, exc in
                XCTFail("JSC exception: \(exc?.toString() ?? "?")")
            }
            ctx.evaluateScript("var window = {};")
            ctx.evaluateScript(network)
            ctx.evaluateScript(riskSource)
            return ctx
        }
        let ctx = try context(risk)
        let probe = "<img src=x onerror='window.hacked=1'>XSS-PROBE-原文"
        // esc is private to risk-alerts.js: no exported or settable escape hook ships.
        XCTAssertEqual(ctx.evaluateScript("typeof window.AgentReinsRisk.esc")?.toString(), "undefined")

        // Real alert fixture (S07) so list+detail both render the probe.
        ctx.evaluateScript("""
        window.AgentReinsNetwork.setLocalTransports([{
          captureMode:'agent-path', agent:'Cursor', tool:'curl',
          startedAt:'2026-10-21T06:00:00Z', pid:42, exitCode:0,
          runID:'xss-bypass', call:'xss-bypass', session:'xss-sess',
          args:['--noproxy','*','https://cdn.agentreins-field.net/' + \(jsString(probe))],
          connections:[{kind:'connected',detail:['cdn.agentreins-field.net:443']}],
          blocks:[], auditBypass:true
        }]);
        var __holder = { innerHTML: '' };
        var __payload = { tasks: [], collected: [], health: [{source:'transport-audit',state:'healthy',detail:'proxy is running on 18891'}] };
        var __alerts = window.AgentReinsRisk.buildAlerts(__payload);
        window.AgentReinsRisk.renderList(__holder, __payload, {
          filter: { sev: 'all', rule: 'all', agent: 'all', q: '' }, selected: null, decisions: []
        });
        """)
        let alertCount = ctx.evaluateScript("__alerts.filter(a=>a.rule==='S07').length")?.toInt32() ?? 0
        XCTAssertGreaterThan(alertCount, 0, "fixture must produce S07")
        var html = ctx.evaluateScript("__holder.innerHTML")?.toString() ?? ""
        XCTAssertFalse(html.contains("<img src=x"), "list must escape via app esc")
        XCTAssertTrue(html.contains("风险告警") || html.contains("XSS-PROBE"))

        ctx.evaluateScript("""
        var sel = __alerts.find(a=>a.rule==='S07');
        window.AgentReinsRisk.renderList(__holder, __payload, {
          filter: { sev: 'all', rule: 'S07', agent: 'all', q: '' }, selected: sel.id, decisions: []
        });
        """)
        html = ctx.evaluateScript("__holder.innerHTML")?.toString() ?? ""
        XCTAssertFalse(html.contains("<img src=x"), "detail must escape via app esc")
        XCTAssertTrue(html.contains("&lt;img src=x onerror=&#39;window.hacked=1&#39;&gt;XSS-PROBE-原文"),
                      "the probe is shown, escaped exactly")

        // Negative control without a hook: a copy of the shipped source whose esc() is the identity must leak.
        let identity = try XCTUnwrap(risk.range(of: #"function esc\(s\)\{return String\(s\?\?''\)\.replace\([^\n]*\}"#,
                                                 options: .regularExpression))
        let brokenCtx = try context(risk.replacingCharacters(in: identity, with: "function esc(s){return String(s??'');}"))
        let broke = brokenCtx.evaluateScript("""
        (function(){
          window.AgentReinsNetwork.setLocalTransports([{
            captureMode:'agent-path', agent:'Cursor', tool:'curl', startedAt:'2026-10-21T06:00:00Z', pid:42, exitCode:0,
            runID:'xss-bypass', call:'xss-bypass', session:'xss-sess',
            args:['--noproxy','*','https://cdn.agentreins-field.net/' + \(jsString(probe))],
            connections:[{kind:'connected',detail:['cdn.agentreins-field.net:443']}], blocks:[], auditBypass:true
          }]);
          var holder = { innerHTML: '' }, payload = { tasks: [], collected: [], health: [] };
          var alerts = window.AgentReinsRisk.buildAlerts(payload);
          window.AgentReinsRisk.renderList(holder, payload, {
            filter: { sev: 'all', rule: 'S07', agent: 'all', q: '' }, selected: alerts.find(a=>a.rule==='S07').id, decisions: []
          });
          return holder.innerHTML.includes('<img src=x');
        })()
        """)?.toBool()
        XCTAssertEqual(broke, true, "an identity esc() in risk-alerts.js must leak raw img through renderList")
    }

    private func jsString(_ s: String) -> String {
        let escaped = s
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "'", with: "\\'")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "'\(escaped)'"
    }
}
