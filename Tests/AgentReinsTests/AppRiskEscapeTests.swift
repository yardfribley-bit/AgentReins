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
        let ctx = try XCTUnwrap(JSContext())
        ctx.exceptionHandler = { _, exc in
            XCTFail("JSC exception: \(exc?.toString() ?? "?")")
        }
        ctx.evaluateScript("var window = {};")
        for name in ["network-view.js", "risk-alerts.js"] {
            let src = try String(contentsOf: root.appendingPathComponent(name), encoding: .utf8)
            ctx.evaluateScript(src)
        }
        let probe = "<img src=x onerror='window.hacked=1'>XSS-PROBE-原文"
        let exact = "&lt;img src=x onerror=&#39;window.hacked=1&#39;&gt;XSS-PROBE-原文"
        let escaped = ctx.evaluateScript("window.AgentReinsRisk.esc(\(jsString(probe)))")?.toString()
        XCTAssertEqual(escaped, exact, "must use app AgentReinsRisk.esc — no local copy")
        XCTAssertFalse(escaped?.contains("<img") == true)

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
        XCTAssertTrue(html.contains("risk-detail") || html.contains("绕过") || html.contains("XSS-PROBE"))

        // Rebind escImpl — renderList must use the broken esc.
        let broke = ctx.evaluateScript("""
        (function(){
          const real = window.AgentReinsRisk.esc;
          window.AgentReinsRisk.esc = s => String(s);
          window.AgentReinsRisk.renderList(__holder, __payload, {
            filter: { sev: 'all', rule: 'S07', agent: 'all', q: '' }, selected: __alerts.find(a=>a.rule==='S07').id, decisions: []
          });
          const leaked = __holder.innerHTML.includes('<img src=x');
          window.AgentReinsRisk.esc = real;
          return leaked;
        })()
        """)?.toBool()
        XCTAssertEqual(broke, true, "breaking escImpl must leak raw img through renderList")
    }

    private func jsString(_ s: String) -> String {
        let escaped = s
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "'", with: "\\'")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "'\(escaped)'"
    }
}
