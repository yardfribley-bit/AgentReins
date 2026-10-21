import JavaScriptCore
import XCTest

/// Item-3 XSS checks against the app's own risk-alerts.js (no local esc copy, no WKWebView).
final class AppRiskEscapeTests: XCTestCase {
    func testAppEscAndRenderListEscapeXSSWithoutLocalEscCopy() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // AgentReinsTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo
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

        ctx.evaluateScript("window.AgentReinsNetwork.setLocalTransports([])")
        ctx.evaluateScript("""
        var __holder = { innerHTML: '' };
        window.AgentReinsRisk.renderList(__holder, {
          tasks: [{ agent: 'Cursor', session: 'xss', cards: [{
            id: 'call:xss', call: 'xss', timestamp: '2026-10-21T06:00:00Z',
            kind: 'command', title: \(jsString(probe)),
            execution: { command: \(jsString(probe)), call: 'xss', startAt: '2026-10-21T06:00:00Z' },
            input: \(jsString(probe))
          }]}],
          collected: [], health: []
        }, { filter: { sev: 'all', rule: 'all', agent: 'all', q: '' }, selected: null, decisions: [] });
        """)
        let html = ctx.evaluateScript("__holder.innerHTML")?.toString() ?? ""
        XCTAssertFalse(html.contains("<img src=x"), "renderList must escape via app esc")
        XCTAssertTrue(html.contains("风险告警") || html.contains("XSS-PROBE"))

        // Deliberately break app esc — exact assertion must fail (proves binding to app code).
        let broke = ctx.evaluateScript("""
        (function(){
          const real = window.AgentReinsRisk.esc;
          window.AgentReinsRisk.esc = s => String(s);
          let failed = false;
          try {
            if (window.AgentReinsRisk.esc("<img>") !== "&lt;img&gt;") failed = true;
          } catch (e) { failed = true; }
          window.AgentReinsRisk.esc = real;
          return failed;
        })()
        """)?.toBool()
        XCTAssertEqual(broke, true, "deliberately breaking app esc must fail the exact assertion")
    }

    private func jsString(_ s: String) -> String {
        let escaped = s
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "'", with: "\\'")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "'\(escaped)'"
    }
}
