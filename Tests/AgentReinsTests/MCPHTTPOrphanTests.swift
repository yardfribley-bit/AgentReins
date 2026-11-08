import XCTest
import AgentReinsCore

final class MCPHTTPOrphanTests: XCTestCase {
    func testParseAndSelectOrphansLeavesListenerAndOtherPorts() {
        let text = """
          10  1 /Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 18977
          11  1 /Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 18977
          12  1 /Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 19000
          13  400 /Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP
          14  1 /Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP
          15  1 /bin/zsh
        """
        let procs = MCPHTTPOrphans.parsePS(text)
        XCTAssertEqual(procs.count, 6)
        let lsof = """
        COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        AgentRein 10 user 5u IPv4 0t0 TCP 127.0.0.1:18977 (LISTEN)
        """
        let listeners = MCPHTTPOrphans.listenerPIDs(lsof: lsof)
        XCTAssertEqual(listeners, [10])
        let orphans = MCPHTTPOrphans.orphanPIDs(procs, selfPid: 10, port: 18977, listenerPIDs: listeners)
        XCTAssertEqual(orphans, [11, 14])
    }
}
