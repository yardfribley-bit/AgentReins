import Foundation
import XCTest
@testable import AgentReins

final class CollectionProcessPresentationTests: XCTestCase {
    private func process(_ pid: String, parent: String, birth: UInt64, command: String = "unknown-service") -> ProcessSnapshotRecord {
        .init(pid: pid, ppid: parent, command: command, agent: "workbuddy", birthIdentity: birth)
    }
    func testNewServiceJoinsTreeAndRemainsAfterLeavingInventory() {
        var registry = CollectionProcessRegistry()
        let root = process("10", parent: "1", birth: 100)
        let child = ProcessSnapshotRecord(pid: "11", ppid: "10", command: "node payment-mcp", agent: "workbuddy", birthIdentity: 200, executablePath: "/usr/bin/node")
        registry.update([root], now: Date(timeIntervalSince1970: 1))
        registry.update([root, child], now: Date(timeIntervalSince1970: 2))
        XCTAssertEqual(registry.ordered.map(\.depth), [0, 1])
        XCTAssertEqual(registry.ordered.last?.node.role.title, "MCP 服务候选")
        registry.update([root], now: Date(timeIntervalSince1970: 3))
        XCTAssertEqual(registry.nodes.count, 2)
        XCTAssertEqual(registry.ordered.last?.node.active, false)
    }
    func testReusedPIDKeepsSeparateIdentitiesAndOriginalParent() {
        var registry = CollectionProcessRegistry()
        registry.update([process("10", parent: "1", birth: 100), process("11", parent: "10", birth: 200)], now: Date(timeIntervalSince1970: 1))
        registry.update([process("10", parent: "1", birth: 300)], now: Date(timeIntervalSince1970: 2))
        XCTAssertEqual(registry.nodes.count, 3)
        let order = registry.ordered
        XCTAssertEqual(order.first?.node.process.birthIdentity, 100)
        XCTAssertEqual(order[1].node.process.birthIdentity, 200)
        XCTAssertEqual(order[1].depth, 1)
        XCTAssertEqual(order[2].depth, 0)
    }
    func testIdentifiesKnownComponentsWithoutHardCodedPIDs() {
        let cases: [(String, String, String)] = [
            ("Electron", "Electron --type=utility --utility-sub-type=network.mojom.NetworkService", "网络服务进程"),
            ("Electron", "Electron /Applications/WorkBuddy.app/Contents/Resources/app.asar/main/daemon-app-server-entry.js --stdio", "应用后台服务"),
            ("Electron", "Electron /Applications/WorkBuddy.app/Contents/Resources/app.asar/main/sidecar-entry.js", "Sidecar 辅助服务"),
            ("node", "node /Users/example/.workbuddy/plugins/cache/workbuddy-builtin/weixinpay/1.0/dist/mcp-server.mjs", "微信支付插件 MCP 服务"),
            ("node", "node /Users/example/.workbuddy/plugins/cache/workbuddy-builtin/sheetagent/1.0/mcp/start.mjs", "表格插件 MCP 服务"),
            ("sandbox-center", "sandbox-center", "安全 / 沙盒相关组件"),
            ("betterleaks", "betterleaks stdin", "敏感信息检测组件"),
            ("AgentReinsHook", "AgentReinsHook PreToolUse", "AgentReins 采集 Hook"),
            ("ffmpeg", "ffmpeg -i video.mp4", "音视频处理工具")
        ]
        for (name, command, title) in cases {
            let record = ProcessSnapshotRecord(pid: "9999", ppid: "1", command: command, agent: "workbuddy", birthIdentity: 1, executablePath: "/test/" + name)
            let node = CollectionProcessNode(process: record, firstSeen: Date(), lastSeen: Date(), active: true)
            XCTAssertEqual(node.role.title, title)
        }
    }
    func testShellArgumentsDoNotTurnShellIntoRendererOrPaymentService() {
        let record = ProcessSnapshotRecord(pid: "10", ppid: "1", command: "zsh -c echo --type=renderer mcp", agent: "workbuddy", birthIdentity: 1, executablePath: "/bin/zsh")
        let node = CollectionProcessNode(process: record, firstSeen: Date(), lastSeen: Date(), active: true)
        XCTAssertEqual(node.role.title, "Shell 命令执行器")
    }

    func testUnknownServicesAreNotAssignedAnInventedRole() {
        XCTAssertEqual(CollectionProcessNode(process: process("12", parent: "1", birth: 100), firstSeen: Date(), lastSeen: Date(), active: true).role.title, "职责待确认")
    }
}
