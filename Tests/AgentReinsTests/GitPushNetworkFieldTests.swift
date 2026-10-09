import Foundation
import XCTest
@testable import AgentReins

/// Source evidence retained from the actual GitHub upload. No network activity
/// or HTTP payload is generated as a substitute for the original observations.
final class GitPushNetworkFieldTests: XCTestCase {
    @MainActor func testActualGitPushSocketRouteAndCompletedCommand() throws {
        guard let path = ProcessInfo.processInfo.environment["AGENTREINS_GIT_NETWORK_FIELD_DIR"] else { throw XCTSkip("需指定本次Git上传的真实采集切片") }
        let root = URL(fileURLWithPath:path)
        let original = try WorkBuddyNetworkEvidence.captureDecoder().decode(GuardEvent.self,from:Data(contentsOf:root.appendingPathComponent("observed-git-socket.json")))
        XCTAssertEqual(original.op,"process_socket_observation");XCTAssertEqual(original.processId,12300)
        let data = try XCTUnwrap(RealtimeDetailProjector.object(original.afterContent))
        let identity = try XCTUnwrap(data["processIdentity"] as? String).split(separator:":")
        let birth = try XCTUnwrap(identity.last.flatMap { UInt64($0) })
        let connections = (data["connections"] as? [[String:Any]] ?? []).map {
            NetworkConnectionRecord(pid:String(original.processId!),localAddress:$0["local"] as? String ?? "",remoteHost:$0["remoteHost"] as? String ?? "",remotePort:$0["remotePort"] as? Int ?? 0,state:$0["state"] as? String)
        }
        let routes = V2rayUProxyDestinationProvider.parse(try String(contentsOf:root.appendingPathComponent("proxy-access-line.txt"),encoding:.utf8))
        XCTAssertEqual(routes.first?.remoteHost,"github.com");XCTAssertEqual(routes.first?.clientPort,62129)
        let process = ProcessSnapshotRecord(pid:"12300",ppid:String(original.parentProcessId ?? 0),command:"",agent:original.agent,birthIdentity:birth)
        let projected = NetworkSocketEvidenceProjector.project(processes:[process],connections:connections,proxyDestinations:routes,observedAt:original.ts,source:original.source ?? "process-observation-lsof")
        let socket = try XCTUnwrap(projected.first)
        XCTAssertEqual(socket.kind,"network");XCTAssertEqual(socket.remoteDomain,"github.com")
        XCTAssertEqual(socket.remotePort,443);XCTAssertEqual(socket.localAddress,"127.0.0.1:62129")
        let resource = try XCTUnwrap(RealtimeDetailProjector.resource(event:socket,input:socket.command,output:nil,kind:"network"))
        XCTAssertEqual(resource.observedRemoteHost,"127.0.0.1");XCTAssertEqual(resource.observedRemotePort,1081)
        XCTAssertEqual(resource.proxySource,"V2rayU");XCTAssertNil(resource.remoteIP);XCTAssertNil(resource.method);XCTAssertNil(resource.url)
        let native = CodexSight.parseSession(root.appendingPathComponent("actual-git-completed.jsonl"),fullHistory:true)
        let completed = try XCTUnwrap(native.first { $0.op == "result" && $0.toolName == "CommandExecution" })
        let card = try XCTUnwrap(RealtimeWorkspaceProjector.cards([completed]).first)
        XCTAssertTrue(card.execution?.command?.contains("git push -u origin codex/agentreins-realtime-visualization") == true)
        XCTAssertEqual(card.execution?.exitCode,0);XCTAssertTrue(card.execution?.cwd?.hasSuffix("AgentReins-v2") == true)
        let target = try XCTUnwrap(ToolActivityEvidenceProjector().project([completed]).first { $0.kind == "network" })
        XCTAssertEqual(target.remoteDomain,"github.com");XCTAssertEqual(target.toolCallId,completed.toolCallId)
        let targetResource = try XCTUnwrap(RealtimeDetailProjector.resource(event:target,input:target.command,output:nil,kind:"network"))
        XCTAssertEqual(targetResource.evidenceType,"tool_intent")
        XCTAssertEqual(targetResource.requestedURL,"https://github.com/yardfribley-bit/AgentReins.git")
        XCTAssertNil(targetResource.method);XCTAssertNil(targetResource.remoteIP)
        let encoder = JSONEncoder();encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(projected+[target]).write(to:root.appendingPathComponent("reprojected-network.json"))
        let tasks = RealtimeWorkspaceProjector.tasks(events:native+[target],since:.distantPast)
        let payload = RealtimeWorkspacePayload(tasks:tasks,collected:projected.map { e in let p=CollectionRecordPresentation(e,receivedAt:e.ts);return RealtimeCollectedRecord(id:e.id.uuidString,agent:e.agent ?? "Codex",source:e.source ?? "",kind:e.kind,op:e.op,summary:p.summary,preview:e.command ?? "",hasTaskIdentity:false,title:p.title,category:p.category,details:e.command ?? "",pid:e.processId,timestamp:e.ts) },unattributedCount:1,processes:[],health:[],observing:false,persistenceError:nil,publishedAt:Date(),truncated:false)
        try encoder.encode(payload).write(to:root.appendingPathComponent("actual-git-network-payload.json"))
    }
}
