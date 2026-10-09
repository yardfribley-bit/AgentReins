import XCTest
@testable import AgentReins

final class RealtimeNetworkEvidenceTests: XCTestCase {
    func testActualGitSocketAndProxyTargetRemainSeparateInResourceDetails() throws {
        let process = ProcessSnapshotRecord(pid:"12300",ppid:"12298",command:"git-remote-https",agent:"codex",birthIdentity:1791562328740728,executablePath:"/usr/bin/git-remote-http")
        let connection = NetworkConnectionRecord(pid:"12300",localAddress:"127.0.0.1:62129",remoteHost:"127.0.0.1",remotePort:1081,state:"ESTABLISHED")
        let route = ProxyDestinationRecord(clientPort:62129,remoteHost:"github.com",remotePort:443,timestamp:Date(timeIntervalSince1970:1791562328),proxyName:"V2rayU")
        let event = try XCTUnwrap(NetworkSocketEvidenceProjector.project(processes:[process],connections:[connection],proxyDestinations:[route],observedAt:Date(timeIntervalSince1970:1791562329.131)).first)
        let detail = try XCTUnwrap(RealtimeDetailProjector.resource(event:event,input:event.command,output:nil,kind:"network"))
        XCTAssertEqual(detail.evidenceType,"proxy_route")
        XCTAssertEqual(detail.observedLocalAddress,"127.0.0.1:62129")
        XCTAssertEqual(detail.observedRemoteHost,"127.0.0.1");XCTAssertEqual(detail.observedRemotePort,1081)
        XCTAssertEqual(detail.domain,"github.com");XCTAssertEqual(detail.remotePort,443)
        XCTAssertNil(detail.remoteIP);XCTAssertNil(detail.method);XCTAssertNil(detail.url)
        XCTAssertEqual(detail.proxySource,"V2rayU")
    }
    @MainActor func testObservedProxyDomainCannotBeReplacedByAnotherToolsURL() {
        let now = Date(),resolver = EventAttributionResolver(window:45)
        let call = GuardEvent(kind:"tool",ruleId:"call",path:"/tmp",command:"{\"url\":\"https://api.github.com\"}",agent:"codex",op:"call",severity:"info",ts:now,action:"requested",sessionId:"s",turnId:"t",toolCallId:"web",toolName:"web_fetch")
        resolver.observe([call],now:now)
        let socket = GuardEvent(kind:"network",ruleId:"network_connection",path:"-",command:nil,agent:"codex",op:"connect",severity:"info",ts:now,action:"observed",processId:4270,remoteHost:"chatgpt.com",remotePort:443,remoteDomain:"chatgpt.com")
        let resolved = resolver.resolve(socket)
        XCTAssertEqual(resolved.remoteDomain,"chatgpt.com");XCTAssertNil(resolved.toolCallId)
    }
    @MainActor func testUnknownSocketIPStaysUnknownWhenToolHasExplicitURL() {
        let now = Date(),resolver = EventAttributionResolver(window:45)
        resolver.observe([GuardEvent(kind:"tool",ruleId:"call",path:"/tmp",command:"{\"url\":\"https://github.com/example/project\"}",agent:"codex",op:"call",severity:"info",ts:now,action:"requested",sessionId:"s",turnId:"t",toolCallId:"web",toolName:"web_fetch")],now:now)
        let socket = GuardEvent(kind:"network",ruleId:"network_connection",path:"-",command:nil,agent:"codex",op:"connect",severity:"info",ts:now,action:"observed",processId:2420,remoteHost:"203.0.113.10",remotePort:443)
        let resolved = resolver.resolve(socket)
        XCTAssertNil(resolved.remoteDomain);XCTAssertEqual(resolved.remoteHost,"203.0.113.10")
    }
    func testLegacyActiveSocketRestoresOnlyTheObservedProxyDomain() throws {
        let old = GuardEvent(kind:"network",ruleId:"network_connection",path:"-",command:nil,agent:"codex",op:"connect",severity:"info",ts:Date(),action:"observed",sessionId:"s",turnId:"t",source:"lsof-network",attributionConfidence:.inferred,attributionMethod:"lsof socket owner + exact client-port join via V2rayU access log + single active tool call (late correlation)",remoteHost:"chatgpt.com",remotePort:443,remoteDomain:"api.github.com")
        let corrected = try XCTUnwrap(RealtimeWorkspaceProjector.normalizedEvents([old]).first)
        XCTAssertEqual(corrected.id,old.id);XCTAssertEqual(corrected.remoteDomain,"chatgpt.com")
    }
    func testCompletedNativeCommandPreservesCommandAndFileURLWorkingDirectory() throws {
        let result = GuardEvent(kind:"tool",ruleId:"codex_command_completed",path:"-",command:"{\"command\":\"git push -u origin feature\",\"cwd\":\"file:///tmp/project%20one\"}",agent:"codex",op:"result",severity:"info",ts:Date(),action:"completed",sessionId:"s",turnId:"t",toolCallId:"execution:native",modelResponse:"{\"stdout\":\"branch pushed\",\"exit_code\":0}",toolName:"CommandExecution",source:"agentsight:codex-local-compat")
        let card = try XCTUnwrap(RealtimeWorkspaceProjector.cards([result]).first)
        XCTAssertTrue(card.input.contains("git push"));XCTAssertEqual(card.execution?.command,"git push -u origin feature")
        XCTAssertEqual(card.execution?.cwd,"/tmp/project one");XCTAssertEqual(card.execution?.exitCode,0)
        XCTAssertNil(card.execution?.startAt,"A completion record does not invent an execution-start observation")
    }
    @MainActor func testIndependentNetworkRemainsVisibleAndRestorableAfterResourceNoise() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("network-visible-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at:url) }
        let now = Date().addingTimeInterval(60)
        let socket = GuardEvent(kind:"network",ruleId:"network_connection",path:"-",command:nil,agent:"codex",op:"connect",severity:"info",ts:now,action:"observed",source:"lsof-network",processId:12300,remoteHost:"github.com",remotePort:443,remoteDomain:"github.com")
        let state = RealtimeWorkspaceState(checkpointURL:url)
        state.ingest([socket])
        state.ingest((1...250).map { i in GuardEvent(kind:"activity",ruleId:"process_observation",path:"-",command:nil,agent:"codex",op:"process_resource_sample",severity:"info",ts:now.addingTimeInterval(Double(i)),action:"observed") })
        let payload = state.payload(processes:[],health:[],observing:true,error:nil)
        XCTAssertTrue(payload.collected.contains { $0.id == socket.id.uuidString })
        XCTAssertFalse(payload.tasks.contains { $0.cards.contains { $0.id == socket.id.uuidString } },"Independent evidence must not be assigned to an arbitrary task")
        state.flushCheckpoint()
        XCTAssertTrue(try XCTUnwrap(RealtimeActiveCheckpoint.load(url)).events.contains { $0.id == socket.id })
    }
}
