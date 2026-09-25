import XCTest
@testable import AgentReins

final class TaskSearchIndexTests: XCTestCase {
    func testHistoryQueriesRouteAcrossCoreEvidenceDomains() {
        if case .memoryLineage = HistoryQueryIntent.classify("192.168.1.39 什么时候写入长期记忆") {} else { XCTFail("memory lineage query was not routed") }
        if case .tokenRanking = HistoryQueryIntent.classify("哪个任务消耗 Token 最多") {} else { XCTFail("token ranking query was not routed") }
        if case .repeatedTools = HistoryQueryIntent.classify("哪些任务重复调用了工具") {} else { XCTFail("repeated tool query was not routed") }
        if case .modelExposure = HistoryQueryIntent.classify("发给大模型的上下文里有什么") {} else { XCTFail("model exposure query was not routed") }
        if case .fileChanges = HistoryQueryIntent.classify("Agent 改了哪些文件") {} else { XCTFail("file change query was not routed") }
        if case .networkEgress = HistoryQueryIntent.classify("这个中转 IP 连接到了哪里") {} else { XCTFail("network query was not routed") }
        if case .toolExecution = HistoryQueryIntent.classify("执行了哪些危险命令") {} else { XCTFail("tool execution query was not routed") }
        if case .securityReview = HistoryQueryIntent.classify("有没有泄露隐私的风险") {} else { XCTFail("security query was not routed") }
    }

    func testHistoryAnalysisKeepsWholeTurnTogether() {
        let firstTurn = (0..<20).map { number in
            GuardEvent(kind: number.isMultiple(of: 2) ? "model" : "tool", ruleId: "fixture",
                path: "-", command: "event-\(number)", agent: "workbuddy", op: number.isMultiple(of: 2) ? "prompt" : "call",
                severity: "info", ts: Date(timeIntervalSince1970: TimeInterval(number)), action: "observed",
                sessionId: "session", turnId: "turn-1")
        }
        let nextTurn = [GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil,
            agent: "workbuddy", op: "prompt", severity: "info", ts: Date(), action: "observed",
            sessionId: "session", turnId: "turn-2")]
        let batches = SemanticAnalyzer.historyBatches(firstTurn + nextTurn)
        XCTAssertEqual(batches.count, 2)
        XCTAssertEqual(batches.map(\.count).sorted(), [1, 20])
    }

    func testRepeatedToolsCountCallsAcrossTasksAndReplaceOldFacts() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let index = try TaskSearchIndex(evidenceURL: root.appendingPathComponent("evidence.sqlite3"))
        func snapshot(_ session: String, command: String) throws -> AgentTaskSnapshot {
            let event = GuardEvent(kind: "tool", ruleId: "fixture", path: "-", command: command,
                agent: "codex", op: "call", severity: "info", ts: Date(), action: "started",
                sessionId: session, turnId: "turn", toolCallId: "call-1", toolName: "Bash")
            return AgentTaskSnapshot.build(session: try XCTUnwrap(AgentSessionSnapshot.build(from: [event]).first), turnID: "turn")
        }
        try index.upsert(snapshot: snapshot("a", command: "ls"), revision: 1)
        try index.upsert(snapshot: snapshot("b", command: "ls"), revision: 1)
        let plan = HistoryQueryUnderstanding(agent: nil, startDate: nil, endDate: nil,
            searchTerms: [], evidenceKind: nil, requiresAddressInModelInput: false, explanation: "重复操作")
        let repeated = try index.aggregate(plan).repeatedTools
        XCTAssertEqual(repeated.first?.occurrences, 2)
        XCTAssertEqual(repeated.first?.tasks, 2)
        try index.upsert(snapshot: snapshot("b", command: "pwd"), revision: 2)
        XCTAssertTrue(try index.aggregate(plan).repeatedTools.isEmpty)
    }

    func testIndexInitializationRemainsRecoverableAcrossRestart() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("evidence.sqlite3")
        do { XCTAssertTrue(try TaskSearchIndex(evidenceURL: url).newlyCreated) }
        do {
            let reopened = try TaskSearchIndex(evidenceURL: url)
            XCTAssertTrue(reopened.newlyCreated)
            try reopened.confirmBackfillInitialized()
        }
        XCTAssertFalse(try TaskSearchIndex(evidenceURL: url).newlyCreated)
    }

    func testIndexedSearchAcrossOneThousandTasks() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let index = try TaskSearchIndex(evidenceURL: root.appendingPathComponent("evidence.sqlite3"))
        for number in 0..<1_000 {
            let event = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil,
                agent: "codex", op: "prompt", severity: "info", ts: Date(), action: "sent",
                sessionId: "session-\(number)", turnId: "turn", userIntent: "任务 \(number)",
                modelPrompt: number == 500 ? "rare-needle-omega" : "ordinary task body",
                inputTokens: number == 500 ? 10_000 : 1, outputTokens: 2)
            let snapshot = AgentTaskSnapshot.build(session: try XCTUnwrap(AgentSessionSnapshot.build(from: [event]).first), turnID: "turn")
            try index.upsert(snapshot: snapshot, revision: 1)
        }
        let plan = HistoryQueryUnderstanding(agent: "codex", startDate: nil, endDate: nil,
            searchTerms: ["rare-needle-omega"], evidenceKind: nil,
            requiresAddressInModelInput: false, explanation: "稀有词")
        var timings: [Double] = []
        for _ in 0..<20 {
            let start = Date()
            XCTAssertEqual(try index.search(plan).map { $0.task.sessionID }, ["session-500"])
            timings.append(Date().timeIntervalSince(start))
        }
        let p95 = timings.sorted()[18]
        print("TASK_SEARCH_BENCHMARK tasks=1000 queries=20 warm_p95_ms=\(p95 * 1000)")
        XCTAssertLessThan(p95, 1, "Indexed lookup over small tasks exceeded one second")
        XCTAssertEqual(try index.aggregate(plan).taskCount, 1)
        let all = HistoryQueryUnderstanding(agent: "codex", startDate: nil, endDate: nil,
            searchTerms: [], evidenceKind: nil, requiresAddressInModelInput: false, explanation: "全部")
        XCTAssertEqual(try index.search(all).count, 30)
        let aggregateStart = Date()
        XCTAssertEqual(try index.aggregate(all).taskCount, 1_000)
        let ranking = try index.aggregate(all).topTokenTasks
        XCTAssertEqual(ranking.first?.sessionID, "session-500")
        XCTAssertEqual(ranking.first?.totalTokens, 10_002)
        XCTAssertEqual(ranking.count, 10)
        XCTAssertFalse(try index.search(all).contains { $0.task.sessionID == "session-500" },
            "Fixture winner must be outside the recent page to validate whole-index ranking")
        print("TASK_AGGREGATE_BENCHMARK tasks=1000 elapsed_ms=\(Date().timeIntervalSince(aggregateStart) * 1000)")
    }

    func testSearchPersistsAndReplacesRevisionWithoutSourceFiles() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("evidence.sqlite3")
        func snapshot(_ body: String) throws -> AgentTaskSnapshot {
            let event = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil,
                agent: "codex", op: "prompt", severity: "info", ts: Date(), action: "sent",
                sessionId: "session", turnId: "turn", userIntent: "部署测试", modelPrompt: body)
            return AgentTaskSnapshot.build(session: try XCTUnwrap(AgentSessionSnapshot.build(from: [event]).first), turnID: "turn")
        }
        let plan = HistoryQueryUnderstanding(agent: "codex", startDate: nil, endDate: nil,
            searchTerms: ["unique-server"], evidenceKind: "model",
            requiresAddressInModelInput: false, explanation: "查找服务器")
        do {
            let index = try TaskSearchIndex(evidenceURL: url)
            try index.upsert(snapshot: snapshot("unique-server 10.2.3.4"), revision: 1)
            XCTAssertEqual(try index.search(plan).count, 1)
        }
        let reopened = try TaskSearchIndex(evidenceURL: url)
        XCTAssertEqual(try reopened.search(plan).first?.revision, 1)
        try reopened.upsert(snapshot: snapshot("replacement body"), revision: 2)
        XCTAssertTrue(try reopened.search(plan).isEmpty)
        try reopened.upsert(snapshot: snapshot("unique-server stale body"), revision: 1)
        XCTAssertTrue(try reopened.search(plan).isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path), "Search must not require the evidence source database")
    }

    func testAddressFacetReturnsCapturedInputExcerpt() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let index = try TaskSearchIndex(evidenceURL: root.appendingPathComponent("evidence.sqlite3"))
        let event = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil,
            agent: "codex", op: "prompt", severity: "info", ts: Date(), action: "sent",
            sessionId: "session", turnId: "turn", userIntent: "检查服务", modelPrompt: "检查地址 10.2.3.4 的配置，再确认 10.2.3.4", inputTokens: 100, outputTokens: 20)
        let snapshot = AgentTaskSnapshot.build(session: try XCTUnwrap(AgentSessionSnapshot.build(from: [event]).first), turnID: "turn")
        try index.upsert(snapshot: snapshot, revision: 1)
        let plan = HistoryQueryUnderstanding(agent: "codex", startDate: nil, endDate: nil,
            searchTerms: [], evidenceKind: "model", requiresAddressInModelInput: true, explanation: "模型输入地址")
        let hits = try index.search(plan)
        XCTAssertEqual(hits.count, 1)
        XCTAssertTrue(try XCTUnwrap(hits.first).excerpt.contains("10.2.3.4"))
        try index.upsert(snapshot: snapshot, revision: 2)
        let aggregates = try index.aggregate(plan)
        XCTAssertEqual(aggregates.taskCount, 1)
        XCTAssertEqual(aggregates.agents.first?.inputTokens, 100)
        XCTAssertEqual(aggregates.agents.first?.outputTokens, 20)
        XCTAssertEqual(aggregates.modelInputAddresses.first?.occurrences, 1)
        XCTAssertEqual(aggregates.modelInputAddresses.first?.tasks, 1)
    }
}
