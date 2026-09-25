import Foundation

/// One bounded slice; active agents reduce throughput, never disable indexing.
enum TaskSearchPump {
    static func delayMilliseconds(active: Bool, worked: Bool) -> Int {
        worked ? (active ? 500 : 200) : 2_000
    }

    static func step(database: EvidenceDatabase, index: TaskSearchIndex,
                     active: Bool, initialize: Bool) throws -> Bool {
        if initialize {
            try database.restartTaskSearchBackfill()
            try index.confirmBackfillInitialized()
        }
        if let job = try database.nextTaskSearchJob() {
            guard let snapshot = try database.taskSnapshot(sessionID: job.sessionID, turnID: job.turnID) else {
                throw NSError(domain: "TaskSearchPump", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "索引工作缺少已解析任务快照，等待投影恢复"])
            }
            try index.upsert(snapshot: snapshot, revision: job.revision)
            try database.completeTaskSearchJob(job)
            return true
        }
        // Rebuild from saved projections only. Busy machines still make bounded progress.
        return !(try database.enqueueTaskSearchBackfill(limit: active ? 1 : 25))
    }
}
