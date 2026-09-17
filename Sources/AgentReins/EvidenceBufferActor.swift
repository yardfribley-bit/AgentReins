import Foundation

struct EvidenceBufferSnapshot: Equatable, Sendable {
    let bufferedEvents: Int
    let oldestEventAge: TimeInterval?
    let flushCount: Int
    let failedFlushCount: Int
    let lastFlushDuration: TimeInterval?
}

/// The single write buffer in front of normalized evidence persistence.
/// Collectors can enqueue without waiting for SQLite; the actor serializes
/// batches and keeps a failed batch in memory for a later retry.
actor EvidenceBufferActor {
    static let maximumBatchSize = 50
    // Keep a safety margin below the public two-second durability SLO so
    // scheduler jitter cannot push an ordinary batch past the deadline.
    static let maximumDelay: TimeInterval = 1.5

    private let database: EvidenceDatabase
    private var pending: [GuardEvent] = []
    private var oldestEnqueuedAt: Date?
    private var scheduledFlush: Task<Void, Never>?
    private var flushCount = 0
    private var failedFlushCount = 0
    private var lastFlushDuration: TimeInterval?

    init(database: EvidenceDatabase) {
        self.database = database
    }

    deinit { scheduledFlush?.cancel() }

    func enqueue(_ events: [GuardEvent], urgent: Bool = false) async {
        guard !events.isEmpty else { return }
        if pending.isEmpty { oldestEnqueuedAt = Date() }
        pending.append(contentsOf: events)

        if urgent || pending.count >= Self.maximumBatchSize {
            await flush()
        } else {
            scheduleFlushIfNeeded()
        }
    }

    func flush() async {
        scheduledFlush?.cancel()
        scheduledFlush = nil
        guard !pending.isEmpty else { return }

        let batch = pending
        pending.removeAll(keepingCapacity: true)
        oldestEnqueuedAt = nil
        let started = Date()
        do {
            try database.append(batch)
            flushCount += 1
            lastFlushDuration = Date().timeIntervalSince(started)
        } catch {
            // Never acknowledge a failed batch. Put it back ahead of newer
            // evidence so time order is retained and retry with bounded delay.
            pending.insert(contentsOf: batch, at: 0)
            oldestEnqueuedAt = oldestEnqueuedAt ?? Date()
            failedFlushCount += 1
            lastFlushDuration = Date().timeIntervalSince(started)
            scheduleFlushIfNeeded(delay: min(10, Self.maximumDelay * Double(failedFlushCount + 1)))
        }
    }

    func snapshot(now: Date = Date()) -> EvidenceBufferSnapshot {
        EvidenceBufferSnapshot(
            bufferedEvents: pending.count,
            oldestEventAge: oldestEnqueuedAt.map { max(0, now.timeIntervalSince($0)) },
            flushCount: flushCount,
            failedFlushCount: failedFlushCount,
            lastFlushDuration: lastFlushDuration)
    }

    private func scheduleFlushIfNeeded(delay: TimeInterval = maximumDelay) {
        guard scheduledFlush == nil else { return }
        scheduledFlush = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else { return }
            await self?.flush()
        }
    }
}
