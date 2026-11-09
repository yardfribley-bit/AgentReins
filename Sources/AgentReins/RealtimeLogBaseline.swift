import AgentReinsCore
import Foundation

/// Records file lengths only, never reads old log bodies. Existing files begin at EOF.
enum RealtimeLogBaseline {
    /// One bounded pass. Heavy folders are not entered. A huge tree stops after
    /// a fixed number of entries so launch does not sit in `contentsOfDirectory`
    /// until the CPU breaker gives up. The live poll resumes the same cursor.
    static func offsets(root: URL) -> [String: UInt64] {
        let cursor = JSONLTreeCursor()
        var spins = 0
        while !cursor.discoveryFinished && spins < 16 {
            _ = cursor.refresh(root: root.path, now: Date(), fullInterval: 0, entryBudget: 4000)
            spins += 1
            if !cursor.discoveryFinished { Thread.sleep(forTimeInterval: 0.01) }
        }
        return cursor.sizes
    }
}
