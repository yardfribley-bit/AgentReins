import Foundation

enum RuntimeRelationshipKind: String, Codable, Sendable {
    case processParent = "Process parent"
    case control = "Control channel"
    case sharedRuntime = "Shared runtime"
}

struct RuntimeRelationship: Identifiable, Equatable, Sendable {
    let id: String
    let sourcePID: String
    let targetPID: String
    let kind: RuntimeRelationshipKind
    let confidence: EvidenceConfidence
    let evidence: String
}

struct AgentRuntimeGraph: Equatable, Sendable {
    let processes: [ProcessSnapshotRecord]
    let relationships: [RuntimeRelationship]

    static func build(processes: [ProcessSnapshotRecord], agent: String?) -> AgentRuntimeGraph {
        let ids = Set(processes.map(\.pid))
        var edges = processes.compactMap { child -> RuntimeRelationship? in
            guard ids.contains(child.ppid) else { return nil }
            return RuntimeRelationship(id: "parent:\(child.ppid):\(child.pid)", sourcePID: child.ppid,
                targetPID: child.pid, kind: .processParent, confidence: .confirmed,
                evidence: "Observed operating-system PPID \(child.ppid)")
        }

        if agent?.lowercased().contains("workbuddy") == true {
            let classified = processes.map { ($0, AgentRuntimeProfileRegistry.classify($0, agentHint: "WorkBuddy")) }
            let sandbox = classified.first { $0.1.componentId == "sandbox" }
            let runtimes = classified.filter {
                ["workbuddy-active-agent", "workbuddy-prewarm-pool"].contains($0.1.componentId)
            }
            if let sandbox {
                for runtime in runtimes where !edges.contains(where: {
                    $0.sourcePID == runtime.0.pid && $0.targetPID == sandbox.0.pid
                }) {
                    edges.append(RuntimeRelationship(id: "runtime:\(runtime.0.pid):\(sandbox.0.pid)",
                        sourcePID: runtime.0.pid, targetPID: sandbox.0.pid,
                        kind: .sharedRuntime, confidence: .inferred,
                        evidence: "Both binaries belong to WorkBuddy and declare the same ~/.workbuddy application home; no PPID relationship is claimed"))
                }
            }
        }
        return AgentRuntimeGraph(processes: processes, relationships: edges.sorted { $0.id < $1.id })
    }
}
