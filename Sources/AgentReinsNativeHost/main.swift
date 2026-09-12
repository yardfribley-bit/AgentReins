import Foundation
import Darwin

private let maximumMessageBytes = 4 * 1_024 * 1_024
private let allowedExtensionOrigin = "chrome-extension://hcmoeaheokpfbbggdmkdeaiokakiampk/"
private let allowedWebAIHosts: Set<String> = ["grok.com", "gemini.google.com", "chatgpt.com", "claude.ai"]
private let isTestOutput = CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--output"

private func readExactly(_ count: Int, from input: FileHandle) throws -> Data? {
    var data = Data()
    while data.count < count {
        let chunk = try input.read(upToCount: count - data.count) ?? Data()
        if chunk.isEmpty { return data.isEmpty ? nil : data }
        data.append(chunk)
    }
    return data
}

private func writeMessage(_ object: [String: Any], to output: FileHandle) throws {
    let payload = try JSONSerialization.data(withJSONObject: object)
    var length = UInt32(payload.count).littleEndian
    try withUnsafeBytes(of: &length) { try output.write(contentsOf: Data($0)) }
    try output.write(contentsOf: payload)
}

private func appendEvidence(_ object: [String: Any]) throws -> Bool {
    guard JSONSerialization.isValidJSONObject(object), object["schemaVersion"] as? Int == 1,
          let value = object["url"] as? String,
          let host = URL(string: value)?.host?.lowercased(), allowedWebAIHosts.contains(host),
          object["eventId"] is String, object["eventType"] is String else { return false }
    let destination: URL
    if isTestOutput {
        let testPath = CommandLine.arguments[2]
        destination = URL(fileURLWithPath: testPath)
    } else {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        destination = base.appendingPathComponent("AgentGuard/web-agent-events.jsonl")
    }
    let directory = destination.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    var line = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    line.append(0x0A)
    if !FileManager.default.fileExists(atPath: destination.path) {
        FileManager.default.createFile(atPath: destination.path, contents: nil)
    }
    let handle = try FileHandle(forWritingTo: destination)
    guard flock(handle.fileDescriptor, LOCK_EX) == 0 else {
        try? handle.close()
        throw POSIXError(.EWOULDBLOCK)
    }
    defer {
        flock(handle.fileDescriptor, LOCK_UN)
        try? handle.close()
    }
    try handle.seekToEnd()
    try handle.write(contentsOf: line)
    try handle.synchronize()
    return true
}

let input = FileHandle.standardInput
let output = FileHandle.standardOutput

if !isTestOutput && !CommandLine.arguments.dropFirst().contains(allowedExtensionOrigin) {
    exit(3)
}

while let header = try readExactly(4, from: input), header.count == 4 {
    let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
    guard length > 0, length <= maximumMessageBytes,
          let payload = try readExactly(Int(length), from: input), payload.count == Int(length),
          let object = try JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        try writeMessage(["ok": false, "error": "invalid_message"], to: output)
        continue
    }
    let accepted = try appendEvidence(object)
    try writeMessage(accepted
        ? ["ok": true, "eventId": object["eventId"] ?? NSNull()]
        : ["ok": false, "error": "evidence_not_allowed"], to: output)
}
