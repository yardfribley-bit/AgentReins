import AgentReinsPeerIdent
import Darwin
import Foundation

/// Kernel identity of the process that owns the client side of a loopback TCP connection.
struct PeerIdentity {
    var pid: Int32
    var uid: UInt32
    var path: String
    var exeBase: String

    static func lookup(clientPort: UInt16, serverPort: UInt16, cancelled: () -> Bool = { false }) -> PeerIdentity? {
        // The accepted socket is sometimes invisible to libproc for a few milliseconds.
        // Stop early when the client has already gone away so a dead connection cannot sit on a worker.
        for attempt in 0..<8 {
            if cancelled() { return nil }
            if let peer = lookupOnce(clientPort: clientPort, serverPort: serverPort) {
                return peer
            }
            if attempt < 7 {
                if cancelled() { return nil }
                Thread.sleep(forTimeInterval: 0.02)
            }
        }
        return nil
    }

    private static func lookupOnce(clientPort: UInt16, serverPort: UInt16) -> PeerIdentity? {
        var pid: Int32 = 0
        var uid: UInt32 = 0
        let cap = 1024
        let buf = UnsafeMutablePointer<CChar>.allocate(capacity: cap)
        buf.initialize(repeating: 0, count: cap)
        defer {
            buf.deinitialize(count: cap)
            buf.deallocate()
        }
        let rc = agentreins_lookup_tcp_peer(clientPort, serverPort, &pid, &uid, buf, Int32(cap))
        guard rc == 1, pid > 0 else { return nil }
        let path = String(cString: buf)
        let base = (path as NSString).lastPathComponent
        return PeerIdentity(pid: pid, uid: uid, path: path, exeBase: base.isEmpty ? "unknown" : base)
    }

    static func processAlive(_ pid: Int32) -> Bool {
        if pid <= 0 { return false }
        if kill(pid, 0) == 0 { return true }
        return errno == EPERM
    }
}
