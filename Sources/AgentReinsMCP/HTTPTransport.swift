import AgentReinsCore
import Darwin
import Foundation
import Network

/// Loopback-only Streamable HTTP MCP. JSON responses; no SSE.
/// Bind is `127.0.0.1` only — never `0.0.0.0`, never IPv6.
enum HTTPTransport {
    static let maxBody = 1_048_576
    static let maxHeader = 65_536
    static let maxConnections = 16
    static let idleSeconds: TimeInterval = 30

    static func run(port: Int, requireToken: Bool) -> Never {
        let auth: String
        let token: String?
        if requireToken {
            guard let loaded = loadToken() else {
                log("AgentReinsMCP: --require-token set but \(tokenURL().path) is missing or empty")
                exit(3)
            }
            token = loaded
            auth = "bearer"
        } else {
            token = nil
            auth = "none"
        }

        // Serial queue: accept, connection count, listener state, writes to a connection.
        // Tool work runs on `work` so one slow call cannot block initialize on another connection.
        let queue = DispatchQueue(label: "com.agentreins.mcp-http")
        let work = DispatchQueue(label: "com.agentreins.mcp-http.work", attributes: .concurrent)
        let state = ServerState(port: port, auth: auth, token: token, queue: queue, work: work)
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            log("AgentReinsMCP: invalid port \(port)")
            exit(2)
        }

        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = false
        params.includePeerToPeer = false
        params.acceptLocalOnly = true
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: nwPort)
        if let ip = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.version = .v4
        }

        let listener: NWListener
        do {
            listener = try NWListener(using: params)
        } catch {
            log("AgentReinsMCP: failed to create listener: \(error)")
            EndpointDiscovery.write(state: "failed", port: port, auth: auth, detail: "\(error)")
            exit(1)
        }
        // No Bonjour / mDNS.
        listener.service = nil

        // Bind before any process listing. Reaping used to call /bin/ps and
        // waitUntilExit without draining the pipe, so ps blocked forever and
        // this process never listened. The port has to be up even if reap is slow.
        installSignals(queue: queue)
        listener.stateUpdateHandler = { listenerState in
            state.onListener(listenerState, listener: listener)
        }
        listener.newConnectionHandler = { conn in
            state.accept(conn)
        }
        listener.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 3) {
            if !state.settled {
                state.settled = true
                state.fail(state: "failed", detail: "listener did not become ready")
            }
        }
        state.startPortWatchdog()
        HTTPProcessGuard.reapAsync(port: port)
        dispatchMain()
    }

    /// Launchd StartInterval entry. If this port's `--http` process is alive and
    /// old enough but nothing is accepting, signal it so KeepAlive starts a new one.
    static func healthCheck(port: Int) {
        let rows = ProcessTable.snapshot()
        var procs: [MCPHTTPOrphans.Proc] = []
        var started: [Int32: Date] = [:]
        for row in rows where (row.path as NSString).lastPathComponent == "AgentReinsMCP" {
            let command = ProcessTable.commandLine(row.pid)
            let text = command.isEmpty ? row.path : command
            procs.append(.init(pid: row.pid, ppid: row.ppid, command: text))
            started[row.pid] = row.startedAt
        }
        let listening = portAccepts(port)
        let launchd = launchdStatusText()
        let victims = MCPHTTPOrphans.healthVictims(
            procs, port: port, portListening: listening, now: Date(), startedAt: started,
            minimumAge: MCPHTTPOrphans.healthGrace(launchdText: launchd))
        let lines = MCPHTTPOrphans.healthLogLines(victims: victims, port: port, launchdText: launchd)
        for pid in victims {
            kill(pid, SIGTERM)
        }
        // healthLogLines is empty when the only launchd fact is kickstart's -9.
        for line in lines {
            log(line)
        }
    }

    /// launchctl print of the HTTP job. Empty when launchd has no such service.
    /// stderr from launchctl is discarded so a missing service is not an error line.
    private static func launchdStatusText() -> String {
        let label = "gui/\(getuid())/com.agentreins.mcp-http"
        return BoundedProcess.run("/bin/launchctl", arguments: ["print", label], timeout: 2)
    }

    static func portAccepts(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port)).bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        if rc == 0 { return true }
        if errno != EINPROGRESS && errno != EAGAIN { return false }
        var ready = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        if poll(&ready, 1, 400) <= 0 { return false }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
        return err == 0
    }

    static func tokenURL() -> URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_MCP_TOKEN_FILE"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return Paths.support.appendingPathComponent("mcp-http.token")
    }

    static func loadToken() -> String? {
        guard let text = try? String(contentsOf: tokenURL(), encoding: .utf8) else { return nil }
        let token = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return token.isEmpty ? nil : token
    }

    private static func installSignals(queue: DispatchQueue) {
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        for sig in [SIGTERM, SIGINT] {
            let source = DispatchSource.makeSignalSource(signal: sig, queue: queue)
            source.setEventHandler {
                EndpointDiscovery.removeIfOwned()
                exit(0)
            }
            source.resume()
        }
    }

    private static func log(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}

private final class PortMisses {
    var value = 0
}

private final class ServerState {
    let port: Int
    let auth: String
    let token: String?
    let queue: DispatchQueue
    let work: DispatchQueue
    let requestTimeout: TimeInterval
    var active = 0
    var settled = false
    let sessions: SessionTable
    var listening = false

    init(port: Int, auth: String, token: String?, queue: DispatchQueue, work: DispatchQueue) {
        self.port = port
        self.auth = auth
        self.token = token
        self.queue = queue
        self.work = work
        self.requestTimeout = Self.envDouble("AGENTREINS_MCP_REQUEST_TIMEOUT_SECONDS", 12)
        self.sessions = SessionTable(
            maxSessions: Self.envInt("AGENTREINS_MCP_MAX_SESSIONS", 64),
            ttl: Self.envDouble("AGENTREINS_MCP_SESSION_TTL_SECONDS", 30 * 60))
    }

    static func envDouble(_ key: String, _ fallback: Double) -> Double {
        guard let raw = ProcessInfo.processInfo.environment[key], let value = Double(raw), value > 0 else { return fallback }
        return value
    }

    static func envInt(_ key: String, _ fallback: Int) -> Int {
        guard let raw = ProcessInfo.processInfo.environment[key], let value = Int(raw), value > 0 else { return fallback }
        return value
    }

    func onListener(_ state: NWListener.State, listener: NWListener) {
        switch state {
        case .ready:
            guard !settled else { return }
            settled = true
            if let bound = listener.port?.rawValue, bound != UInt16(port) {
                fail(state: "failed", detail: "listener bound \(bound), requested \(port)")
                return
            }
            let listing = Self.lsofListen(port)
            if !Self.loopbackOnly(listing, port: port) {
                let detail = listing.isEmpty ? "lsof showed no 127.0.0.1 listener" : listing
                fail(state: "not_loopback", detail: detail)
                return
            }
            listening = true
            EndpointDiscovery.write(state: "listening", port: port, auth: auth)
            HTTPTransportLog.write("AgentReinsMCP listening on http://127.0.0.1:\(port)/mcp auth=\(auth)")
        case .failed(let error):
            guard !settled else { return }
            settled = true
            let listing = Self.lsofListen(port)
            if Self.isAddrInUse(error) {
                let detail = listing.isEmpty ? "\(error)" : listing
                EndpointDiscovery.write(state: "port_in_use", port: port, auth: auth, detail: detail)
                HTTPTransportLog.write("AgentReinsMCP: port \(port) is already in use (state=port_in_use)\n\(detail)")
                exit(1)
            }
            fail(state: "failed", detail: "\(error)\n\(listing)")
        case .waiting(let error):
            if Self.isAddrInUse(error) {
                guard !settled else { return }
                settled = true
                let listing = Self.lsofListen(port)
                EndpointDiscovery.write(state: "port_in_use", port: port, auth: auth, detail: listing.isEmpty ? "\(error)" : listing)
                HTTPTransportLog.write("AgentReinsMCP: port \(port) is already in use (state=port_in_use)\n\(listing)")
                exit(1)
            }
        default:
            break
        }
    }

    func fail(state: String, detail: String) {
        EndpointDiscovery.write(state: state, port: port, auth: auth, detail: detail)
        HTTPTransportLog.write("AgentReinsMCP: exiting (\(state)) \(detail)")
        exit(1)
    }

    /// The process can stay in dispatchMain after the listener stops accepting.
    /// Two failed connects in a row exit so launchd KeepAlive starts a new process.
    func startPortWatchdog() {
        let misses = PortMisses()
        func tick() {
            queue.asyncAfter(deadline: .now() + 15) { [weak self] in
                guard let self else { return }
                guard self.settled, self.listening else { tick(); return }
                if HTTPTransport.portAccepts(self.port) {
                    misses.value = 0
                } else {
                    misses.value += 1
                    if misses.value >= 2 {
                        self.fail(state: "not_listening", detail: "process alive but 127.0.0.1:\(self.port) is not accepting")
                        return
                    }
                }
                tick()
            }
        }
        tick()
    }

    func accept(_ conn: NWConnection) {
        if active >= HTTPTransport.maxConnections {
            conn.cancel()
            return
        }
        active += 1
        let box = ConnectionBox()
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard !box.started else { return }
                box.started = true
                if !self.localIsLoopback(conn) {
                    self.release(conn, box: box)
                    return
                }
                self.serve(conn, box: box)
            case .failed, .cancelled:
                box.markCancelled()
                self.release(conn, box: box)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    func release(_ conn: NWConnection, box: ConnectionBox) {
        if !box.released {
            box.released = true
            active = max(0, active - 1)
        }
        conn.cancel()
    }

    func localIsLoopback(_ conn: NWConnection) -> Bool {
        guard let endpoint = conn.currentPath?.localEndpoint else { return true }
        guard case .hostPort(let host, _) = endpoint else { return false }
        switch host {
        case .ipv4(let addr):
            return addr == .loopback
        case .name(let name, _):
            return name == "127.0.0.1" || name == "localhost"
        default:
            return false
        }
    }

    func clientPort(_ conn: NWConnection) -> UInt16? {
        func port(of endpoint: NWEndpoint?) -> UInt16? {
            guard let endpoint, case .hostPort(_, let value) = endpoint else { return nil }
            return value.rawValue
        }
        let local = port(of: conn.currentPath?.localEndpoint)
        let remote = port(of: conn.currentPath?.remoteEndpoint) ?? port(of: conn.endpoint)
        let listen = UInt16(self.port)
        // Prefer the side that is not our listen port (the client's ephemeral port).
        if let remote, remote != listen { return remote }
        if let local, local != listen { return local }
        return remote ?? local
    }

    func serve(_ conn: NWConnection, box: ConnectionBox) {
        var buffer = Data()
        var idle: DispatchWorkItem?
        let arm: () -> Void = {
            idle?.cancel()
            let work = DispatchWorkItem { conn.cancel() }
            idle = work
            self.queue.asyncAfter(deadline: .now() + HTTPTransport.idleSeconds, execute: work)
        }
        let sendAndClose: (Data) -> Void = { bytes in
            idle?.cancel()
            guard box.claimSend() else { return }
            conn.send(content: bytes, completion: .contentProcessed { _ in
                conn.cancel()
            })
        }
        func pump() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
                if box.shouldStop() {
                    conn.cancel()
                    return
                }
                if let data, !data.isEmpty { buffer.append(data) }
                switch HTTPCodec.pull(buffer, maxBody: HTTPTransport.maxBody, maxHeader: HTTPTransport.maxHeader) {
                case .needMore:
                    if isComplete || error != nil {
                        box.markCancelled()
                        conn.cancel()
                        return
                    }
                    pump()
                case .fail(let status, let reason, let errorName):
                    sendAndClose(HTTPCodec.encode(status: status, reason: reason,
                                                  headers: ["Content-Type": "application/json; charset=utf-8",
                                                            "Cache-Control": "no-store"],
                                                  body: HTTPCodec.jsonBody(["error": errorName])))
                case .ready(let message):
                    idle?.cancel()
                    self.dispatch(conn, box: box, message: message)
                }
            }
        }
        arm()
        pump()
    }

    /// Body is in hand. Further work (peer lookup, tool call) runs off the accept queue.
    /// A second receive watches for the client going away so the worker can stop.
    func dispatch(_ conn: NWConnection, box: ConnectionBox, message: HTTPMessage) {
        box.requestId = Self.requestId(message.body)
        box.sessionHeader = message.headers["mcp-session-id"]
        let peerPort = clientPort(conn)
        let local = String(describing: conn.currentPath?.localEndpoint)
        let remote = String(describing: conn.currentPath?.remoteEndpoint)
        armDisconnectWatch(conn, box: box)
        let timeout = DispatchWorkItem { [weak box] in
            guard let box, box.claimSend() else { return }
            box.markTimedOut()
            let body = HTTPCodec.jsonBody(MCPDispatcher.rpcError(
                box.requestId, -32000,
                "request timed out; tool read was stopped so this call would not hang until the client abandoned it. Evidence was not modified."))
            var headers = [
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            ]
            if let sid = box.sessionHeader, !sid.isEmpty { headers["Mcp-Session-Id"] = sid }
            let bytes = HTTPCodec.encode(status: 200, reason: "OK", headers: headers, body: body)
            conn.send(content: bytes, completion: .contentProcessed { _ in
                conn.cancel()
            })
        }
        box.timeout = timeout
        queue.asyncAfter(deadline: .now() + requestTimeout, execute: timeout)
        let port = self.port
        work.async { [weak self] in
            guard let self else { return }
            let abandon = {
                self.queue.async {
                    box.timeout?.cancel()
                    HTTPTransportLog.write("AgentReinsMCP: request abandoned")
                    conn.cancel()
                }
            }
            if box.wasCancelled() { abandon(); return }
            if box.shouldStop() { return }
            let peer = peerPort.flatMap {
                PeerIdentity.lookup(clientPort: $0, serverPort: UInt16(port), cancelled: { box.shouldStop() })
            }
            if box.wasCancelled() { abandon(); return }
            if box.shouldStop() { return }
            if peer == nil {
                HTTPTransportLog.write("AgentReinsMCP: peer lookup failed clientPort=\(peerPort.map(String.init) ?? "?") local=\(local) remote=\(remote)")
            }
            let response = self.route(message, peer: peer, isCancelled: { box.shouldStop() })
            self.queue.async {
                box.timeout?.cancel()
                if box.wasCancelled() { abandon(); return }
                if box.shouldStop() { return }
                guard box.claimSend() else { return }
                conn.send(content: response, completion: .contentProcessed { _ in
                    conn.cancel()
                })
            }
        }
    }

    func armDisconnectWatch(_ conn: NWConnection, box: ConnectionBox) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 1024) { _, _, isComplete, error in
            if isComplete || error != nil {
                box.markCancelled()
                return
            }
            if !box.shouldStop() { self.armDisconnectWatch(conn, box: box) }
        }
    }

    static func requestId(_ body: Data) -> Any {
        guard let obj = try? JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed]) as? [String: Any],
              obj.keys.contains("id") else { return NSNull() }
        return obj["id"] ?? NSNull()
    }

    func route(_ message: HTTPMessage, peer: PeerIdentity?, isCancelled: @escaping () -> Bool = { false }) -> Data {
        let jsonHeaders = [
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        ]
        func json(_ status: Int, _ reason: String, _ obj: [String: Any], extra: [String: String] = [:]) -> Data {
            var headers = jsonHeaders
            for (k, v) in extra { headers[k] = v }
            return HTTPCodec.encode(status: status, reason: reason, headers: headers, body: HTTPCodec.jsonBody(obj))
        }
        func empty(_ status: Int, _ reason: String, extra: [String: String] = [:]) -> Data {
            var headers = ["Cache-Control": "no-store"]
            for (k, v) in extra { headers[k] = v }
            return HTTPCodec.encode(status: status, reason: reason, headers: headers, body: Data())
        }

        if !Self.hostAllowed(message.headers["host"], port: port) {
            return json(403, "Forbidden", ["error": "host_rejected"])
        }
        if !Self.originAllowed(message.headers["origin"]) {
            return json(403, "Forbidden", ["error": "origin_rejected"])
        }
        guard let peer else {
            return json(403, "Forbidden", ["error": "peer_unidentified"])
        }
        if peer.uid != UInt32(getuid()) {
            return json(403, "Forbidden", ["error": "peer_forbidden"])
        }

        if message.method == "GET" && message.path == "/healthz" {
            return json(200, "OK", ["ok": true, "version": MCPDispatcher.serverVersion])
        }
        if message.path != "/mcp" {
            return json(404, "Not Found", ["error": "not_found"])
        }
        if message.method == "GET" {
            return json(405, "Method Not Allowed", ["error": "sse_not_supported"], extra: ["Allow": "POST, DELETE"])
        }
        if message.method == "OPTIONS" {
            return json(403, "Forbidden", ["error": "origin_rejected"])
        }
        if message.method == "DELETE" {
            guard let sid = message.headers["mcp-session-id"], !sid.isEmpty else {
                return json(400, "Bad Request", ["error": "session_required"])
            }
            guard sessions.remove(sid) else {
                return json(404, "Not Found", MCPDispatcher.rpcError(NSNull(), -32001, "session not found"))
            }
            return empty(204, "No Content")
        }
        if message.method != "POST" {
            return json(405, "Method Not Allowed", ["error": "method_not_allowed"], extra: ["Allow": "POST, DELETE"])
        }
        if message.headers["content-length"] == nil {
            return json(411, "Length Required", ["error": "length_required"])
        }
        if !Self.isJSON(message.headers["content-type"]) {
            return json(415, "Unsupported Media Type", ["error": "content_type"])
        }
        if let token {
            guard Self.authorized(message.headers["authorization"], token: token) else {
                return json(401, "Unauthorized", ["error": "unauthorized"], extra: ["WWW-Authenticate": "Bearer"])
            }
        }
        if let proto = message.headers["mcp-protocol-version"], !MCPDispatcher.supportedProtocols.contains(proto) {
            return json(400, "Bad Request", ["error": "unsupported_protocol_version"])
        }

        let parsed: Any
        do {
            parsed = try JSONSerialization.jsonObject(with: message.body, options: [.fragmentsAllowed])
        } catch {
            return json(400, "Bad Request", MCPDispatcher.rpcError(NSNull(), -32700, "parse error"))
        }
        // Dictionary first: an NSDictionary must not be treated as a batch array.
        guard let obj = parsed as? [String: Any] else {
            if parsed as? [Any] != nil {
                return json(400, "Bad Request", MCPDispatcher.rpcError(NSNull(), -32600, "JSON-RPC batch is not supported"))
            }
            return json(400, "Bad Request", MCPDispatcher.rpcError(NSNull(), -32600, "invalid request"))
        }

        let method = obj["method"] as? String ?? ""
        let isInitialize = method == "initialize"
        let session: MCPSession
        if isInitialize {
            guard let created = sessions.create() else {
                return json(503, "Service Unavailable", ["error": "too_many_sessions"])
            }
            session = created
        } else {
            guard let sid = message.headers["mcp-session-id"], !sid.isEmpty else {
                return json(400, "Bad Request", ["error": "session_required"])
            }
            guard let existing = sessions.get(sid) else {
                return json(404, "Not Found", MCPDispatcher.rpcError(obj["id"] ?? NSNull(), -32001, "session not found"))
            }
            session = existing
        }

        if isCancelled() { return Data() }
        let reply = MCPDispatcher.handle(obj, session: session, auditActor: session.auditActor(peer: peer),
                                         auditSync: false, isCancelled: isCancelled)
        var extra = [
            "Mcp-Session-Id": session.id,
            "MCP-Protocol-Version": session.protocolVersion,
        ]
        if reply == nil {
            return empty(202, "Accepted", extra: extra)
        }
        for (k, v) in jsonHeaders { extra[k] = v }
        return HTTPCodec.encode(status: 200, reason: "OK", headers: extra, body: HTTPCodec.jsonBody(reply ?? [:]))
    }

    static func hostAllowed(_ host: String?, port: Int) -> Bool {
        guard let host else { return false }
        let value = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return value == "127.0.0.1:\(port)" || value == "localhost:\(port)"
    }

    static func originAllowed(_ origin: String?) -> Bool {
        guard let origin else { return true }
        let value = origin.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.isEmpty || value.lowercased() == "null" { return true }
        guard let url = URL(string: value), let host = url.host?.lowercased() else { return false }
        return host == "127.0.0.1" || host == "localhost"
    }

    static func isJSON(_ contentType: String?) -> Bool {
        guard let contentType else { return false }
        let base = contentType.split(separator: ";").first?
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        return base == "application/json"
    }

    static func authorized(_ header: String?, token: String) -> Bool {
        guard let header else { return false }
        let parts = header.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard parts.count == 2, parts[0].lowercased() == "bearer" else { return false }
        return constantTimeEqual(String(parts[1]), token)
    }

    static func isAddrInUse(_ error: NWError) -> Bool {
        if case .posix(let code) = error, code == .EADDRINUSE { return true }
        let text = String(describing: error).lowercased()
        return text.contains("address already in use") || text.contains("eaddrinuse")
    }

    static func lsofListen(_ port: Int) -> String {
        let url = URL(fileURLWithPath: "/usr/sbin/lsof")
        guard FileManager.default.isExecutableFile(atPath: url.path) else { return "" }
        var last = ""
        for _ in 0..<4 {
            last = BoundedProcess.run(url.path, arguments: ["-nP", "-iTCP:\(port)", "-sTCP:LISTEN"], timeout: 1.5)
            if last.contains("LISTEN") { return last }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return last
    }

    /// Every LISTEN row must be 127.0.0.1:<port>. Empty output is not proof.
    static func loopbackOnly(_ listing: String, port: Int) -> Bool {
        let rows = listing.split(separator: "\n").map(String.init).filter { $0.contains("LISTEN") }
        guard !rows.isEmpty else { return false }
        let needle = "127.0.0.1:\(port)"
        for row in rows {
            if !row.contains(needle) { return false }
            if row.contains("*:\(port)") || row.contains("[::]") || row.contains("::1:\(port)") { return false }
        }
        return true
    }
}

private final class ConnectionBox {
    let lock = NSLock()
    var started = false
    var released = false
    var requestId: Any = NSNull()
    var sessionHeader: String?
    var timeout: DispatchWorkItem?
    private var cancelled = false
    private var timedOut = false
    private var finished = false

    func markCancelled() {
        lock.lock(); cancelled = true; lock.unlock()
        timeout?.cancel()
    }

    func markTimedOut() {
        lock.lock(); timedOut = true; lock.unlock()
    }

    func wasCancelled() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    func shouldStop() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled || timedOut || finished
    }

    /// First caller sends the response. A timeout, a disconnect, or a finished call loses.
    func claimSend() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if finished || cancelled || timedOut { return false }
        finished = true
        return true
    }
}

/// Idle sessions expire. When the table is full, the least recently used session is evicted
/// so a client that initializes and never DELETEs cannot pin the process at 503.
private final class SessionTable {
    struct Entry {
        var session: MCPSession
        var lastUsed: Date
    }

    let maxSessions: Int
    let ttl: TimeInterval
    let now: () -> Date
    private let lock = NSLock()
    private var sessions: [String: Entry] = [:]
    private var order: [String] = []

    init(maxSessions: Int = 64, ttl: TimeInterval = 30 * 60, now: @escaping () -> Date = { Date() }) {
        self.maxSessions = max(1, maxSessions)
        self.ttl = ttl
        self.now = now
    }

    func create() -> MCPSession? {
        lock.lock(); defer { lock.unlock() }
        evictExpiredLocked(now())
        if sessions.count >= maxSessions, let oldest = order.first {
            sessions.removeValue(forKey: oldest)
            order.removeFirst()
        }
        if sessions.count >= maxSessions { return nil }
        let session = MCPSession(id: UUID().uuidString.lowercased(), transport: "http")
        sessions[session.id] = Entry(session: session, lastUsed: now())
        order.append(session.id)
        return session
    }

    func get(_ id: String) -> MCPSession? {
        lock.lock(); defer { lock.unlock() }
        let moment = now()
        evictExpiredLocked(moment)
        guard var entry = sessions[id] else { return nil }
        entry.lastUsed = moment
        sessions[id] = entry
        if let index = order.firstIndex(of: id) { order.remove(at: index) }
        order.append(id)
        return entry.session
    }

    @discardableResult
    func remove(_ id: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        evictExpiredLocked(now())
        return removeLocked(id)
    }

    private func evictExpiredLocked(_ moment: Date) {
        let stale = sessions.compactMap { moment.timeIntervalSince($0.value.lastUsed) > ttl ? $0.key : nil }
        for id in stale { removeLocked(id) }
    }

    private func removeLocked(_ id: String) -> Bool {
        let removed = sessions.removeValue(forKey: id) != nil
        if let index = order.firstIndex(of: id) { order.remove(at: index) }
        return removed
    }
}

/// Stops leftover AgentReinsMCP processes before this one binds 127.0.0.1.
/// Same-port `--http` processes that are not the listener, and stdio workers
/// whose client has died (ppid 1), are signaled. A listener on this port is left
/// alone so the existing port_in_use exit still applies. Other ports are left alone.
private enum HTTPProcessGuard {
    /// Does not block the caller. Listing is in-process. A fixture, or a last-resort
    /// `/bin/ps`, is read with a hard timeout that kills the child.
    static func reapAsync(port: Int) {
        DispatchQueue.global(qos: .utility).async {
            let done = reap(port: port)
            if !done.isEmpty {
                HTTPTransportLog.write("AgentReinsMCP: reaped \(done.count) orphan process(es): \(done.map(String.init).joined(separator: ","))")
            }
        }
    }

    static func reap(port: Int) -> [Int32] {
        let listing = ServerState.lsofListen(port)
        let listeners = MCPHTTPOrphans.listenerPIDs(lsof: listing)
        let procs = MCPHTTPOrphans.parsePS(processText())
        let selfPid = ProcessInfo.processInfo.processIdentifier
        let victims = MCPHTTPOrphans.reapPIDs(procs, selfPid: selfPid, port: port, listenerPIDs: listeners)
        let dry = ProcessInfo.processInfo.environment["AGENTREINS_MCP_REAP_DRY_RUN"] == "1"
        var done: [Int32] = []
        for pid in victims where pid != selfPid {
            if dry {
                HTTPTransportLog.write("AgentReinsMCP: orphan http pid=\(pid) not listening; dry-run")
                done.append(pid)
                continue
            }
            let command = commandText(pid)
            guard MCPHTTPOrphans.isAgentReinsMCP(command) else { continue }
            let legacy = MCPHTTPOrphans.isLegacyBundle(command)
            let samePort = MCPHTTPOrphans.isHTTPServerCommand(command)
                && MCPHTTPOrphans.commandTargetsPort(command, port: port)
            let abandonedStdio = !MCPHTTPOrphans.isHTTPServerCommand(command)
            guard samePort || abandonedStdio || legacy else { continue }
            kill(pid, SIGTERM)
            done.append(pid)
            HTTPTransportLog.write("AgentReinsMCP: reaped orphan http pid=\(pid)")
        }
        if !dry && !done.isEmpty {
            Thread.sleep(forTimeInterval: 0.3)
            for pid in done where pid != selfPid && PeerIdentity.processAlive(pid) {
                kill(pid, SIGKILL)
            }
        }
        return done
    }

    private static func processText() -> String {
        if let path = ProcessInfo.processInfo.environment["AGENTREINS_MCP_PS_FIXTURE"], !path.isEmpty,
           let text = try? String(contentsOfFile: path, encoding: .utf8) {
            return text
        }
        let rows = ProcessTable.snapshot()
        var lines: [String] = []
        for row in rows where (row.path as NSString).lastPathComponent == "AgentReinsMCP" {
            let command = ProcessTable.commandLine(row.pid)
            let text = command.isEmpty ? row.path : command
            lines.append("\(row.pid) \(row.ppid) \(text)")
        }
        if !lines.isEmpty { return lines.joined(separator: "\n") }
        // Last resort. Drained while running, and killed if it has not exited in 2.5s.
        return BoundedProcess.run("/bin/ps", arguments: ["-ax", "-o", "pid=,ppid=,command="], timeout: 2.5)
    }

    private static func commandText(_ pid: Int32) -> String {
        if ProcessInfo.processInfo.environment["AGENTREINS_MCP_PS_FIXTURE"] != nil {
            let procs = MCPHTTPOrphans.parsePS(processText())
            return procs.first { $0.pid == pid }?.command ?? ""
        }
        let command = ProcessTable.commandLine(pid)
        if !command.isEmpty { return command }
        return BoundedProcess.run("/bin/ps", arguments: ["-p", String(pid), "-o", "command="], timeout: 2.5)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private enum HTTPTransportLog {
    static func write(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}

struct HTTPMessage {
    var method: String
    var path: String
    var headers: [String: String]
    var body: Data
}

enum HTTPCodec {
    enum Pull {
        case needMore
        case fail(Int, String, String)
        case ready(HTTPMessage)
    }

    static func pull(_ data: Data, maxBody: Int, maxHeader: Int) -> Pull {
        let marker = Data("\r\n\r\n".utf8)
        guard let headerEnd = data.range(of: marker) else {
            if data.count > maxHeader { return .fail(400, "Bad Request", "headers_too_large") }
            return .needMore
        }
        let headerData = data.subdata(in: data.startIndex..<headerEnd.lowerBound)
        guard let headerText = String(data: headerData, encoding: .utf8) else {
            return .fail(400, "Bad Request", "bad_headers")
        }
        var lines = headerText.components(separatedBy: "\r\n")
        if lines.isEmpty { return .fail(400, "Bad Request", "bad_request_line") }
        let request = lines.removeFirst()
        let parts = request.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 3 else { return .fail(400, "Bad Request", "bad_request_line") }
        let method = String(parts[0]).uppercased()
        let rawPath = String(parts[1])
        let path = rawPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? rawPath
        var headers: [String: String] = [:]
        for line in lines where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { return .fail(400, "Bad Request", "bad_header") }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if headers[name] == nil { headers[name] = String(value) }
        }
        if let encoding = headers["transfer-encoding"]?.lowercased(), encoding.contains("chunked") {
            return .fail(400, "Bad Request", "chunked_not_supported")
        }
        let bodyStart = headerEnd.upperBound
        let length: Int
        if let raw = headers["content-length"] {
            guard let n = Int(raw), n >= 0 else { return .fail(400, "Bad Request", "bad_content_length") }
            if n > maxBody { return .fail(413, "Payload Too Large", "body_too_large") }
            length = n
        } else {
            length = 0
        }
        if data.distance(from: bodyStart, to: data.endIndex) < length { return .needMore }
        let bodyEnd = data.index(bodyStart, offsetBy: length)
        let body = data.subdata(in: bodyStart..<bodyEnd)
        return .ready(HTTPMessage(method: method, path: path, headers: headers, body: body))
    }

    static func jsonBody(_ obj: Any) -> Data {
        guard JSONSerialization.isValidJSONObject(obj),
              let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]) else {
            return Data("{}".utf8)
        }
        return data
    }

    static func encode(status: Int, reason: String, headers: [String: String], body: Data) -> Data {
        var fields = headers
        fields["Content-Length"] = "\(body.count)"
        fields["Connection"] = "close"
        var text = "HTTP/1.1 \(status) \(reason)\r\n"
        for key in fields.keys.sorted() {
            text += "\(key): \(fields[key] ?? "")\r\n"
        }
        text += "\r\n"
        var data = Data(text.utf8)
        data.append(body)
        return data
    }
}
