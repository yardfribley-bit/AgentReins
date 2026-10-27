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

        let queue = DispatchQueue(label: "com.agentreins.mcp-http")
        let state = ServerState(port: port, auth: auth, token: token, queue: queue)
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
        dispatchMain()
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

private final class ServerState {
    let port: Int
    let auth: String
    let token: String?
    let queue: DispatchQueue
    var active = 0
    var settled = false
    let sessions = SessionTable()

    init(port: Int, auth: String, token: String?, queue: DispatchQueue) {
        self.port = port
        self.auth = auth
        self.token = token
        self.queue = queue
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
        let listen = UInt16(port)
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
            conn.send(content: bytes, completion: .contentProcessed { _ in
                conn.cancel()
            })
        }
        func pump() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
                if let data, !data.isEmpty { buffer.append(data) }
                switch HTTPCodec.pull(buffer, maxBody: HTTPTransport.maxBody, maxHeader: HTTPTransport.maxHeader) {
                case .needMore:
                    if isComplete || error != nil {
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
                    let peerPort = self.clientPort(conn)
                    let peer = peerPort.flatMap { PeerIdentity.lookup(clientPort: $0, serverPort: UInt16(self.port)) }
                    if peer == nil {
                        let local = String(describing: conn.currentPath?.localEndpoint)
                        let remote = String(describing: conn.currentPath?.remoteEndpoint)
                        HTTPTransportLog.write("AgentReinsMCP: peer lookup failed clientPort=\(peerPort.map(String.init) ?? "?") local=\(local) remote=\(remote)")
                    }
                    let response = self.route(message, peer: peer)
                    sendAndClose(response)
                }
            }
        }
        arm()
        pump()
    }

    func route(_ message: HTTPMessage, peer: PeerIdentity?) -> Data {
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
                return json(404, "Not Found", ["error": "session_not_found"])
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
                return json(404, "Not Found", ["error": "session_not_found"])
            }
            session = existing
        }

        let reply = MCPDispatcher.handle(obj, session: session, auditActor: session.auditActor(peer: peer))
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
        for _ in 0..<10 {
            let proc = Process()
            proc.executableURL = url
            proc.arguments = ["-nP", "-iTCP:\(port)", "-sTCP:LISTEN"]
            let out = Pipe()
            proc.standardOutput = out
            proc.standardError = Pipe()
            do {
                try proc.run()
                proc.waitUntilExit()
                last = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                if last.contains("LISTEN") { return last }
            } catch {
                return ""
            }
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
    var started = false
    var released = false
}

private final class SessionTable {
    var sessions: [String: MCPSession] = [:]

    func create() -> MCPSession? {
        if sessions.count >= 64 { return nil }
        let session = MCPSession(id: UUID().uuidString.lowercased(), transport: "http")
        sessions[session.id] = session
        return session
    }

    func get(_ id: String) -> MCPSession? { sessions[id] }

    @discardableResult
    func remove(_ id: String) -> Bool { sessions.removeValue(forKey: id) != nil }
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
