import Darwin
import Foundation

/// A second AgentReins.app, including a backup copy on the desktop, must not
/// start. Two writers on the evidence file are what froze the machine.
public enum AppInstanceGate {
    public struct Proc: Equatable, Sendable {
        public var pid: Int32
        public var path: String
        public init(pid: Int32, path: String) {
            self.pid = pid
            self.path = path
        }
    }

    public static func isThisApp(_ path: String) -> Bool {
        let base = (path as NSString).lastPathComponent
        guard base == "AgentReins" else { return false }
        return path.lowercased().contains(".app/")
    }

    public static func others(selfPid: Int32, processes: [Proc]) -> [Proc] {
        processes.filter { $0.pid != selfPid && $0.pid > 0 && isThisApp($0.path) }
    }

    public static func message(otherPath: String) -> String {
        "已经有一个 AgentReins 在运行（\(otherPath)）。这次启动退出，避免两份同时写证据、把机器卡住。"
    }
}

/// One sustained hot stretch, or memory pressure, slows sampling. One log line.
public final class RuntimeBudget: @unchecked Sendable {
    public static let shared = RuntimeBudget()
    public init() {}
    private let lock = NSLock()
    private var hot = 0
    private var throttled = false
    private var announced = false

    public var isThrottled: Bool {
        lock.lock(); defer { lock.unlock() }
        return throttled
    }

    /// `cpuPercent` is one core = 100. Three hot samples, or memory pressure, throttle.
    public func observe(cpuPercent: Double, memoryPressure: Bool) -> String {
        lock.lock(); defer { lock.unlock() }
        if memoryPressure || cpuPercent >= 100 {
            hot += 1
        } else if cpuPercent < 60 {
            hot = 0
        }
        let next = memoryPressure || hot >= 3
        if next && !announced {
            announced = true
            fputs("AgentReins 本进程持续占用过高，已放慢采样并暂停非必要监视。\n", stderr)
        }
        if !next { announced = false }
        throttled = next
        return next ? "throttled" : "normal"
    }

    public static func cpuPercent(userMicros: Int64, systemMicros: Int64, elapsed: TimeInterval) -> Double {
        guard elapsed > 0.05 else { return 0 }
        return Double(userMicros + systemMicros) / (elapsed * 1_000_000) * 100
    }

    public static func paceText(_ mode: String) -> String {
        mode == "throttled" ? "throttled\n" : "normal\n"
    }

    public static func paceURL() -> URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_PACE_FILE"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentReins/runtime-pace")
    }

    public static func writePace(_ mode: String) {
        let url = paceURL()
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(paceText(mode).utf8).write(to: url, options: .atomic)
    }

    private var timer: DispatchSourceTimer?
    private var memory: DispatchSourceMemoryPressure?
    private var memoryHot = false
    private var lastUser: Int64 = 0
    private var lastSystem: Int64 = 0
    private var lastAt = Date()

    public func startSampling() {
        lock.lock()
        let already = timer != nil
        lock.unlock()
        guard !already else { return }
        var usage = rusage()
        getrusage(RUSAGE_SELF, &usage)
        lastUser = Self.micros(usage.ru_utime)
        lastSystem = Self.micros(usage.ru_stime)
        lastAt = Date()
        let source = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        source.schedule(deadline: .now() + 5, repeating: 5)
        source.setEventHandler { [weak self] in self?.sample() }
        source.resume()
        let pressure = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: .global(qos: .utility))
        pressure.setEventHandler { [weak self] in self?.memoryHot = true }
        pressure.resume()
        lock.lock()
        timer = source
        memory = pressure
        lock.unlock()
    }

    private func sample() {
        var usage = rusage()
        getrusage(RUSAGE_SELF, &usage)
        let user = Self.micros(usage.ru_utime)
        let system = Self.micros(usage.ru_stime)
        let elapsed = Date().timeIntervalSince(lastAt)
        let cpu = Self.cpuPercent(userMicros: user - lastUser, systemMicros: system - lastSystem, elapsed: elapsed)
        lastUser = user
        lastSystem = system
        lastAt = Date()
        let hotMemory = memoryHot
        memoryHot = false
        let mode = observe(cpuPercent: cpu, memoryPressure: hotMemory)
        Self.writePace(mode)
    }

    private static func micros(_ value: timeval) -> Int64 {
        Int64(value.tv_sec) * 1_000_000 + Int64(value.tv_usec)
    }
}

/// Jobs that stay alive after the window closes. Quitting the app unloads them.
public enum BackgroundJobs {
    public static let labels = [
        "com.agentreins.mcp-http",
        "com.agentreins.mcp-http-health",
        "com.agentreins.socket-sampler",
    ]

    public static func ownedLabels(_ discovered: [String]) -> [String] {
        var set = Set(labels)
        for label in discovered where label.hasPrefix("com.agentreins.") && (label.contains("mitm") || label.contains("audit-proxy")) {
            set.insert(label)
        }
        return set.sorted()
    }

    public static func bootoutArguments(uid: UInt32, label: String) -> [String] {
        ["bootout", "gui/\(uid)/\(label)"]
    }

    public static func bootstrapArguments(uid: UInt32, plistPath: String) -> [String] {
        ["bootstrap", "gui/\(uid)", plistPath]
    }
}
