import AgentReinsCore
import Darwin
import Foundation

/// kqueue vnode watch (DispatchSource) on a bounded credential set.
/// `O_EVTONLY` does not count as a read. NOTE_ATTRIB fires when access time moves.
/// This is not FSEvents and not a full-disk watch. APFS may coalesce atime,
/// so the caller must label a hit without an open descriptor as possible.
final class CredentialPathWatch {
    var onAccess: ((String) -> Void)?
    private let queue: DispatchQueue
    private var sources: [String: DispatchSourceFileSystemObject] = [:]
    private var baseline: [String: FileLayerCapture.AccessStamp] = [:]

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    func replace(paths: [String]) {
        let wanted = Set(paths.prefix(FileLayerCapture.watchCap))
        for path in sources.keys where !wanted.contains(path) {
            sources[path]?.cancel()
            sources[path] = nil
            baseline[path] = nil
        }
        for path in wanted where sources[path] == nil {
            let fd = path.withCString { open($0, O_EVTONLY) }
            guard fd >= 0 else { continue }
            baseline[path] = Self.stamp(path)
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.attrib, .write, .extend, .rename, .delete],
                queue: queue)
            source.setEventHandler { [weak self] in
                self?.handle(path)
            }
            source.setCancelHandler {
                close(fd)
            }
            source.resume()
            sources[path] = source
        }
    }

    func stop() {
        for source in sources.values { source.cancel() }
        sources.removeAll()
        baseline.removeAll()
    }

    private func handle(_ path: String) {
        guard let current = Self.stamp(path) else { return }
        let previous = baseline[path]
        baseline[path] = current
        guard let previous, FileLayerCapture.isAccessRead(previous: previous, current: current) else { return }
        onAccess?(path)
    }

    private static func stamp(_ path: String) -> FileLayerCapture.AccessStamp? {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        let access = TimeInterval(info.st_atimespec.tv_sec) + TimeInterval(info.st_atimespec.tv_nsec) / 1_000_000_000
        let modified = TimeInterval(info.st_mtimespec.tv_sec) + TimeInterval(info.st_mtimespec.tv_nsec) / 1_000_000_000
        return FileLayerCapture.AccessStamp(access: access, modified: modified)
    }
}
