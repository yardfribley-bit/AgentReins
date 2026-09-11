import Foundation

enum RawLogCapture {
    static func capture(url: URL, source: String, previousOffset: UInt64?, maximumInitialBytes: UInt64 = 512 * 1_024)
        -> RawEvidenceRecord? {
        guard let handle = try? FileHandle(forReadingFrom: url),
              let end = try? handle.seekToEnd() else { return nil }
        defer { try? handle.close() }
        let start: UInt64
        if let previousOffset, previousOffset <= end { start = previousOffset }
        else { start = end > maximumInitialBytes ? end - maximumInitialBytes : 0 }
        guard end > start else { return nil }
        try? handle.seek(toOffset: start)
        guard let payload = try? handle.readToEnd(), !payload.isEmpty else { return nil }
        let values = try? url.resourceValues(forKeys: [.fileResourceIdentifierKey])
        return RawEvidenceRecord(source: source, stream: url.path,
            offsetStart: Int64(start), offsetEnd: Int64(end),
            fingerprint: values?.fileResourceIdentifier.map { String(describing: $0) },
            observedAt: Date(), payload: payload)
    }
}
