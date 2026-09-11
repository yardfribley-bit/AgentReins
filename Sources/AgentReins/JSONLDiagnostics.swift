import Foundation

struct JSONLDiagnosticResult: Equatable {
    let completeRows: Int
    let malformedRows: Int
    let trailingPartialRows: Int
}

enum JSONLDiagnostics {
    static func inspect(_ data: Data) -> JSONLDiagnosticResult {
        let trailingPartial = data.last.map { $0 != 0x0A } ?? false
        let pieces = data.split(separator: 0x0A, omittingEmptySubsequences: true)
        var valid = 0, malformed = 0
        for row in pieces.prefix(max(0, pieces.count - (trailingPartial ? 1 : 0))) {
            if (try? JSONSerialization.jsonObject(with: Data(row))) != nil { valid += 1 }
            else { malformed += 1 }
        }
        return JSONLDiagnosticResult(completeRows: valid + malformed, malformedRows: malformed,
                                     trailingPartialRows: trailingPartial ? 1 : 0)
    }
}
