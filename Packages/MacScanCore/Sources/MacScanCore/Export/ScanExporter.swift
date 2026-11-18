import Foundation

public enum ExportFormat: String, CaseIterable, Sendable {
    case json
    case csv

    public var fileExtension: String { rawValue }
}

public enum ScanExporter {
    public static func export(_ sessions: [ScanSession], as format: ExportFormat) throws -> Data {
        switch format {
        case .json: try json(sessions)
        case .csv: Data(csv(sessions).utf8)
        }
    }

    /// A single session exports as one object; several as an array.
    public static func json(_ sessions: [ScanSession]) throws -> Data {
        if sessions.count == 1 { return try JSONEncoder.macScan.encode(sessions[0]) }
        return try JSONEncoder.macScan.encode(sessions)
    }

    public static let csvHeader = ["scan_id", "scan_started", "scan_status", "severity", "path", "engine", "reason", "detail", "sha256", "found_at"]

    public static func csv(_ sessions: [ScanSession]) -> String {
        let iso = ISO8601DateFormatter()
        var lines = [csvHeader.joined(separator: ",")]
        for s in sessions {
            for f in s.findings {
                let row = [
                    s.id.uuidString,
                    iso.string(from: s.startedAt),
                    s.status.rawValue,
                    f.severity.rawValue,
                    f.path,
                    f.engine.title,
                    f.reason,
                    f.detail ?? "",
                    f.sha256 ?? "",
                    iso.string(from: f.date),
                ]
                lines.append(row.map(escape).joined(separator: ","))
            }
        }
        return lines.joined(separator: "\r\n") + "\r\n"
    }

    /// RFC 4180 quoting. Also neutralises spreadsheet formula injection (=, +, -, @ prefixes).
    static func escape(_ field: String) -> String {
        var value = field
        if let first = value.first, "=+-@".contains(first) {
            value = "'" + value
        }
        if value.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" }) {
            return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return value
    }
}
