import Foundation
import os

/// Appends log lines to ~/Library/Logs/MacScan/MacScan.log (rotated at 5 MB) and mirrors them to os_log.
public final class FileLogger: @unchecked Sendable {
    public static let shared = FileLogger()

    public enum Level: String, Codable, Sendable {
        case info = "INFO"
        case warning = "WARN"
        case error = "ERROR"
    }

    public let fileURL: URL
    /// When set, lines go here instead of the log file (used by the root scan worker, which must not
    /// create root-owned files in the user's ~/Library/Logs).
    private let sink: (@Sendable (Level, String) -> Void)?
    private let queue = DispatchQueue(label: "MacScan.FileLogger")
    private let osLog = Logger(subsystem: "MacScan", category: "scanner")
    private let maxBytes: UInt64 = 5 * 1024 * 1024
    private let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    public init(directory: URL? = nil) {
        let dir = directory ?? AppPaths.logs
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("MacScan.log")
        sink = nil
    }

    /// A logger that forwards every line to `sink` and never touches the disk.
    public init(forwardingTo sink: @escaping @Sendable (Level, String) -> Void) {
        fileURL = URL(fileURLWithPath: "/dev/null")
        self.sink = sink
    }

    public func info(_ message: String) { log(.info, message) }
    public func warning(_ message: String) { log(.warning, message) }
    public func error(_ message: String) { log(.error, message) }

    public func log(_ level: Level, _ message: String) {
        if let sink {
            sink(level, message)
            return
        }
        switch level {
        case .info: osLog.info("\(message, privacy: .public)")
        case .warning: osLog.warning("\(message, privacy: .public)")
        case .error: osLog.error("\(message, privacy: .public)")
        }
        let line = "\(formatter.string(from: Date())) [\(level.rawValue)] \(message)\n"
        queue.async { [self] in append(line) }
    }

    /// Blocks until pending writes are on disk (used by tests and at quit).
    public func flush() {
        queue.sync {}
    }

    private func append(_ line: String) {
        let fm = FileManager.default
        if let attrs = try? fm.attributesOfItem(atPath: fileURL.path),
           let size = attrs[.size] as? UInt64, size > maxBytes {
            let rotated = fileURL.deletingPathExtension().appendingPathExtension("1.log")
            try? fm.removeItem(at: rotated)
            try? fm.moveItem(at: fileURL, to: rotated)
        }
        if !fm.fileExists(atPath: fileURL.path) {
            fm.createFile(atPath: fileURL.path, contents: nil)
        }
        guard let handle = try? FileHandle(forWritingTo: fileURL) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data(line.utf8))
    }
}
