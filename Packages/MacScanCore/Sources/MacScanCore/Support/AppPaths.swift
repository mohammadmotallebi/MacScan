import Foundation

/// Well-known locations used by MacScan. All are created on first access.
public enum AppPaths {
    public static var home: URL { FileManager.default.homeDirectoryForCurrentUser }

    public static var applicationSupport: URL {
        ensure(home.appendingPathComponent("Library/Application Support/MacScan", isDirectory: true))
    }

    public static var history: URL {
        ensure(applicationSupport.appendingPathComponent("History", isDirectory: true))
    }

    /// MacScan's own ClamAV database directory (filled by "Update virus database").
    public static var clamDatabase: URL {
        ensure(applicationSupport.appendingPathComponent("ClamAV", isDirectory: true))
    }

    public static var ignoreListFile: URL {
        applicationSupport.appendingPathComponent("ignored.json")
    }

    public static var logs: URL {
        ensure(home.appendingPathComponent("Library/Logs/MacScan", isDirectory: true))
    }

    /// Per-scan temporary directory (file lists, compiled rules). Caller deletes it.
    public static func makeTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("MacScan-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @discardableResult
    static func ensure(_ url: URL) -> URL {
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
