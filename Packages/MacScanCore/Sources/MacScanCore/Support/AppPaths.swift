import Foundation
import os

/// Well-known locations used by MacScan. All are created on first access.
public enum AppPaths {
    /// The user whose files are scanned. Normally the current user; an elevated (root) scan worker
    /// sets it to the user who started the scan so ~/Applications, startup items and crontab stay theirs.
    private static let targetUser = OSAllocatedUnfairLock<(home: URL, name: String)?>(initialState: nil)

    public static func setTargetUser(home: URL, name: String) {
        targetUser.withLock { $0 = (home, name) }
    }

    public static var home: URL {
        targetUser.withLock { $0?.home } ?? FileManager.default.homeDirectoryForCurrentUser
    }

    public static var userName: String {
        targetUser.withLock { $0?.name } ?? NSUserName()
    }

    public static var applicationSupport: URL {
        ensure(home.appendingPathComponent("Library/Application Support/MacScan", isDirectory: true))
    }

    public static var history: URL {
        ensure(applicationSupport.appendingPathComponent("History", isDirectory: true))
    }

    /// Items the user moved to quarantine (see `QuarantineStore`).
    public static var quarantine: URL {
        ensure(URL(fileURLWithPath: quarantinePath, isDirectory: true))
    }

    /// The quarantine folder's path, without creating it.
    public static var quarantinePath: String {
        home.appendingPathComponent("Library/Application Support/MacScan/Quarantine").path
    }

    /// MacScan's own ClamAV database directory (filled by "Update virus database").
    public static var clamDatabase: URL {
        ensure(applicationSupport.appendingPathComponent("ClamAV", isDirectory: true))
    }

    public static var ignoreListFile: URL {
        applicationSupport.appendingPathComponent("ignored.json")
    }

    /// What the Downloads watcher has already seen (so each run scans only new items).
    public static var downloadsSeenFile: URL {
        applicationSupport.appendingPathComponent("downloads-seen.json")
    }

    /// The startup items seen by the last Startup Items scan (to report what changed since).
    public static var startupBaselineFile: URL {
        applicationSupport.appendingPathComponent("startup-baseline.json")
    }

    /// The browser extensions seen by the last Browser Extensions scan (to report what changed since).
    public static var extensionBaselineFile: URL {
        applicationSupport.appendingPathComponent("extensions-baseline.json")
    }

    /// What the last completed Full Check found (to report what changed since).
    public static var fullCheckBaselineFile: URL {
        applicationSupport.appendingPathComponent("fullcheck-baseline.json")
    }

    /// The sensitive permissions seen at the last permission watch.
    public static var permissionWatchFile: URL {
        applicationSupport.appendingPathComponent("permission-watch.json")
    }

    /// Held while a background scan runs, so the scheduled scan and the Downloads watcher take turns.
    public static var backgroundLockFile: URL {
        applicationSupport.appendingPathComponent("background.lock")
    }

    public static var downloads: URL {
        home.appendingPathComponent("Downloads", isDirectory: true)
    }

    public static var launchAgents: URL {
        home.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
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
