import AppKit
import Foundation

// MARK: - Ignore list

public struct IgnoreEntry: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var path: String
    public var engine: EngineID
    public var reason: String
    /// SHA-256 at the time of ignoring. If the file changes, the finding shows up again.
    public var fingerprint: String?
    public var addedAt: Date

    public init(finding: Finding) {
        id = UUID()
        path = finding.path
        engine = finding.engine
        reason = finding.reason
        fingerprint = finding.sha256
        addedAt = Date()
    }

    public func matches(_ f: Finding) -> Bool {
        guard f.path == path, f.engine == engine else { return false }
        // VirusTotal reasons contain changing counts; match those on path+engine+hash only.
        if engine != .virustotal, f.reason != reason { return false }
        if let fingerprint, let current = f.sha256, fingerprint != current { return false }
        return true
    }
}

public struct IgnoreList: Codable, Hashable, Sendable {
    public var entries: [IgnoreEntry] = []

    public init(entries: [IgnoreEntry] = []) {
        self.entries = entries
    }

    /// Returns (kept, ignoredCount). Clean findings are never filtered.
    public func filter(_ findings: [Finding]) -> ([Finding], Int) {
        guard !entries.isEmpty else { return (findings, 0) }
        var kept: [Finding] = []
        var ignored = 0
        for f in findings {
            if f.severity > .clean, entries.contains(where: { $0.matches(f) }) {
                ignored += 1
            } else {
                kept.append(f)
            }
        }
        return (kept, ignored)
    }

    public static func load(from url: URL = AppPaths.ignoreListFile) -> IgnoreList {
        guard let data = try? Data(contentsOf: url),
              let list = try? JSONDecoder.macScan.decode(IgnoreList.self, from: data)
        else { return IgnoreList() }
        return list
    }

    public func save(to url: URL = AppPaths.ignoreListFile) throws {
        try JSONEncoder.macScan.encode(self).write(to: url, options: .atomic)
    }
}

// MARK: - History

public struct HistoryStore: Sendable {
    public let directory: URL
    public let maxSessions: Int

    public init(directory: URL = AppPaths.history, maxSessions: Int = 100) {
        self.directory = directory
        self.maxSessions = maxSessions
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    private func url(for id: UUID) -> URL {
        directory.appendingPathComponent("\(id.uuidString).json")
    }

    public func save(_ session: ScanSession) throws {
        try JSONEncoder.macScan.encode(session).write(to: url(for: session.id), options: .atomic)
        prune()
    }

    /// All sessions, newest first. Unreadable files are skipped (and logged).
    public func loadAll() -> [ScanSession] {
        guard let files = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) else { return [] }
        var sessions: [ScanSession] = []
        for file in files where file.pathExtension == "json" {
            do {
                sessions.append(try JSONDecoder.macScan.decode(ScanSession.self, from: Data(contentsOf: file)))
            } catch {
                FileLogger.shared.warning("Skipping unreadable history file \(file.lastPathComponent): \(error.localizedDescription)")
            }
        }
        return sessions.sorted { $0.startedAt > $1.startedAt }
    }

    public func delete(_ id: UUID) throws {
        let file = url(for: id)
        if FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.removeItem(at: file)
        }
    }

    private func prune() {
        let all = loadAll()
        guard all.count > maxSessions else { return }
        for s in all.dropFirst(maxSessions) { try? delete(s.id) }
    }
}

// MARK: - Custom folder targets

/// Persists the user's custom scan folders as bookmarks (survive renames/moves) in UserDefaults.
/// MacScan isn't sandboxed, so plain (non security-scoped) bookmarks are sufficient.
public struct TargetStore: Sendable {
    static let key = "MacScan.CustomFolderBookmarks"
    let defaultsSuite: String?

    public init(defaultsSuite: String? = nil) {
        self.defaultsSuite = defaultsSuite
    }

    private var defaults: UserDefaults {
        defaultsSuite.flatMap { UserDefaults(suiteName: $0) } ?? .standard
    }

    public func load() -> [URL] {
        let blobs = defaults.array(forKey: Self.key) as? [Data] ?? []
        var urls: [URL] = []
        for blob in blobs {
            var stale = false
            if let url = try? URL(resolvingBookmarkData: blob, options: [.withoutUI], relativeTo: nil, bookmarkDataIsStale: &stale) {
                urls.append(url)
            }
        }
        return urls
    }

    public func save(_ urls: [URL]) {
        let blobs = urls.compactMap { try? $0.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil) }
        defaults.set(blobs, forKey: Self.key)
    }
}

// MARK: - Full Disk Access

public enum FullDiskAccess {
    /// Deep link to System Settings › Privacy & Security › Full Disk Access.
    public static let settingsURL = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!

    /// Best-effort check: TCC-protected locations are only readable with Full Disk Access.
    public static func isLikelyGranted() -> Bool {
        let home = AppPaths.home.path
        let probes = [
            home + "/Library/Safari",
            home + "/Library/Mail",
            "/Library/Application Support/com.apple.TCC",
        ]
        let fm = FileManager.default
        var tested = false
        for probe in probes where fm.fileExists(atPath: probe) {
            tested = true
            if (try? fm.contentsOfDirectory(atPath: probe)) != nil { return true }
        }
        return !tested
    }

    @MainActor
    public static func openSettings() {
        NSWorkspace.shared.open(settingsURL)
    }
}

// MARK: - JSON coding

extension JSONEncoder {
    public static var macScan: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return e
    }
}

extension JSONDecoder {
    public static var macScan: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
