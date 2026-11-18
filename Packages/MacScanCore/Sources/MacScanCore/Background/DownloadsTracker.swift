import Foundation

/// Remembers which top-level items in ~/Downloads were already seen, so the Downloads watcher scans
/// only what's new. Read-only towards the folder itself; the only file it writes is its own state.
public struct DownloadsTracker: Sendable {
    /// Size and modification time of one top-level item.
    public struct Entry: Codable, Hashable, Sendable {
        public var size: Int64
        /// Milliseconds since 1970 (whole numbers survive JSON exactly).
        public var modified: Int64
        public var isDirectory: Bool

        public init(size: Int64, modified: Int64, isDirectory: Bool) {
            self.size = size
            self.modified = modified
            self.isDirectory = isDirectory
        }
    }

    public typealias Snapshot = [String: Entry]

    /// Files that browsers and download tools write while a download is still in progress.
    static let partialExtensions: Set<String> = ["crdownload", "download", "part", "partial", "opdownload", "aria2", "tmp"]

    public let folder: URL
    public let stateFile: URL

    public init(folder: URL = AppPaths.downloads, stateFile: URL = AppPaths.downloadsSeenFile) {
        self.folder = folder
        self.stateFile = stateFile
    }

    static func isTracked(_ name: String) -> Bool {
        guard !name.hasPrefix(".") else { return false }   // .DS_Store, browser temp files
        return !partialExtensions.contains((name as NSString).pathExtension.lowercased())
    }

    /// The folder's top-level items right now, without hidden files and unfinished downloads.
    /// Throws when the folder can't be read (for example when macOS denies access).
    public func current() throws -> Snapshot {
        var snapshot: Snapshot = [:]
        for name in try FileManager.default.contentsOfDirectory(atPath: folder.path) where Self.isTracked(name) {
            if let entry = entry(for: name) { snapshot[name] = entry }
        }
        return snapshot
    }

    func entry(for name: String) -> Entry? {
        let path = folder.appendingPathComponent(name).path
        var info = stat()
        guard lstat(path, &info) == 0 else { return nil }
        let isDirectory = (info.st_mode & S_IFMT) == S_IFDIR
        let modified = Int64(info.st_mtimespec.tv_sec) * 1000 + Int64(info.st_mtimespec.tv_nsec / 1_000_000)
        return Entry(size: isDirectory ? 0 : Int64(info.st_size), modified: modified, isDirectory: isDirectory)
    }

    /// What was seen last time, or nil when the watcher has never run.
    public func loadSeen() -> Snapshot? {
        guard let data = try? Data(contentsOf: stateFile) else { return nil }
        return try? JSONDecoder().decode(Snapshot.self, from: data)
    }

    public func save(_ snapshot: Snapshot) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(snapshot).write(to: stateFile, options: .atomic)
    }

    /// Marks everything in the folder as seen, so only later arrivals are scanned.
    public func baseline() throws {
        try save(try current())
    }

    public func forget() {
        try? FileManager.default.removeItem(at: stateFile)
    }

    /// Names that are new or changed since `seen`, sorted.
    public static func newItems(in current: Snapshot, since seen: Snapshot) -> [String] {
        current.filter { seen[$0.key] != $0.value }.keys.sorted()
    }

    /// Waits until the named items stop changing (a download or copy may still be writing them), up to
    /// `timeout`. Returns the entries of the items that still exist; an item that never settles is
    /// returned as it is, so nothing is skipped for good.
    public func waitUntilSettled(_ names: [String], interval: Duration, timeout: Duration) async -> Snapshot {
        let quietMilliseconds = Int64(interval.components.seconds) * 1000 + Int64(interval.components.attoseconds / 1_000_000_000_000_000)
        let deadline = ContinuousClock.now + timeout
        var previous: Snapshot = [:]
        for name in names { previous[name] = entry(for: name) }
        while true {
            try? await Task.sleep(for: min(interval, max(.zero, deadline - ContinuousClock.now)))
            var latest: Snapshot = [:]
            for name in names { latest[name] = entry(for: name) }
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let settled = latest == previous && latest.values.allSatisfy { now - $0.modified >= quietMilliseconds }
            if settled || latest.isEmpty || ContinuousClock.now >= deadline || Task.isCancelled { return latest }
            previous = latest
        }
    }
}
