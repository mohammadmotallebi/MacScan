import Foundation

// Disk usage: walks a folder once, adds up the on-disk size of every folder, and keeps the largest files.
// Read-only. Nothing is removed here; the app offers "Move to Trash" per item after the user confirms.

/// A file or folder in a disk usage report.
public struct DiskItem: Identifiable, Hashable, Sendable {
    public var id: String { path }
    public let path: String
    public var size: Int64
    public let isDirectory: Bool
    /// A bundle shown as one item in Finder (.app, .photoslibrary, …).
    public let isPackage: Bool
    /// Files inside (folders only).
    public var fileCount: Int
    public let modified: Date?
    /// Stands for "N smaller files" in a folder listing; not a real path.
    public let isAggregate: Bool

    public var url: URL { URL(fileURLWithPath: path) }
    public var name: String { isAggregate ? path : (path as NSString).lastPathComponent }

    public init(path: String, size: Int64, isDirectory: Bool, isPackage: Bool = false, fileCount: Int = 0,
                modified: Date? = nil, isAggregate: Bool = false) {
        self.path = path
        self.size = size
        self.isDirectory = isDirectory
        self.isPackage = isPackage
        self.fileCount = fileCount
        self.modified = modified
        self.isAggregate = isAggregate
    }
}

/// What a disk usage scan found.
public struct DiskUsageReport: Sendable {
    struct Folder: Sendable {
        var size: Int64 = 0
        var fileCount = 0
        var isPackage = false
        var modified: Date?
        var childFolders: [String] = []
        /// Files at least `listedFileMinimum` bytes, listed individually.
        var files: [DiskItem] = []
        /// Everything smaller, summed up.
        var otherFilesSize: Int64 = 0
        var otherFilesCount = 0
    }

    public let root: String
    public internal(set) var totalSize: Int64 = 0
    public internal(set) var fileCount = 0
    public internal(set) var folderCount = 0
    /// Largest files, biggest first.
    public internal(set) var largestFiles: [DiskItem] = []
    /// Folders MacScan wasn't allowed to read (first 200), and how many there were in total.
    public internal(set) var unreadable: [String] = []
    public internal(set) var unreadableCount = 0
    public internal(set) var cancelled = false
    public internal(set) var duration: Duration = .zero
    var folders: [String: Folder] = [:]

    /// The item for a folder in the report (nil if it isn't one).
    public func folder(_ path: String) -> DiskItem? {
        guard let f = folders[path] else { return nil }
        return DiskItem(path: path, size: f.size, isDirectory: true, isPackage: f.isPackage, fileCount: f.fileCount, modified: f.modified)
    }

    /// Sub-folders and larger files directly inside `path`, biggest first, plus one entry for the smaller files.
    public func children(of path: String) -> [DiskItem] {
        guard let f = folders[path] else { return [] }
        var items = f.childFolders.compactMap(folder) + f.files
        items.sort { $0.size != $1.size ? $0.size > $1.size : $0.path < $1.path }
        if f.otherFilesCount > 0 {
            items.append(DiskItem(path: "\(f.otherFilesCount) smaller file\(f.otherFilesCount == 1 ? "" : "s")", size: f.otherFilesSize,
                                  isDirectory: false, fileCount: f.otherFilesCount, isAggregate: true))
        }
        return items
    }

    /// Paths of the biggest folders (excluding the root and folders inside packages), computed once after the scan.
    var topFolders: [String] = []

    /// The biggest folders anywhere under the root (excluding the root and folders inside packages).
    /// Cheap: reads the list computed at the end of the scan, with current sizes.
    public func largestFolders(limit: Int = 100) -> [DiskItem] {
        topFolders.compactMap(folder).sorted { $0.size > $1.size }.prefix(limit).map { $0 }
    }

    /// Picks the biggest folders in one pass (a folder that is ≥ 95% one sub-folder is left out in favour of that
    /// sub-folder). A folder is inside a package if its parent is a package or is inside
    /// one. Parents are visited before children (shorter paths first), so each check is a dictionary lookup.
    /// (Checking every folder against every package path took minutes on a large home folder.)
    static func computeTopFolders(_ folders: [String: Folder], root: String, keep: Int) -> [String] {
        var insidePackage: [String: Bool] = [root: false]
        insidePackage.reserveCapacity(folders.count)
        var candidates: [(path: String, size: Int64)] = []
        candidates.reserveCapacity(folders.count)
        for path in folders.keys.sorted(by: { $0.count < $1.count }) where path != root {
            let parent = (path as NSString).deletingLastPathComponent
            let inside = (folders[parent]?.isPackage ?? false) || (insidePackage[parent] ?? false)
            insidePackage[path] = inside
            guard !inside, let folder = folders[path] else { continue }
            // Skip a folder that is mostly one sub-folder (Containers › com.docker.docker › Data › vms): the
            // sub-folder already stands for it, and a chain of near-identical sizes hides everything else.
            // Packages are kept: they're shown as one item.
            let biggestChild = folder.childFolders.compactMap { folders[$0]?.size }.max() ?? 0
            if !folder.isPackage, folder.size > 0, Double(biggestChild) >= Double(folder.size) * 0.95 { continue }
            candidates.append((path, folder.size))
        }
        candidates.sort { $0.size != $1.size ? $0.size > $1.size : $0.path < $1.path }
        return candidates.prefix(keep).map(\.path)
    }

    /// Updates the report after everything inside a folder was moved to the Trash: the folder stays, empty.
    public mutating func markEmptied(_ path: String) {
        guard var f = folders[path] else { return }
        let size = f.size
        let files = f.fileCount
        let prefix = path + "/"
        folders = folders.filter { !$0.key.hasPrefix(prefix) }
        largestFiles.removeAll { $0.path.hasPrefix(prefix) }
        topFolders.removeAll { $0.hasPrefix(prefix) }
        f.size = 0
        f.fileCount = 0
        f.childFolders = []
        f.files = []
        f.otherFilesSize = 0
        f.otherFilesCount = 0
        folders[path] = f
        var parent = (path as NSString).deletingLastPathComponent
        while path != root, parent.count >= root.count, var p = folders[parent] {
            p.size -= size
            p.fileCount -= files
            folders[parent] = p
            if parent == root { break }
            parent = (parent as NSString).deletingLastPathComponent
        }
        totalSize -= size
        fileCount -= files
        folderCount = folders.count
    }

    /// Updates the report after the user moved an item to the Trash: subtracts its size from every folder above it.
    public mutating func markRemoved(_ item: DiskItem) {
        guard !item.isAggregate else { return }
        let files = item.isDirectory ? (folders[item.path]?.fileCount ?? item.fileCount) : 1
        var parent = (item.path as NSString).deletingLastPathComponent
        if var p = folders[parent] {
            p.childFolders.removeAll { $0 == item.path }
            if let i = p.files.firstIndex(where: { $0.path == item.path }) {
                p.files.remove(at: i)
            } else if !item.isDirectory {
                p.otherFilesSize -= item.size
                p.otherFilesCount -= 1
            }
            folders[parent] = p
        }
        while parent.count >= root.count, var p = folders[parent] {
            p.size -= item.size
            p.fileCount -= files
            folders[parent] = p
            if parent == root { break }
            parent = (parent as NSString).deletingLastPathComponent
        }
        if item.isDirectory {
            let prefix = item.path + "/"
            folders = folders.filter { $0.key != item.path && !$0.key.hasPrefix(prefix) }
            largestFiles.removeAll { $0.path.hasPrefix(prefix) }
            folderCount = folders.count
        }
        largestFiles.removeAll { $0.path == item.path }
        if item.isDirectory {
            let prefix = item.path + "/"
            topFolders.removeAll { $0 == item.path || $0.hasPrefix(prefix) }
        }
        totalSize -= item.size
        fileCount -= files
    }
}

public struct DiskUsageProgress: Sendable, Equatable {
    public var filesScanned: Int
    public var bytesCounted: Int64
    public var currentFolder: String

    public init(filesScanned: Int, bytesCounted: Int64, currentFolder: String) {
        self.filesScanned = filesScanned
        self.bytesCounted = bytesCounted
        self.currentFolder = currentFolder
    }
}

/// Walks a folder and builds a `DiskUsageReport`. Symbolic links are never followed, and other disks mounted
/// inside the folder are skipped, so nothing is counted twice or outside the chosen location.
public struct DiskUsageScanner: Sendable {
    public let root: URL
    /// How many of the largest files to keep.
    public let largestFileCount: Int
    /// Files at least this big are listed individually in folder listings; smaller ones are summed up.
    public let listedFileMinimum: Int64

    /// Never descended into when scanning the whole disk: other volumes and system mount points.
    static let skippedSystemPaths: Set<String> = ["/System/Volumes", "/Volumes", "/dev", "/net", "/home", "/private/var/vm"]

    public init(root: URL, largestFileCount: Int = 200, listedFileMinimum: Int64 = 1_000_000) {
        self.root = root
        self.largestFileCount = max(1, largestFileCount)
        self.listedFileMinimum = max(0, listedFileMinimum)
    }

    /// Scans synchronously on several threads; call from a background task. Checks Task cancellation and
    /// returns partial results.
    public func scan(progress: (@Sendable (DiskUsageProgress) -> Void)? = nil) -> DiskUsageReport {
        let start = ContinuousClock.now
        let rootPath = Paths.canonical(root).path
        let rootURL = URL(fileURLWithPath: rootPath, isDirectory: true)
        let rootValues = try? rootURL.resourceValues(forKeys: Set(Self.keys))
        let shared = WalkState(rootVolume: rootValues?.volumeIdentifier.map { "\($0)" }, wholeDisk: rootPath == "/")
        shared.push([rootURL])
        if Task.isCancelled { shared.cancel() }

        // Workers list one folder at a time and push its sub-folders back, so big trees spread over all threads.
        let workerCount = max(2, min(8, ProcessInfo.processInfo.activeProcessorCount))
        let results = WorkerResults()
        let group = DispatchGroup()
        for _ in 0..<workerCount {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                results.add(self.work(shared))
                group.leave()
            }
        }
        // This thread only watches for cancellation and reports progress.
        while group.wait(timeout: .now() + .milliseconds(200)) == .timedOut {
            if Task.isCancelled { shared.cancel() }
            let (files, bytes, folder) = shared.snapshot()
            progress?(DiskUsageProgress(filesScanned: files, bytesCounted: bytes, currentFolder: folder))
        }

        var report = DiskUsageReport(root: rootPath)
        report.cancelled = shared.isCancelled || Task.isCancelled
        var top: [DiskItem] = []
        var unreadable: [String] = []
        for local in results.all {
            report.folders.merge(local.folders) { a, _ in a }
            report.fileCount += local.fileCount
            top += local.top
            unreadable += local.unreadable
        }
        if report.folders[rootPath] == nil {
            report.folders[rootPath] = .init(isPackage: rootValues?.isPackage ?? false, modified: rootValues?.contentModificationDate)
        }
        // A folder's size so far covers only files directly inside; add each folder to its parent, deepest first.
        // (Folders listed after a cancel may be missing; their parents simply don't count them.)
        for path in report.folders.keys.sorted(by: { $0.count > $1.count }) where path != rootPath {
            guard let f = report.folders[path] else { continue }
            let parent = (path as NSString).deletingLastPathComponent
            report.folders[parent]?.size += f.size
            report.folders[parent]?.fileCount += f.fileCount
        }
        if report.cancelled {
            // Drop links to folders that were never listed.
            let known = Set(report.folders.keys)
            for key in known { report.folders[key]?.childFolders.removeAll { !known.contains($0) } }
        }

        report.topFolders = DiskUsageReport.computeTopFolders(report.folders, root: rootPath, keep: 200)

        top.sort { $0.size != $1.size ? $0.size > $1.size : $0.path < $1.path }
        report.largestFiles = Array(top.prefix(largestFileCount))
        report.totalSize = report.folders[rootPath]?.size ?? 0
        report.folderCount = report.folders.count
        unreadable.sort()
        report.unreadable = Array(unreadable.prefix(200))
        report.unreadableCount = unreadable.count
        report.duration = ContinuousClock.now - start
        let (files, bytes, _) = shared.snapshot()
        progress?(DiskUsageProgress(filesScanned: files, bytesCounted: bytes, currentFolder: rootPath))
        return report
    }

    static let keys: [URLResourceKey] = [.isDirectoryKey, .isSymbolicLinkKey, .isPackageKey, .totalFileAllocatedSizeKey,
                                         .fileAllocatedSizeKey, .contentModificationDateKey, .volumeIdentifierKey]

    /// What one worker found. Every folder is listed by exactly one worker, so the dictionaries never overlap.
    struct LocalResult: Sendable {
        var folders: [String: DiskUsageReport.Folder] = [:]
        var top: [DiskItem] = []
        var fileCount = 0
        var unreadable: [String] = []
    }

    func work(_ shared: WalkState) -> LocalResult {
        var local = LocalResult()
        var topFloor: Int64 = 0
        while let dir = shared.pop() {
            // Each folder in its own autorelease pool: these threads run for the whole scan, and the URLs and
            // attribute caches Foundation hands back would otherwise pile up until the end (gigabytes on a full disk).
            autoreleasepool { list(dir, shared: shared, into: &local, topFloor: &topFloor) }
            shared.done()
        }
        return local
    }

    private func list(_ dir: URL, shared: WalkState, into local: inout LocalResult, topFloor: inout Int64) {
        let fm = FileManager.default
        do {
            let path = dir.path
            let values = try? dir.resourceValues(forKeys: [.isPackageKey, .contentModificationDateKey])
            var folder = DiskUsageReport.Folder(isPackage: values?.isPackage ?? false, modified: values?.contentModificationDate)
            let entries: [URL]
            do {
                entries = try fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: Self.keys, options: [])
            } catch {
                if PermissionErrors.isPermissionDenied(error) { local.unreadable.append(path) }
                local.folders[path] = folder
                return
            }
            var subfolders: [URL] = []
            var bytes: Int64 = 0
            for url in entries {
                guard let v = try? url.resourceValues(forKeys: Set(Self.keys)), v.isSymbolicLink != true else { continue }
                let childPath = path == "/" ? "/" + url.lastPathComponent : path + "/" + url.lastPathComponent
                if v.isDirectory == true {
                    let volume = v.volumeIdentifier.map { "\($0)" }
                    if Self.skippedSystemPaths.contains(childPath) || shared.crossesVolume(volume) { continue }
                    folder.childFolders.append(childPath)
                    subfolders.append(URL(fileURLWithPath: childPath, isDirectory: true))
                    continue
                }
                let size = Int64(v.totalFileAllocatedSize ?? v.fileAllocatedSize ?? 0)
                bytes += size
                folder.size += size
                folder.fileCount += 1
                let item = DiskItem(path: childPath, size: size, isDirectory: false, modified: v.contentModificationDate)
                if size >= listedFileMinimum {
                    folder.files.append(item)
                } else {
                    folder.otherFilesSize += size
                    folder.otherFilesCount += 1
                }
                if local.top.count < largestFileCount || size > topFloor {
                    local.top.append(item)
                    if local.top.count >= largestFileCount * 2 {
                        local.top.sort { $0.size > $1.size }
                        local.top.removeLast(local.top.count - largestFileCount)
                        topFloor = local.top.last?.size ?? 0
                    }
                }
            }
            local.fileCount += folder.fileCount
            local.folders[path] = folder
            shared.push(subfolders)
            shared.count(files: folder.fileCount, bytes: bytes, folder: path)
        }
    }
}

/// The shared folder queue and counters for the workers.
final class WalkState: @unchecked Sendable {
    private let condition = NSCondition()
    private var pending: [URL] = []
    private var active = 0
    private var cancelled = false
    private var files = 0
    private var bytes: Int64 = 0
    private var lastFolder = ""
    let rootVolume: String?
    let wholeDisk: Bool

    init(rootVolume: String?, wholeDisk: Bool) {
        self.rootVolume = rootVolume
        self.wholeDisk = wholeDisk
    }

    /// Other disks mounted inside the chosen folder are skipped (except when scanning the whole startup disk,
    /// whose firmlinked data volume has its own identifier).
    func crossesVolume(_ volume: String?) -> Bool {
        !wholeDisk && volume != nil && rootVolume != nil && volume != rootVolume
    }

    func push(_ urls: [URL]) {
        guard !urls.isEmpty else { return }
        condition.lock()
        pending.append(contentsOf: urls)
        condition.broadcast()
        condition.unlock()
    }

    /// The next folder to list, or nil when everything is done (or cancelled).
    func pop() -> URL? {
        condition.lock()
        defer { condition.unlock() }
        while pending.isEmpty && active > 0 && !cancelled { condition.wait() }
        guard !cancelled, let next = pending.popLast() else {
            condition.broadcast()
            return nil
        }
        active += 1
        return next
    }

    func done() {
        condition.lock()
        active -= 1
        if active == 0 && pending.isEmpty { condition.broadcast() }
        condition.unlock()
    }

    func cancel() {
        condition.lock()
        cancelled = true
        condition.broadcast()
        condition.unlock()
    }

    var isCancelled: Bool { condition.lock(); defer { condition.unlock() }; return cancelled }

    func count(files n: Int, bytes b: Int64, folder: String) {
        condition.lock()
        files += n
        bytes += b
        lastFolder = folder
        condition.unlock()
    }

    func snapshot() -> (Int, Int64, String) {
        condition.lock()
        defer { condition.unlock() }
        return (files, bytes, lastFolder)
    }
}

/// Collects each worker's result.
final class WorkerResults: @unchecked Sendable {
    private let lock = NSLock()
    private var results: [DiskUsageScanner.LocalResult] = []
    func add(_ r: DiskUsageScanner.LocalResult) { lock.lock(); results.append(r); lock.unlock() }
    var all: [DiskUsageScanner.LocalResult] { lock.lock(); defer { lock.unlock() }; return results }
}
