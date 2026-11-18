import Foundation
import Testing
@testable import MacScanCore

@Suite struct DiskUsageTests {
    /// Writes a file of `bytes` bytes (allocated size is at least that, rounded up to blocks).
    @discardableResult
    func file(_ dir: TempDir, _ relative: String, bytes: Int) throws -> URL {
        try dir.write(relative, Data(repeating: 0x41, count: bytes))
    }

    func allocated(_ url: URL) -> Int64 {
        let v = try? url.resourceValues(forKeys: [.totalFileAllocatedSizeKey, .fileAllocatedSizeKey])
        return Int64(v?.totalFileAllocatedSize ?? v?.fileAllocatedSize ?? 0)
    }

    @Test func addsUpFoldersAndFindsLargestFiles() throws {
        let dir = try TempDir()
        let big = try file(dir, "Movies/big.mov", bytes: 3_000_000)
        let mid = try file(dir, "Movies/Clips/mid.mp4", bytes: 2_000_000)
        let small1 = try file(dir, "Documents/a.txt", bytes: 10_000)
        let small2 = try file(dir, "Documents/b.txt", bytes: 20_000)
        let pkg = try file(dir, "Apps/Tool.app/Contents/MacOS/Tool", bytes: 1_500_000)
        // A symlink to a big folder must not be followed or counted.
        try FileManager.default.createSymbolicLink(at: dir.url.appendingPathComponent("Link"), withDestinationURL: dir.url.appendingPathComponent("Movies"))

        let report = DiskUsageScanner(root: dir.url, largestFileCount: 3, listedFileMinimum: 1_000_000).scan()
        let root = report.root
        let expectedTotal = [big, mid, small1, small2, pkg].map(allocated).reduce(0, +)
        #expect(report.totalSize == expectedTotal)
        #expect(report.fileCount == 5)
        #expect(!report.cancelled)

        // Largest files: top 3, biggest first.
        #expect(report.largestFiles.map(\.name) == ["big.mov", "mid.mp4", "Tool"])

        // Root children: folders sorted by size, no symlink.
        let top = report.children(of: root)
        #expect(top.map(\.name) == ["Movies", "Apps", "Documents"])
        let movies = try #require(top.first)
        #expect(movies.size == allocated(big) + allocated(mid))
        #expect(movies.fileCount == 2)
        #expect(report.folder(root + "/Apps/Tool.app")?.isPackage == true)

        // Inside Documents both files are below the listing threshold: one "smaller files" entry.
        let docs = report.children(of: root + "/Documents")
        #expect(docs.count == 1)
        #expect(docs.first?.isAggregate == true)
        #expect(docs.first?.size == allocated(small1) + allocated(small2))
        #expect(docs.first?.name == "2 smaller files")

        // Largest folders skip the insides of packages.
        let folders = report.largestFolders().map { $0.path.replacingOccurrences(of: root, with: "") }
        #expect(folders.first == "/Movies")
        #expect(folders.contains("/Apps/Tool.app"))
        #expect(!folders.contains("/Apps/Tool.app/Contents"))
    }

    @Test func markRemovedUpdatesEveryFolderAbove() throws {
        let dir = try TempDir()
        let big = try file(dir, "Movies/Clips/big.mov", bytes: 3_000_000)
        try file(dir, "Movies/keep.mov", bytes: 1_200_000)
        var report = DiskUsageScanner(root: dir.url, listedFileMinimum: 1_000_000).scan()
        let root = report.root
        let total = report.totalSize
        let item = try #require(report.largestFiles.first { $0.name == "big.mov" })
        report.markRemoved(item)
        #expect(report.totalSize == total - allocated(big))
        #expect(report.folder(root + "/Movies/Clips")?.size == 0)
        #expect(report.folder(root + "/Movies")?.fileCount == 1)
        #expect(!report.largestFiles.contains { $0.name == "big.mov" })
        #expect(report.children(of: root + "/Movies/Clips").isEmpty)

        // Removing a whole folder drops it and its files from the report.
        let movies = try #require(report.folder(root + "/Movies"))
        report.markRemoved(movies)
        #expect(report.totalSize == 0)
        #expect(report.children(of: root).isEmpty)
        #expect(report.largestFiles.isEmpty)
        #expect(report.fileCount == 0)
    }

    @Test func cancellationReturnsPartialResults() async throws {
        let dir = try TempDir()
        for i in 0..<600 { try file(dir, "many/f\(i).dat", bytes: 100) }
        let scanner = DiskUsageScanner(root: dir.url)
        let task = Task.detached { () -> DiskUsageReport in
            withUnsafeCurrentTask { $0?.cancel() }
            return scanner.scan()
        }
        let report = await task.value
        #expect(report.cancelled)
        #expect(report.fileCount < 600)
    }

    @Test func reportsUnreadableFolders() throws {
        let dir = try TempDir()
        try file(dir, "locked/secret.dat", bytes: 100)
        try file(dir, "open/ok.dat", bytes: 100)
        let locked = dir.url.appendingPathComponent("locked")
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: locked.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: locked.path) }
        let report = DiskUsageScanner(root: dir.url).scan()
        #expect(report.unreadableCount == 1)
        #expect(report.unreadable.first?.hasSuffix("/locked") == true)
        #expect(report.fileCount == 1)
    }

    @Test func largestFoldersIsFastAndSkipsPackageInsides() {
        // 20,000 apps × (bundle + Contents + Resources) and 140,000 plain folders: ~200k folders.
        typealias Folder = DiskUsageReport.Folder
        var folders: [String: Folder] = ["/r": Folder()]
        for i in 0..<20_000 {
            let app = "/r/Apps/A\(i).app"
            folders[app] = Folder(size: Int64(i), isPackage: true)
            folders[app + "/Contents"] = Folder(size: Int64(i))
            folders[app + "/Contents/Resources"] = Folder(size: 10_000_000)   // huge, but inside a package
        }
        for i in 0..<140_000 { folders["/r/Data/d\(i % 100)/f\(i)"] = Folder(size: Int64(i)) }
        folders["/r/Apps"] = Folder(size: 1)
        folders["/r/Data"] = Folder(size: 1)
        for i in 0..<100 { folders["/r/Data/d\(i)"] = Folder(size: 1) }
        folders["/r/Data/d7/f7/Deep.bundle"] = Folder(size: 9_999_999, isPackage: true)
        folders["/r/Data/d7/f7/Deep.bundle/Contents"] = Folder(size: 9_999_999)

        let start = ContinuousClock.now
        let top = DiskUsageReport.computeTopFolders(folders, root: "/r", keep: 200)
        let elapsed = ContinuousClock.now - start
        #expect(elapsed < .seconds(2), "took \(elapsed)")
        #expect(top.count == 200)
        #expect(top.first == "/r/Data/d7/f7/Deep.bundle", "a package itself is listed")
        #expect(!top.contains { $0.contains(".app/") || $0.contains(".bundle/") }, "nothing inside packages")
        #expect(!top.contains("/r"))
    }

    @Test func largestFoldersCollapsesSingleChildChains() {
        typealias Folder = DiskUsageReport.Folder
        let folders: [String: Folder] = [
            "/r": Folder(size: 1_000, childFolders: ["/r/Containers", "/r/Other"]),
            "/r/Containers": Folder(size: 900, childFolders: ["/r/Containers/docker", "/r/Containers/small"]),
            "/r/Containers/docker": Folder(size: 880, childFolders: ["/r/Containers/docker/vms"]),
            "/r/Containers/docker/vms": Folder(size: 879),        // holds the big file itself
            "/r/Containers/small": Folder(size: 20),
            "/r/Other": Folder(size: 100, childFolders: ["/r/Other/a", "/r/Other/b"]),
            "/r/Other/a": Folder(size: 60),
            "/r/Other/b": Folder(size: 40),
        ]
        let top = DiskUsageReport.computeTopFolders(folders, root: "/r", keep: 10)
        #expect(top == ["/r/Containers/docker/vms", "/r/Other", "/r/Other/a", "/r/Other/b", "/r/Containers/small"])
    }
}
