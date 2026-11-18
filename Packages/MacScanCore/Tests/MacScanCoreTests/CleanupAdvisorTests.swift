import Foundation
import Testing
@testable import MacScanCore

@Suite struct CleanupAdvisorTests {
    @discardableResult
    func file(_ dir: TempDir, _ relative: String, bytes: Int = 4096, age days: Double? = nil) throws -> URL {
        let url = try dir.write(relative, Data(repeating: 0x42, count: bytes))
        if let days {
            try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-days * 86_400)], ofItemAtPath: url.path)
        }
        return url
    }

    func advise(_ home: TempDir) -> (DiskUsageReport, [CleanupSuggestion]) {
        let report = DiskUsageScanner(root: home.url, listedFileMinimum: 1).scan()
        let advisor = CleanupAdvisor(home: home.url, minimumSize: 1, minimumDownloadSize: 1, minimumStaleFileSize: 1)
        return (report, advisor.suggestions(for: report))
    }

    @Test func suggestsKnownCleanupTargets() throws {
        let home = try TempDir()
        try file(home, "Library/Caches/com.app/cache.db", bytes: 50_000)
        try file(home, "Library/Caches/Homebrew/old.tar.gz", bytes: 20_000)       // inside Caches: not listed twice
        try file(home, "Library/Developer/Xcode/DerivedData/App-abc/Build/x.o", bytes: 30_000)
        try file(home, ".Trash/deleted.mov", bytes: 10_000)
        try file(home, "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw", bytes: 80_000)
        try file(home, "Projects/web/node_modules/react/index.js", bytes: 40_000)
        try file(home, "Projects/web/node_modules/a/node_modules/b/i.js", bytes: 5_000)  // nested: covered by the outer one
        try file(home, "Projects/py/.venv/lib/site.py", bytes: 15_000)
        // Tools' own dependencies: deleting them breaks the tool, so they're never suggested.
        try file(home, ".vscode/extensions/ext-1.0/node_modules/x/i.js", bytes: 40_000)
        try file(home, "Library/Application Support/Code/sdk/node_modules/y/i.js", bytes: 40_000)
        try file(home, ".ollama/models/blobs/sha256-abc", bytes: 70_000, age: 800)    // a model, not a "stale file"
        try file(home, "Downloads/Installer.dmg", bytes: 25_000, age: 90)
        try file(home, "Downloads/Fresh.dmg", bytes: 25_000, age: 2)                    // too new
        try file(home, "Downloads/notes.txt", bytes: 25_000, age: 90)                   // not an installer
        try file(home, "Documents/Archive.mov", bytes: 60_000, age: 800)                // large and stale
        try file(home, "Documents/Work.key", bytes: 60_000, age: 3)

        let (_, suggestions) = advise(home)
        let byPath = Dictionary(uniqueKeysWithValues: suggestions.map { ($0.item.path.replacingOccurrences(of: Paths.canonical(home.url).path, with: "~"), $0) })

        #expect(Set(byPath.keys) == [
            "~/Library/Caches", "~/Library/Developer/Xcode/DerivedData", "~/.Trash",
            "~/Library/Containers/com.docker.docker/Data/vms", "~/Projects/web/node_modules", "~/Projects/py/.venv",
            "~/Downloads/Installer.dmg", "~/Documents/Archive.mov", "~/.ollama/models",
        ])
        #expect(byPath["~/.ollama/models"]?.action.isManual == true)
        #expect(byPath["~/Library/Caches"]?.priority == .safe)
        #expect(byPath["~/Library/Caches"]?.action == .trashContents)
        #expect(byPath["~/.Trash"]?.action.isManual == true)
        #expect(byPath["~/Library/Containers/com.docker.docker/Data/vms"]?.priority == .review)
        #expect(byPath["~/Library/Containers/com.docker.docker/Data/vms"]?.action.isManual == true, "never delete Docker.raw in Finder")
        #expect(byPath["~/Projects/web/node_modules"]?.priority == .review)
        #expect(byPath["~/Documents/Archive.mov"]?.explanation.contains("2 years") == true)

        // "Safe to clean" first, then by size.
        let priorities = suggestions.map(\.priority)
        #expect(priorities == priorities.sorted())
        #expect(suggestions.first?.item.path.hasSuffix("Library/Caches") == true)
    }

    @Test func smallItemsAreNotSuggested() throws {
        let home = try TempDir()
        try file(home, "Library/Caches/tiny/x", bytes: 100)
        let report = DiskUsageScanner(root: home.url).scan()
        #expect(CleanupAdvisor(home: home.url).suggestions(for: report).isEmpty, "default threshold is 50 MB")
    }

    @Test func markEmptiedKeepsTheFolder() throws {
        let home = try TempDir()
        try file(home, "Library/Caches/a/x", bytes: 30_000)
        try file(home, "Library/Caches/b/y", bytes: 30_000)
        try file(home, "Documents/keep", bytes: 30_000)
        var report = DiskUsageScanner(root: home.url).scan()
        let caches = Paths.canonical(home.url).path + "/Library/Caches"
        let total = report.totalSize
        let cachesSize = try #require(report.folder(caches)).size
        report.markEmptied(caches)
        #expect(report.folder(caches)?.size == 0)
        #expect(report.children(of: caches).isEmpty)
        #expect(report.totalSize == total - cachesSize)
        #expect(report.folder(Paths.canonical(home.url).path + "/Library")?.size == 0)
        #expect(report.fileCount == 1)
    }
}

extension CleanupAction {
    var isManual: Bool { if case .manual = self { true } else { false } }
}
