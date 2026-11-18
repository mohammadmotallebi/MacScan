import Foundation
import Testing
@testable import MacScanCore

@Suite struct FileEnumeratorTests {
    @Test func findsFilesAndBundles() throws {
        let dir = try TempDir()
        try dir.write("a.txt", "hello")
        try dir.write("sub/b.txt", "world")
        let app = try dir.makeApp("Demo")

        let result = try FileEnumerator(settings: ScanSettings()).enumerate([.path(dir.url)])
        let paths = Set(result.items.map(\.path))
        #expect(paths.contains(dir.url.appendingPathComponent("a.txt").path))
        #expect(paths.contains(dir.url.appendingPathComponent("sub/b.txt").path))

        let bundle = try #require(result.items.first { $0.kind == .appBundle })
        #expect(bundle.path == app.path)

        let exe = try #require(result.items.first { $0.path.hasSuffix("Contents/MacOS/Demo") })
        #expect(exe.isMachO)
        #expect(exe.bundleURL?.path == app.path)
        #expect(exe.unitPath == app.path)

        let readme = try #require(result.items.first { $0.path.hasSuffix("readme.txt") })
        #expect(!readme.isMachO)
        #expect(readme.bundleURL?.path == app.path)
    }

    @Test func respectsExclusionsAndSizeLimit() throws {
        let dir = try TempDir()
        try dir.write("keep.txt", "x")
        try dir.write("excluded/secret.txt", "x")
        try dir.write("big.bin", Data(count: 2 * 1024 * 1024))

        var settings = ScanSettings()
        settings.excludedPaths = [dir.url.appendingPathComponent("excluded").path]
        settings.maxFileSizeMB = 1
        let result = try FileEnumerator(settings: settings).enumerate([.path(dir.url)])
        let names = result.items.map(\.url.lastPathComponent)
        #expect(names == ["keep.txt"])
        #expect(result.skippedCount == 1)
    }

    @Test func symlinkHandling() throws {
        let dir = try TempDir()
        let real = try dir.write("real/target.txt", "x")
        let other = try TempDir()
        let outside = try other.write("outside.txt", "y")
        try FileManager.default.createSymbolicLink(at: dir.url.appendingPathComponent("link-in.txt"), withDestinationURL: real)
        try FileManager.default.createSymbolicLink(at: dir.url.appendingPathComponent("link-out.txt"), withDestinationURL: outside)

        var settings = ScanSettings()
        settings.skipSymlinks = true
        var result = try FileEnumerator(settings: settings).enumerate([.path(dir.url)])
        #expect(result.items.count == 1)
        #expect(result.skippedCount == 0)

        settings.skipSymlinks = false
        result = try FileEnumerator(settings: settings).enumerate([.path(dir.url)])
        let paths = Set(result.items.map(\.path))
        // The in-tree target is listed once (deduplicated); the outside target is followed.
        #expect(paths == [real.path, outside.path])
    }

    @Test func applicationsModeKeepsOnlyExecutableContent() throws {
        let dir = try TempDir()
        try dir.makeApp("Exec")
        try dir.write("Exec.app/Contents/Resources/install.sh", "#!/bin/sh\necho hi\n")

        var settings = ScanSettings()
        settings.appScanExecutablesOnly = true
        let result = try FileEnumerator(settings: settings).enumerate(root: dir.url, applicationsMode: true)
        let names = Set(result.items.map(\.url.lastPathComponent))
        #expect(names.contains("Exec.app"))
        #expect(names.contains("Exec"))
        #expect(names.contains("install.sh"))
        #expect(!names.contains("readme.txt"))
        #expect(!names.contains("Info.plist"))
    }

    @Test func singleFileTarget() throws {
        let dir = try TempDir()
        let f = try dir.write("one.txt", "1")
        let result = try FileEnumerator(settings: ScanSettings()).enumerate([.path(f)])
        #expect(result.items.map(\.path) == [f.path])
    }

    @Test func missingPathIsAnIssueNotACrash() throws {
        let result = try FileEnumerator(settings: ScanSettings()).enumerate([.path(URL(fileURLWithPath: "/nonexistent/xyz"))])
        #expect(result.items.isEmpty)
        #expect(result.issues.count == 1)
        #expect(result.issues[0].isPermissionDenied == false)
    }

    @Test func unreadableDirectoryIsPermissionIssue() throws {
        let dir = try TempDir()
        let locked = dir.url.appendingPathComponent("locked")
        try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: locked.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: locked.path) }

        let result = try FileEnumerator(settings: ScanSettings()).enumerate([.path(locked)])
        #expect(result.issues.first?.isPermissionDenied == true)
    }

    @Test func machODetection() throws {
        #expect(MachO.inspect(path: "/usr/bin/true") == .executableCode)
        let dir = try TempDir()
        let text = try dir.write("t.txt", "not a binary")
        #expect(MachO.inspect(path: text.path) == .notMachO)
        // Java class files share the 0xCAFEBABE magic; make sure they're not treated as fat Mach-O.
        let java = try dir.write("A.class", Data([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0, 0, 0, 0]))
        #expect(MachO.inspect(path: java.path) == .notMachO)
    }
}
