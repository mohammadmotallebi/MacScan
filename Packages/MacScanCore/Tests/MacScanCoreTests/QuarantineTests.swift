import Foundation
import Testing
@testable import MacScanCore

@Suite struct QuarantineTests {
    let dir: TempDir
    let store: QuarantineStore

    init() throws {
        dir = try TempDir()
        store = QuarantineStore(directory: dir.url.appendingPathComponent("Quarantine"))
    }

    func mode(_ url: URL) -> mode_t {
        var info = stat()
        lstat(url.path, &info)
        return info.st_mode & 0o7777
    }

    @Test func fileIsMovedLockedAndRestoredExactly() throws {
        let file = try dir.write("work/tool.sh", "#!/bin/sh\necho hi\n")
        chmod(file.path, 0o755)

        let item = try store.quarantine(path: file.path, reason: "EICAR test", engine: .clamav)
        #expect(!FileManager.default.fileExists(atPath: file.path))
        #expect(item.name == "tool.sh")
        #expect(item.size == 18)
        #expect(item.originalMode == 0o755)
        #expect(item.sha256 == FileHasher.sha256(of: Data("#!/bin/sh\necho hi\n".utf8)))
        #expect(store.list() == [item] || store.list().map(\.id) == [item.id])

        let payload = store.directory.appendingPathComponent("\(item.id.uuidString)/payload")
        #expect(mode(payload) == 0, "locked: nobody can read or run it")
        #expect((try? Data(contentsOf: payload)) == nil)

        try store.restore(item)
        #expect(try String(contentsOf: file, encoding: .utf8) == "#!/bin/sh\necho hi\n")
        #expect(mode(file) == 0o755)
        #expect(store.list().isEmpty)
        #expect(!FileManager.default.fileExists(atPath: store.directory.appendingPathComponent(item.id.uuidString).path))
    }

    @Test func appBundlesAreQuarantinedWhole() throws {
        let app = try dir.makeApp("Suspect")
        let item = try store.quarantine(path: app.path, reason: "Self-signed")
        #expect(item.isDirectory)
        #expect(item.size == nil)
        #expect(!FileManager.default.fileExists(atPath: app.path))
        try store.restore(item)
        #expect(FileManager.default.isExecutableFile(atPath: app.appendingPathComponent("Contents/MacOS/Suspect").path))
    }

    @Test func restoreRefusesToOverwriteOrGuessAFolder() throws {
        let file = try dir.write("a/one.txt", "one")
        let item = try store.quarantine(path: file.path, reason: "r")

        try dir.write("a/one.txt", "newer")
        #expect(throws: QuarantineError.restoreTargetExists(file.path)) { try store.restore(item) }
        #expect(try String(contentsOf: file, encoding: .utf8) == "newer")
        #expect(store.list().count == 1, "still safely in quarantine, still locked")
        #expect(mode(store.directory.appendingPathComponent("\(item.id.uuidString)/payload")) == 0)

        try FileManager.default.removeItem(at: file.deletingLastPathComponent())
        #expect(throws: QuarantineError.restoreFolderMissing(file.deletingLastPathComponent().path)) { try store.restore(item) }
        #expect(store.list().count == 1)
    }

    @Test func deleteRemovesFilesAndLockedFolders() throws {
        let file = try dir.write("x.bin", "x")
        let app = try dir.makeApp("Gone")
        let first = try store.quarantine(path: file.path, reason: "r")
        let second = try store.quarantine(path: app.path, reason: "r")
        #expect(store.list().count == 2)
        try store.delete(first)
        try store.delete(second)
        #expect(store.list().isEmpty)
        #expect((try FileManager.default.contentsOfDirectory(atPath: store.directory.path)).isEmpty)
    }

    @Test func refusesSystemLocationsMissingFilesAndItself() throws {
        #expect(throws: QuarantineError.protectedLocation("/System/Library/CoreServices/Finder.app")) {
            try store.quarantine(path: "/System/Library/CoreServices/Finder.app", reason: "r")
        }
        #expect(throws: QuarantineError.protectedLocation("/Applications")) { try store.quarantine(path: "/Applications", reason: "r") }
        let missing = dir.url.appendingPathComponent("nope").path
        #expect(throws: QuarantineError.notFound(missing)) { try store.quarantine(path: missing, reason: "r") }

        let file = try dir.write("y.bin", "y")
        let item = try store.quarantine(path: file.path, reason: "r")
        let inside = store.directory.appendingPathComponent("\(item.id.uuidString)/payload").path
        #expect(throws: QuarantineError.protectedLocation(inside)) { try store.quarantine(path: inside, reason: "r") }
        #expect(store.list().count == 1)
    }

    @Test func symlinksAreMovedAsLinks() throws {
        let target = try dir.write("real.txt", "real")
        let link = dir.url.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let item = try store.quarantine(path: link.path, reason: "r")
        #expect(try String(contentsOf: target, encoding: .utf8) == "real", "the link's target is untouched")
        #expect(mode(target) != 0)
        try store.restore(item)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == target.path)
    }
}
