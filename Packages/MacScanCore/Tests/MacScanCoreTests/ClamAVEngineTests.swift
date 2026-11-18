import Foundation
import Testing
@testable import MacScanCore

/// ClamAV tests use a tiny custom signature database containing only an EICAR signature,
/// so they don't need the ~300 MB official database. They are skipped if clamscan isn't installed.
@Suite struct ClamAVEngineTests {
    static let clamscan = ToolLocator.autodetect(.clamscan)

    /// Writes an .ndb database whose only signature matches the EICAR test string.
    func makeTestDatabase(in dir: TempDir) throws -> URL {
        let hex = EICAR.string.utf8.map { String(format: "%02x", $0) }.joined()
        try dir.write("db/macscan-test.ndb", "MacScan.Test.EICAR:0:*:\(hex)\n")
        return dir.url.appendingPathComponent("db")
    }

    @Test(.enabled(if: clamscan != nil, "clamscan not installed"))
    func detectsEICAR() async throws {
        let dir = try TempDir()
        let db = try makeTestDatabase(in: dir)
        let eicar = try dir.write("files/eicar.com", EICAR.string)
        let clean = try dir.write("files/clean.txt", "just some text")
        let spaced = try dir.write("files/with space: and colon.txt", EICAR.string)

        let engine = ClamAVEngine(clamscanURL: URL(fileURLWithPath: Self.clamscan!), databaseDirectory: db)
        #expect(await engine.availability().isAvailable)

        let items = [eicar, clean, spaced].map { ScanItem(url: $0, kind: .file) }
        let recorder = EventRecorder()
        try await engine.scan(items, context: .test, events: recorder.sink)

        let findings = await recorder.findings
        #expect(Set(findings.map(\.path)) == [eicar.path, spaced.path])
        #expect(findings.allSatisfy { $0.severity == .threat && $0.engine == .clamav })
        #expect(findings.first?.reason.contains("MacScan.Test.EICAR") == true)
        #expect(Set(await recorder.finished) == Set(items.map(\.path)))
    }

    /// Uses the real signature database if "Update virus database" has been run.
    @Test(.enabled(if: clamscan != nil && ClamAVDatabase.hasDatabase(ClamAVDatabase.resolve(override: nil)), "no official ClamAV database"))
    func detectsEICARWithOfficialDatabase() async throws {
        let dir = try TempDir()
        let eicar = try dir.write("eicar.com", EICAR.string)
        let engine = ClamAVEngine(clamscanURL: URL(fileURLWithPath: Self.clamscan!), databaseDirectory: ClamAVDatabase.resolve(override: nil))
        let recorder = EventRecorder()
        try await engine.scan([ScanItem(url: eicar, kind: .file)], context: .test, events: recorder.sink)
        let findings = await recorder.findings
        #expect(findings.count == 1)
        #expect(findings.first?.reason.lowercased().contains("eicar") == true)
    }

    @Test func missingClamscanIsReportedNotCrashed() async throws {
        let engine = ClamAVEngine(clamscanURL: nil, databaseDirectory: URL(fileURLWithPath: "/nonexistent"))
        guard case .notInstalled(let instructions) = await engine.availability() else {
            Issue.record("expected notInstalled")
            return
        }
        #expect(instructions.contains("brew install clamav"))
        await #expect(throws: EngineError.self) {
            try await engine.scan([ScanItem(url: URL(fileURLWithPath: "/etc/hosts"), kind: .file)], context: .test, events: { _ in })
        }
    }

    @Test(.enabled(if: clamscan != nil, "clamscan not installed"))
    func emptyDatabaseNeedsSetup() async throws {
        let dir = try TempDir()
        let engine = ClamAVEngine(clamscanURL: URL(fileURLWithPath: Self.clamscan!), databaseDirectory: dir.url)
        guard case .needsSetup = await engine.availability() else {
            Issue.record("expected needsSetup")
            return
        }
    }

    @Test func cancellationStopsClamscan() async throws {
        // A stand-in clamscan that never finishes, so cancellation is deterministic.
        let dir = try TempDir()
        let fake = try dir.write("bin/clamscan", "#!/bin/sh\nexec /bin/sleep 30\n")
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fake.path)
        let db = try makeTestDatabase(in: dir)
        let file = try dir.write("f.txt", "x")

        let engine = ClamAVEngine(clamscanURL: fake, databaseDirectory: db)
        let start = ContinuousClock.now
        let task = Task {
            try await engine.scan([ScanItem(url: file, kind: .file)], context: .test, events: { _ in })
        }
        try await Task.sleep(for: .milliseconds(300))
        task.cancel()
        let result = await task.result
        #expect(throws: CancellationError.self) { try result.get() }
        #expect(ContinuousClock.now - start < .seconds(5))
    }

    @Test func parsesOutputLines() {
        #expect(ClamAVEngine.parseLine("/a/b.txt: OK") == .init(path: "/a/b.txt", signature: nil))
        #expect(ClamAVEngine.parseLine("/a/x: y.com: Eicar-Signature FOUND") == .init(path: "/a/x: y.com", signature: "Eicar-Signature"))
        #expect(ClamAVEngine.parseLine("/a/empty: Empty file") == .init(path: "/a/empty", signature: nil))
        #expect(ClamAVEngine.parseLine("LibClamAV Warning: something") == nil)
    }

    @Test func puaIsWarning() {
        let item = ScanItem(url: URL(fileURLWithPath: "/x"), kind: .file)
        #expect(ClamAVEngine.finding(for: item, signature: "PUA.Osx.Adware.Foo").severity == .warning)
        #expect(ClamAVEngine.finding(for: item, signature: "Osx.Trojan.Bar").severity == .threat)
    }
}
