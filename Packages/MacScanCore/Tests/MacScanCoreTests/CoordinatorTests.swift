import Foundation
import Testing
@testable import MacScanCore

/// A deterministic engine for coordinator tests: flags files whose name contains "bad".
struct FakeEngine: ScanEngine {
    let id = EngineID.yara
    let displayName = "Fake"
    var delay: Duration = .zero
    var available = true

    func availability() async -> EngineAvailability {
        available ? .available(detail: "fake") : .notInstalled(instructions: "fake missing")
    }

    func handles(_ item: ScanItem) -> Bool { item.kind == .file }

    func scan(_ items: [ScanItem], context: ScanContext, events: @escaping EngineEventSink) async throws {
        for item in items {
            try Task.checkCancellation()
            if delay > .zero { try await Task.sleep(for: delay) }
            await events(.itemStarted(item.path))
            if item.url.lastPathComponent.contains("bad") {
                await events(.finding(Finding(path: item.path, severity: .threat, engine: id, reason: "bad file", unitPath: item.unitPath)))
            }
            await events(.itemFinished(item.path))
        }
    }
}

final class ProgressLog: @unchecked Sendable {
    private let lock = NSLock()
    private var _values: [ScanProgress] = []
    func append(_ p: ScanProgress) { lock.withLock { _values.append(p) } }
    var values: [ScanProgress] { lock.withLock { _values } }
}

@Suite struct CoordinatorTests {
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))

    @Test func producesThreatsAndCleanRows() async throws {
        let dir = try TempDir()
        let bad = try dir.write("bad.txt", "x")
        let good = try dir.write("good.txt", "y")
        let progress = ProgressLog()

        let coordinator = ScanCoordinator(engines: [FakeEngine()], settings: ScanSettings(), logger: logger)
        let session = await coordinator.run(targets: [.path(dir.url)]) { progress.append($0) }

        #expect(session.status == .completed)
        #expect(session.itemsTotal == 2)
        #expect(session.itemsScanned == 2)
        let threat = try #require(session.findings.first)
        #expect(threat.severity == .threat)
        #expect(threat.path == bad.path)
        #expect(threat.sha256 == (try FileHasher.sha256(of: bad)))
        #expect(session.findings.contains { $0.path == good.path && $0.severity == .clean && $0.engine == .scanner })
        #expect(progress.values.first?.phase == .enumerating)
        #expect(progress.values.contains { $0.phase == .scanning && $0.itemsDone == 2 })
    }

    @Test func ignoreListHidesMatchingFindingUntilFileChanges() async throws {
        let dir = try TempDir()
        let bad = try dir.write("bad.bin", "v1")
        let coordinator = ScanCoordinator(engines: [FakeEngine()], settings: ScanSettings(), logger: logger)
        let first = await coordinator.run(targets: [.path(dir.url)]) { _ in }
        let finding = try #require(first.findings.first { $0.severity == .threat })

        let ignoring = ScanCoordinator(engines: [FakeEngine()], settings: ScanSettings(), ignoreList: IgnoreList(entries: [IgnoreEntry(finding: finding)]), logger: logger)
        let second = await ignoring.run(targets: [.path(dir.url)]) { _ in }
        #expect(!second.findings.contains { $0.severity == .threat })
        #expect(second.ignoredCount == 1)

        try "v2 changed".write(to: bad, atomically: true, encoding: .utf8)
        let third = await ignoring.run(targets: [.path(dir.url)]) { _ in }
        #expect(third.findings.contains { $0.severity == .threat }, "changed file must be reported again")
    }

    @Test func cancellationReturnsPartialSession() async throws {
        let dir = try TempDir()
        for i in 0..<50 { try dir.write("f\(i).txt", "x") }
        let coordinator = ScanCoordinator(engines: [FakeEngine(delay: .milliseconds(50))], settings: ScanSettings(), logger: logger)
        let task = Task { await coordinator.run(targets: [.path(dir.url)]) { _ in } }
        try await Task.sleep(for: .milliseconds(300))
        task.cancel()
        let session = await task.value
        #expect(session.status == .cancelled)
        #expect(session.itemsScanned < 50)
    }

    @Test func unavailableEnginesAreNotedAndNoEnginesFails() async throws {
        let dir = try TempDir()
        try dir.write("a.txt", "x")
        let coordinator = ScanCoordinator(engines: [FakeEngine(available: false)], settings: ScanSettings(), logger: logger)
        let session = await coordinator.run(targets: [.path(dir.url)]) { _ in }
        #expect(session.status == .failed)
        #expect(session.notes.contains { $0.contains("fake missing") })
    }

    @Test func appBundleRollsUpToOneCleanRow() async throws {
        let dir = try TempDir()
        let app = try dir.makeApp("Rollup")
        let coordinator = ScanCoordinator(engines: [FakeEngine()], settings: ScanSettings(), logger: logger)
        let session = await coordinator.run(targets: [.path(dir.url)]) { _ in }
        #expect(session.findings.count == 1)
        #expect(session.findings.first?.path == app.path)
        #expect(session.findings.first?.severity == .clean)
    }

    @Test(.enabled(if: ToolLocator.autodetect(.yara) != nil, "yara not installed"))
    func endToEndWithRealEngines() async throws {
        let dir = try TempDir()
        let eicar = try dir.write("eicar.com", EICAR.string)
        try dir.write("plain.txt", "hello")
        let adhoc = try dir.copy("/usr/bin/true", to: "tool")
        try shell("/usr/bin/codesign", ["--force", "--sign", "-", adhoc.path])

        var settings = ScanSettings()
        settings.enableClamAV = false // official DB may not be downloaded on this machine
        let coordinator = ScanCoordinator(engines: EngineFactory.makeEngines(settings: settings), settings: settings, logger: logger)
        let session = await coordinator.run(targets: [.path(dir.url)]) { _ in }

        #expect(session.enginesUsed.contains(.yara))
        #expect(session.enginesUsed.contains(.integrity))
        #expect(session.findings.contains { $0.path == eicar.path && $0.engine == .yara && $0.severity == .threat })
        #expect(session.findings.contains { $0.path == adhoc.path && $0.engine == .integrity && $0.severity == .warning })
        #expect(session.findings.contains { $0.path.hasSuffix("plain.txt") && $0.severity == .clean })
    }
}

@Suite struct PersistenceAndExportTests {
    func sampleSession() -> ScanSession {
        var s = ScanSession(targets: ["/tmp/x"])
        s.findings = [
            Finding(path: "/tmp/x/a,b \"quoted\".txt", severity: .threat, engine: .clamav, reason: "ClamAV: Eicar", detail: "line1\nline2", sha256: "abc"),
            Finding(path: "/tmp/x/=cmd.txt", severity: .clean, engine: .scanner, reason: "No issues found"),
        ]
        s.finishedAt = Date()
        return s
    }

    @Test func csvEscaping() {
        let csv = ScanExporter.csv([sampleSession()])
        let lines = csv.components(separatedBy: "\r\n")
        #expect(lines[0] == ScanExporter.csvHeader.joined(separator: ","))
        #expect(csv.contains(#""/tmp/x/a,b ""quoted"".txt""#))
        #expect(csv.contains("\"line1\nline2\""))
        #expect(ScanExporter.escape("=SUM(A1)") == "'=SUM(A1)")
        #expect(ScanExporter.escape("plain") == "plain")
    }

    @Test func jsonRoundTrip() throws {
        let s = sampleSession()
        let data = try ScanExporter.json([s])
        let decoded = try JSONDecoder.macScan.decode(ScanSession.self, from: data)
        #expect(decoded.id == s.id)
        #expect(decoded.findings.count == 2)
        let many = try ScanExporter.json([s, s])
        #expect(try JSONDecoder.macScan.decode([ScanSession].self, from: many).count == 2)
    }

    @Test func historyStoreSaveLoadDeletePrune() throws {
        let dir = try TempDir()
        let store = HistoryStore(directory: dir.url, maxSessions: 2)
        var a = ScanSession(startedAt: Date(timeIntervalSinceNow: -300))
        a.targets = ["a"]
        let b = ScanSession(startedAt: Date(timeIntervalSinceNow: -200))
        let c = ScanSession(startedAt: Date(timeIntervalSinceNow: -100))
        try store.save(a)
        try store.save(b)
        try store.save(c)
        let all = store.loadAll()
        #expect(all.map(\.id) == [c.id, b.id], "newest first, oldest pruned")
        try store.delete(b.id)
        #expect(store.loadAll().map(\.id) == [c.id])
    }

    @Test func ignoreListPersistence() throws {
        let dir = try TempDir()
        let file = dir.url.appendingPathComponent("ignored.json")
        let f = Finding(path: "/x", severity: .warning, engine: .integrity, reason: "Unsigned executable", sha256: "h1")
        try IgnoreList(entries: [IgnoreEntry(finding: f)]).save(to: file)
        let loaded = IgnoreList.load(from: file)
        #expect(loaded.entries.count == 1)
        #expect(loaded.filter([f]).1 == 1)
        var changed = f
        changed.sha256 = "h2"
        #expect(loaded.filter([changed]).1 == 0)
    }

    @Test func targetStoreRoundTrip() throws {
        let dir = try TempDir()
        let suite = "MacScanTests-\(UUID())"
        let store = TargetStore(defaultsSuite: suite)
        store.save([dir.url])
        #expect(store.load().map { Paths.canonical($0).path } == [dir.url.path])
    }
}
