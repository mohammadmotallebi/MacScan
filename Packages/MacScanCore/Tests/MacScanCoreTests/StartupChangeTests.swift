import Foundation
import Testing
@testable import MacScanCore

@Suite struct StartupChangeTests {
    let dir: TempDir
    let root: TempDir
    let home: TempDir
    let tracker: StartupChangeTracker

    init() throws {
        dir = try TempDir()
        root = try TempDir()
        home = try TempDir()
        tracker = StartupChangeTracker(file: dir.url.appendingPathComponent("baseline.json"))
    }

    func writeAgent(_ name: String, _ arguments: [String]) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: ["Label": name, "ProgramArguments": arguments], format: .xml, options: 0)
        try home.write("Library/LaunchAgents/\(name).plist", data)
    }

    func scan() async -> ScanSession {
        var settings = ScanSettings()
        settings.enableClamAV = false
        settings.enableYara = false
        let coordinator = ScanCoordinator(
            engines: EngineFactory.makeEngines(settings: settings), settings: settings,
            logger: FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs")),
            persistenceLocations: PersistenceLocations(home: home.url, root: root.url, includeCrontab: false))
        return await coordinator.run(targets: [.startupItems]) { _ in }
    }

    @Test func differencesNameWhatChanged() {
        let old = StartupItemState(name: "a", program: "/usr/bin/true", arguments: ["/usr/bin/true", "--x"], signer: "Team ABC", contentHash: "1")
        #expect(old.differences(from: old).isEmpty)
        var new = old
        new.name = "renamed"   // display only
        #expect(new.differences(from: old).isEmpty)
        new.program = "/tmp/evil"
        new.arguments = ["/tmp/evil"]
        new.signer = "unsigned"
        new.contentHash = "2"
        #expect(new.differences(from: old) == [
            "Program changed: /usr/bin/true → /tmp/evil", "Arguments changed (were: --x)",
            "Signer changed: Team ABC → unsigned", "File contents changed",
        ])
        #expect(StartupItemState.signerSummary(.unreadable("x")) == nil)
        #expect(StartupItemState.signerSummary(.signed(identifier: nil, teamID: "ABC", authority: "Dev")) == "Team ABC")
    }

    @Test func firstScanSavesABaselineAndLaterScansReportChanges() async throws {
        try writeAgent("com.example.keep", ["/usr/bin/true"])
        try writeAgent("com.example.edit", ["/usr/bin/true", "--old"])
        try writeAgent("com.example.gone", ["/usr/bin/true"])
        try home.write(".zshrc", "export A=1\n")

        var first = await scan()
        #expect(first.startupSnapshot?.count == 4)
        tracker.apply(to: &first)
        #expect(first.startupSnapshot == nil)
        #expect(first.startupChanges == nil)
        #expect(first.findings.allSatisfy { $0.change == nil })
        #expect(first.notes.contains { $0.hasPrefix("Startup items: baseline saved (4 items)") })

        // Nothing changed.
        var same = await scan()
        tracker.apply(to: &same)
        #expect(same.startupChanges?.isEmpty == true)
        #expect(same.notes.contains { $0.hasPrefix("Startup items: nothing added, changed or removed") })

        try writeAgent("com.example.new", ["/usr/bin/true"])
        try writeAgent("com.example.edit", ["/usr/bin/true", "--new"])
        try FileManager.default.removeItem(at: home.url.appendingPathComponent("Library/LaunchAgents/com.example.gone.plist"))
        try home.write(".zshrc", "export A=2\n")

        var second = await scan()
        tracker.apply(to: &second)
        let changes = try #require(second.startupChanges)
        #expect(changes.added == ["com.example.new"])
        #expect(changes.changed.sorted() == [".zshrc", "com.example.edit"])
        #expect(changes.removed == ["com.example.gone"])
        func finding(_ suffix: String) -> Finding? { second.findings.first { $0.engine == .persistence && $0.path.hasSuffix(suffix) } }
        #expect(finding("com.example.new.plist")?.change == .new)
        #expect(finding("com.example.new.plist")?.detail?.hasPrefix("New since the scan on ") == true)
        #expect(finding("com.example.edit.plist")?.change == .changed)
        #expect(finding("com.example.edit.plist")?.detail?.contains("• Arguments changed (were: --old)") == true)
        #expect(finding(".zshrc")?.detail?.contains("• File contents changed") == true)
        #expect(finding("com.example.keep.plist")?.change == nil)
        #expect(second.notes.contains { $0.contains("1 new (com.example.new); 2 changed") && $0.contains("1 removed (com.example.gone)") })

        // The change was recorded: the next scan is quiet again.
        var third = await scan()
        tracker.apply(to: &third)
        #expect(third.startupChanges?.isEmpty == true)
        #expect(third.findings.allSatisfy { $0.change == nil })
    }

    @Test func otherScansLeaveTheBaselineAlone() async throws {
        var session = ScanSession(targets: ["Applications"])
        tracker.apply(to: &session)
        #expect(session.notes.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: tracker.file.path))
    }

    @Test func sessionsWithChangesSurviveJSONAndOldSessionsStillDecode() throws {
        var session = ScanSession(targets: ["Startup Items"])
        var finding = Finding(path: "/x.plist", severity: .clean, engine: .persistence, reason: "r")
        finding.change = .new
        session.findings = [finding]
        session.startupChanges = StartupChangeSummary(since: Date(timeIntervalSince1970: 0), added: ["x"])
        let decoded = try JSONDecoder.macScan.decode(ScanSession.self, from: JSONEncoder.macScan.encode(session))
        #expect(decoded.findings.first?.change == .new)
        #expect(decoded.startupChanges?.added == ["x"])

        // History written before this feature has none of the new keys.
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder.macScan.encode(ScanSession())) as? [String: Any])
        object.removeValue(forKey: "startupChanges")
        object.removeValue(forKey: "startupSnapshot")
        _ = try JSONDecoder.macScan.decode(ScanSession.self, from: JSONSerialization.data(withJSONObject: object))
    }

    @Test func scheduledScanNotifiesAboutNewStartupItems() {
        var session = ScanSession()
        session.trigger = .scheduled
        #expect(BackgroundScanWorker.notification(for: session, previous: nil) == nil)
        session.startupChanges = StartupChangeSummary(since: Date(), removed: ["old"])
        #expect(BackgroundScanWorker.notification(for: session, previous: nil) == nil, "a removed item alone is not worth a notification")
        session.startupChanges = StartupChangeSummary(since: Date(), added: ["com.example.new"])
        #expect(BackgroundScanWorker.notification(for: session, previous: nil) == BackgroundNotification(title: "MacScan: 1 new startup item", body: "com.example.new", sessionID: session.id))
        session.startupChanges?.changed = [".zshrc"]
        #expect(BackgroundScanWorker.notification(for: session, previous: nil)?.title == "MacScan: 2 new or changed startup items")
        session.findings = [Finding(path: "/tmp/bad", severity: .threat, engine: .clamav, reason: "EICAR")]
        #expect(BackgroundScanWorker.notification(for: session, previous: nil)?.body == "Scheduled scan: bad · 2 new or changed startup items")
    }
}
