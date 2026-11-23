import Foundation
import Testing
@testable import MacScanCore

/// Records launchctl calls instead of talking to launchd.
final class FakeLaunchctl: LaunchctlRunning, @unchecked Sendable {
    private let lock = NSLock()
    private var _calls: [[String]] = []
    private var loaded = Set<String>()
    /// Number of `bootstrap` calls that fail before one succeeds.
    var bootstrapFailures = 0

    var calls: [[String]] { lock.withLock { _calls } }

    func run(_ arguments: [String]) async -> Int32 {
        lock.withLock {
            _calls.append(arguments)
            switch arguments.first {
            case "bootstrap":
                if bootstrapFailures > 0 { bootstrapFailures -= 1; return 37 }
                loaded.insert((arguments[2] as NSString).lastPathComponent.replacingOccurrences(of: ".plist", with: ""))
                return 0
            case "bootout":
                return loaded.remove((arguments[1] as NSString).lastPathComponent) == nil ? 3 : 0
            case "print":
                return loaded.contains((arguments[1] as NSString).lastPathComponent) ? 0 : 113
            default:
                return 0
            }
        }
    }
}

extension ScanSettings {
    /// Defaults with the startup and new-app watchers off, for tests about the other agents.
    static var noWatchers: ScanSettings {
        var s = ScanSettings()
        s.watchStartupItems = false
        s.watchNewApps = false
        return s
    }
}

final class NotificationRecorder: BackgroundNotifying, @unchecked Sendable {
    private let lock = NSLock()
    private var _sent: [BackgroundNotification] = []
    var sent: [BackgroundNotification] { lock.withLock { _sent } }
    func notify(_ notification: BackgroundNotification) async { lock.withLock { _sent.append(notification) } }
}

@Suite struct BackgroundAgentTests {
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))

    func makeAgent(_ dir: TempDir, launchctl: FakeLaunchctl) -> BackgroundAgent {
        BackgroundAgent(
            executable: URL(fileURLWithPath: "/Applications/MacScan.app/Contents/MacOS/MacScan"),
            directory: dir.url.appendingPathComponent("LaunchAgents"),
            downloadsFolder: dir.url.appendingPathComponent("Downloads"),
            launchctl: launchctl,
            domain: "gui/501",
            retryDelay: .milliseconds(1)
        )
    }

    func readPlist(_ url: URL) throws -> [String: Any] {
        try #require(try PropertyListSerialization.propertyList(from: Data(contentsOf: url), format: nil) as? [String: Any])
    }

    @Test func nothingIsInstalledByDefault() async throws {
        let dir = try TempDir()
        let launchctl = FakeLaunchctl()
        let agent = makeAgent(dir, launchctl: launchctl)
        try await agent.sync(settings: ScanSettings.noWatchers, logger: logger)
        #expect(launchctl.calls.isEmpty)
        #expect(!agent.isInstalled(.scheduled))
        #expect(!agent.isInstalled(.downloads))
    }

    @Test func weeklyScheduleBecomesACalendarInterval() async throws {
        let dir = try TempDir()
        let launchctl = FakeLaunchctl()
        let agent = makeAgent(dir, launchctl: launchctl)
        var settings = ScanSettings.noWatchers
        settings.scheduledScanEnabled = true
        settings.scheduleFrequency = .weekly
        settings.scheduleWeekday = 7
        settings.scheduleHour = 3
        settings.scheduleMinute = 30
        try await agent.sync(settings: settings, logger: logger)

        let plist = try readPlist(agent.plistURL(for: .scheduled))
        #expect(plist["Label"] as? String == "com.local.MacScan.scheduled-scan")
        #expect(plist["ProgramArguments"] as? [String] == ["/Applications/MacScan.app/Contents/MacOS/MacScan", "--macscan-background-scan", "scheduled"])
        #expect(plist["StartCalendarInterval"] as? [String: Int] == ["Hour": 3, "Minute": 30, "Weekday": 7])
        #expect(plist["RunAtLoad"] as? Bool == false)
        #expect(plist["KeepAlive"] == nil)
        #expect(plist["WatchPaths"] == nil)
        #expect(!agent.isInstalled(.downloads))
        #expect(launchctl.calls.last == ["bootstrap", "gui/501", agent.plistURL(for: .scheduled).path])
        #expect(agent.installedExecutable(for: .scheduled) == "/Applications/MacScan.app/Contents/MacOS/MacScan")
    }

    @Test func dailyScheduleHasNoWeekdayAndClampsTheTime() throws {
        let dir = try TempDir()
        let agent = makeAgent(dir, launchctl: FakeLaunchctl())
        var settings = ScanSettings.noWatchers
        settings.scheduledScanEnabled = true
        settings.scheduleHour = 99
        settings.scheduleMinute = -5
        let job = try #require(agent.job(for: .scheduled, settings: settings))
        #expect(job["StartCalendarInterval"] as? [String: Int] == ["Hour": 23, "Minute": 0])
    }

    @Test func downloadsWatcherWatchesTheDownloadsFolder() async throws {
        let dir = try TempDir()
        let launchctl = FakeLaunchctl()
        let agent = makeAgent(dir, launchctl: launchctl)
        var settings = ScanSettings.noWatchers
        settings.watchDownloads = true
        try await agent.sync(settings: settings, logger: logger)

        let plist = try readPlist(agent.plistURL(for: .downloads))
        #expect(plist["WatchPaths"] as? [String] == [dir.url.appendingPathComponent("Downloads").path])
        #expect((plist["ProgramArguments"] as? [String])?.last == "downloads")
        #expect(plist["StartCalendarInterval"] == nil)
        #expect(!agent.isInstalled(.scheduled))
    }

    @Test func syncIsIdempotentReloadsOnChangeAndRemovesWhenTurnedOff() async throws {
        let dir = try TempDir()
        let launchctl = FakeLaunchctl()
        let agent = makeAgent(dir, launchctl: launchctl)
        var settings = ScanSettings.noWatchers
        settings.scheduledScanEnabled = true
        settings.watchDownloads = true
        try await agent.sync(settings: settings, logger: logger)
        let afterInstall = launchctl.calls.count

        // Same settings: only "is it loaded?" checks, no reload.
        try await agent.sync(settings: settings, logger: logger)
        let again = launchctl.calls.dropFirst(afterInstall)
        #expect(again.count == 2)
        #expect(again.allSatisfy { $0.first == "print" })

        // A new time reloads just the schedule.
        settings.scheduleHour = 20
        try await agent.sync(settings: settings, logger: logger)
        let reload = launchctl.calls.dropFirst(afterInstall + 2).map { $0.first ?? "" }
        #expect(reload == ["bootout", "bootstrap", "print"])
        let schedule = try readPlist(agent.plistURL(for: .scheduled))["StartCalendarInterval"] as? [String: Int]
        #expect(schedule?["Hour"] == 20)

        // Turning both off unloads and deletes both plists, and nothing else in the folder.
        let other = try dir.write("LaunchAgents/com.example.other.plist", "keep me")
        try await agent.sync(settings: ScanSettings.noWatchers, logger: logger)
        #expect(!agent.isInstalled(.scheduled))
        #expect(!agent.isInstalled(.downloads))
        #expect(FileManager.default.fileExists(atPath: other.path))
        #expect(launchctl.calls.suffix(2).map { $0.first ?? "" } == ["bootout", "bootout"])
    }

    @Test func bootstrapIsRetriedAndAFailureIsReported() async throws {
        let dir = try TempDir()
        var settings = ScanSettings.noWatchers
        settings.watchDownloads = true

        let flaky = FakeLaunchctl()
        flaky.bootstrapFailures = 2
        try await makeAgent(dir, launchctl: flaky).sync(settings: settings, logger: logger)
        #expect(flaky.calls.filter { $0.first == "bootstrap" }.count == 3)

        let dir2 = try TempDir()
        let broken = FakeLaunchctl()
        broken.bootstrapFailures = 100
        await #expect(throws: BackgroundAgentError.couldNotLoad(label: "com.local.MacScan.downloads-watcher", exitCode: 37)) {
            try await makeAgent(dir2, launchctl: broken).sync(settings: settings, logger: logger)
        }
    }

    @Test func settingsWithoutBackgroundKeysDecodeAsOff() throws {
        let old = Data(#"{"maxFileSizeMB": 250, "elevatedScans": true}"#.utf8)
        let settings = try JSONDecoder().decode(ScanSettings.self, from: old)
        #expect(settings.maxFileSizeMB == 250)
        #expect(!settings.scheduledScanEnabled)
        #expect(!settings.watchDownloads)
        // The startup and new-app watchers are on unless turned off.
        #expect(settings.watchStartupItems && settings.watchNewApps && settings.backgroundScansEnabled)
        #expect(settings.scheduleFrequency == .daily)
        #expect(settings.scheduleHour == 12)

        var changed = ScanSettings.noWatchers
        changed.watchDownloads = true
        changed.scheduleFrequency = .weekly
        let roundTrip = try JSONDecoder().decode(ScanSettings.self, from: JSONEncoder().encode(changed))
        #expect(roundTrip == changed)
    }

    @Test func startupItemsScanLabelsMacScansOwnAgent() throws {
        let entry = PersistenceEntry(
            kind: .userLaunchAgent,
            source: "/Users/x/Library/LaunchAgents/com.local.MacScan.downloads-watcher.plist",
            label: BackgroundAgent.label(for: .downloads),
            program: "/usr/bin/true",
            arguments: ["/usr/bin/true", BackgroundScanWorker.flag, "downloads"]
        )
        let finding = PersistenceScanner().analyze(entry)
        #expect(finding.detail?.contains("MacScan's own background scan agent") == true)

        let stranger = PersistenceEntry(kind: .userLaunchAgent, source: "/x.plist", label: "com.example.agent", program: "/usr/bin/true", arguments: ["/usr/bin/true"])
        #expect(PersistenceScanner().analyze(stranger).detail?.contains("MacScan's own") == false)
    }
}

@Suite struct DownloadsTrackerTests {
    @Test func tracksTopLevelItemsButNotHiddenOrUnfinishedDownloads() throws {
        let dir = try TempDir()
        try dir.write("Downloads/installer.dmg", "dmg")
        try dir.write("Downloads/.DS_Store", "x")
        try dir.write("Downloads/movie.mp4.crdownload", "partial")
        try dir.write("Downloads/Safari.download/Info.plist", "partial")
        try dir.write("Downloads/archive.zip.part", "partial")
        try dir.write("Downloads/Unpacked/inner/file.txt", "nested")
        let tracker = DownloadsTracker(folder: dir.url.appendingPathComponent("Downloads"), stateFile: dir.url.appendingPathComponent("seen.json"))

        let snapshot = try tracker.current()
        #expect(snapshot.keys.sorted() == ["Unpacked", "installer.dmg"])
        #expect(snapshot["installer.dmg"]?.size == 3)
        #expect(snapshot["Unpacked"]?.isDirectory == true)
    }

    @Test func baselineThenOnlyNewAndChangedItemsAreNew() throws {
        let dir = try TempDir()
        let old = try dir.write("Downloads/old.pkg", "old")
        try dir.write("Downloads/same.txt", "same")
        let tracker = DownloadsTracker(folder: dir.url.appendingPathComponent("Downloads"), stateFile: dir.url.appendingPathComponent("seen.json"))
        #expect(tracker.loadSeen() == nil)

        try tracker.baseline()
        let seen = try #require(tracker.loadSeen())
        #expect(DownloadsTracker.newItems(in: try tracker.current(), since: seen).isEmpty)

        try dir.write("Downloads/new.dmg", "new")
        try "old but now longer".write(to: old, atomically: true, encoding: .utf8)
        #expect(DownloadsTracker.newItems(in: try tracker.current(), since: seen) == ["new.dmg", "old.pkg"])

        tracker.forget()
        #expect(tracker.loadSeen() == nil)
    }

    @Test func unreadableFolderThrows() throws {
        let dir = try TempDir()
        let tracker = DownloadsTracker(folder: dir.url.appendingPathComponent("Missing"), stateFile: dir.url.appendingPathComponent("seen.json"))
        #expect(throws: (any Error).self) { try tracker.current() }
    }

    @Test func waitsForAFileThatIsStillBeingWritten() async throws {
        let dir = try TempDir()
        let file = try dir.write("Downloads/growing.bin", "1")
        let tracker = DownloadsTracker(folder: dir.url.appendingPathComponent("Downloads"), stateFile: dir.url.appendingPathComponent("seen.json"))

        let writer = Task {
            for i in 0..<4 {
                try await Task.sleep(for: .milliseconds(60))
                try String(repeating: "x", count: 10 * (i + 2)).write(to: file, atomically: false, encoding: .utf8)
            }
        }
        let settled = await tracker.waitUntilSettled(["growing.bin", "vanished.bin"], interval: .milliseconds(150), timeout: .seconds(10))
        try await writer.value
        #expect(settled.keys.sorted() == ["growing.bin"])
        #expect(settled["growing.bin"]?.size == 50)
    }

    @Test func givesUpWaitingAtTheTimeout() async throws {
        let dir = try TempDir()
        try dir.write("Downloads/a.bin", "1")
        let tracker = DownloadsTracker(folder: dir.url.appendingPathComponent("Downloads"), stateFile: dir.url.appendingPathComponent("seen.json"))
        // The quiet period (5 s) can't pass before the timeout: the item is returned anyway.
        let start = ContinuousClock.now
        let settled = await tracker.waitUntilSettled(["a.bin"], interval: .seconds(5), timeout: .milliseconds(50))
        #expect(settled.keys.sorted() == ["a.bin"])
        #expect(ContinuousClock.now - start < .seconds(2))
    }
}

@Suite struct BackgroundScanWorkerTests {
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))

    struct Fixture {
        let dir: TempDir
        let notifier = NotificationRecorder()
        var env: BackgroundScanEnvironment
        var downloads: URL { dir.url.appendingPathComponent("Downloads") }
    }

    func makeFixture(_ configure: (inout ScanSettings) -> Void, customFolders: [URL] = []) throws -> Fixture {
        let dir = try TempDir()
        try FileManager.default.createDirectory(at: dir.url.appendingPathComponent("Downloads"), withIntermediateDirectories: true)
        var settings = ScanSettings()
        configure(&settings)
        let notifier = NotificationRecorder()
        // Fake persistence roots: a scheduled scan's Startup Items part never reads the real system.
        let locations = PersistenceLocations(home: dir.url.appendingPathComponent("Home"), root: dir.url.appendingPathComponent("Root"), includeCrontab: false)
        var env = BackgroundScanEnvironment(
            settings: settings,
            customFolders: customFolders,
            coordinator: ScanCoordinator(engines: [FakeEngine()], settings: settings, logger: logger, persistenceLocations: locations),
            historyStore: HistoryStore(directory: dir.url.appendingPathComponent("History")),
            downloads: DownloadsTracker(folder: dir.url.appendingPathComponent("Downloads"), stateFile: dir.url.appendingPathComponent("seen.json")),
            notifier: notifier,
            logger: logger
        )
        env.settleInterval = .milliseconds(20)
        env.settleTimeout = .seconds(5)
        env.appSettleInterval = .milliseconds(20)
        env.startupSettle = .zero
        env.appTrackers = [DownloadsTracker(folder: dir.url.appendingPathComponent("Applications"), stateFile: dir.url.appendingPathComponent("apps-seen.json"))]
        var fixture = Fixture(dir: dir, env: env)
        fixture.env.notifier = fixture.notifier
        return fixture
    }

    @Test func doesNothingWhenTurnedOff() async throws {
        let f = try makeFixture { _ in }
        try f.dir.write("Downloads/bad.sh", "x")
        #expect(await BackgroundScanWorker.run(.downloads, environment: f.env).isEmpty)
        #expect(await BackgroundScanWorker.run(.scheduled, environment: f.env).isEmpty)
        #expect(f.env.historyStore.loadAll().isEmpty)
        #expect(f.env.downloads.loadSeen() == nil)
        #expect(f.notifier.sent.isEmpty)
    }

    @Test func firstDownloadsRunOnlyRecordsWhatIsAlreadyThere() async throws {
        let f = try makeFixture { $0.watchDownloads = true }
        try f.dir.write("Downloads/bad-old.sh", "x")
        let sessions = await BackgroundScanWorker.run(.downloads, environment: f.env)
        #expect(sessions.isEmpty)
        #expect(f.env.downloads.loadSeen()?.keys.sorted() == ["bad-old.sh"])
        #expect(f.notifier.sent.isEmpty)
    }

    @Test func scansOnlyNewDownloadsAndNotifiesAboutThreats() async throws {
        let f = try makeFixture { $0.watchDownloads = true }
        try f.dir.write("Downloads/bad-old.sh", "already here")
        try f.env.downloads.baseline()

        let bad = try f.dir.write("Downloads/bad-new.sh", "x")
        try f.dir.write("Downloads/fine.txt", "y")
        try f.dir.write("Downloads/bad-still-downloading.crdownload", "z")
        let sessions = await BackgroundScanWorker.run(.downloads, environment: f.env)

        let session = try #require(sessions.first)
        #expect(sessions.count == 1)
        #expect(session.trigger == .downloads)
        #expect(session.itemsTotal == 2)
        #expect(session.flagged.map(\.path) == [bad.path])
        #expect(session.targets.count == 2)

        let saved = f.env.historyStore.loadAll()
        #expect(saved.map(\.id) == [session.id])
        #expect(saved.first?.trigger == .downloads)

        let note = try #require(f.notifier.sent.first)
        #expect(f.notifier.sent.count == 1)
        #expect(note.title == "MacScan found 1 threat")
        #expect(note.body == "In Downloads: bad-new.sh")
        #expect(note.sessionID == session.id)

        // Nothing new: no scan, no notification. The files are untouched.
        #expect(await BackgroundScanWorker.run(.downloads, environment: f.env).isEmpty)
        #expect(f.notifier.sent.count == 1)
        #expect(FileManager.default.fileExists(atPath: bad.path))

        // A finished download (renamed from .crdownload) is picked up next time.
        try FileManager.default.moveItem(at: f.downloads.appendingPathComponent("bad-still-downloading.crdownload"), to: f.downloads.appendingPathComponent("bad-finished.zip"))
        let next = await BackgroundScanWorker.run(.downloads, environment: f.env)
        #expect(next.first?.targets == [f.downloads.appendingPathComponent("bad-finished.zip").path])
        #expect(f.notifier.sent.count == 2)
    }

    @Test func cleanDownloadsAreSavedQuietlyAndOnlyTheNewestAreKept() async throws {
        let f = try makeFixture { $0.watchDownloads = true }
        try f.env.downloads.baseline()
        for i in 0..<(BackgroundScanWorker.cleanSessionsKept + 3) {
            try f.dir.write("Downloads/photo-\(i).jpg", "pixels")
            #expect(await BackgroundScanWorker.run(.downloads, environment: f.env).count == 1)
        }
        #expect(f.notifier.sent.isEmpty)
        #expect(f.env.historyStore.loadAll().count == BackgroundScanWorker.cleanSessionsKept)
    }

    @Test func removedDownloadsAreForgotten() async throws {
        let f = try makeFixture { $0.watchDownloads = true }
        let file = try f.dir.write("Downloads/gone-soon.txt", "x")
        try f.env.downloads.baseline()
        try FileManager.default.removeItem(at: file)
        #expect(await BackgroundScanWorker.run(.downloads, environment: f.env).isEmpty)
        #expect(f.env.downloads.loadSeen()?.isEmpty == true)
    }

    @Test func scheduledScanCoversCustomFoldersAndNotifiesOnlyAboutNewResults() async throws {
        let folder = try TempDir()
        let bad = try folder.write("bad-one.sh", "x")
        var f = try makeFixture({ $0.scheduledScanEnabled = true }, customFolders: [folder.url, URL(fileURLWithPath: "/nonexistent-macscan-test")])
        // Keep the real /Applications out of the test: scan only the custom folder.
        f.env.settings.excludedPaths = ["/Applications", "~/Applications"]
        f.env.coordinator = ScanCoordinator(
            engines: [FakeEngine()], settings: f.env.settings, logger: logger,
            persistenceLocations: PersistenceLocations(home: f.dir.url.appendingPathComponent("Home"), root: f.dir.url.appendingPathComponent("Root"), includeCrontab: false)
        )

        let first = try #require(await BackgroundScanWorker.run(.scheduled, environment: f.env).first)
        #expect(first.trigger == .scheduled)
        #expect(first.targets == ["Applications", "Startup Items", folder.url.path])
        #expect(first.flagged.map(\.path) == [bad.path])
        #expect(f.notifier.sent.map(\.body) == ["Scheduled scan: bad-one.sh"])

        // Same result again: saved, but no second notification.
        _ = await BackgroundScanWorker.run(.scheduled, environment: f.env)
        #expect(f.notifier.sent.count == 1)
        #expect(f.env.historyStore.loadAll().count == 2)

        // A new threat notifies, and names only the new one.
        try folder.write("bad-two.sh", "x")
        _ = await BackgroundScanWorker.run(.scheduled, environment: f.env)
        #expect(f.notifier.sent.count == 2)
        #expect(f.notifier.sent.last?.title == "MacScan found 1 threat")
        #expect(f.notifier.sent.last?.body == "New since the last scheduled scan: bad-two.sh")
    }

    /// What the fake Full Check reader returns; tests change it between runs.
    final class ExtrasBox: @unchecked Sendable {
        var value = FullCheckExtras(checks: [], privacy: PrivacyReport(grants: [], user: .read(0), system: .read(0)))
    }

    static func grant(_ client: String, _ permission: PrivacyPermission) -> PrivacyGrant {
        PrivacyGrant(permission: permission, client: client, name: client, path: nil, decision: .allowed, detail: nil,
                     signer: nil, risk: .none, reasons: [], modified: nil, services: [])
    }

    func fullCheckFixture(fullCheck: Bool) throws -> (Fixture, ExtrasBox) {
        var f = try makeFixture { $0.scheduledScanEnabled = true; $0.scheduledFullCheck = fullCheck }
        f.env.settings.excludedPaths = ["/Applications", "~/Applications"]
        let home = f.dir.url.appendingPathComponent("Home")
        f.env.coordinator = ScanCoordinator(
            engines: [FakeEngine()], settings: f.env.settings, logger: logger,
            persistenceLocations: PersistenceLocations(home: home, root: f.dir.url.appendingPathComponent("Root"), includeCrontab: false),
            processLister: FakeProcessList(processes: []),
            browserLocations: BrowserLocations(home: home, safariListing: { _ in nil }))
        let box = ExtrasBox()
        f.env = f.env.with(fullCheckReader: { box.value }, tracker: FullCheckChangeTracker(file: f.dir.url.appendingPathComponent("fullcheck-baseline.json")))
        return (f, box)
    }

    @Test func scheduledFullCheckNotifiesAboutChanges() async throws {
        let (f, box) = try fullCheckFixture(fullCheck: true)
        let firewallOn = PostureCheck(id: .firewall, title: "Firewall", status: .pass, summary: "On.")
        box.value = FullCheckExtras(checks: [firewallOn], privacy: PrivacyReport(grants: [Self.grant("Zoom", .camera)], user: .read(1), system: .read(0)))

        // First run: a Full Check that only saves the starting point.
        let first = try #require(await BackgroundScanWorker.run(.scheduled, environment: f.env).first)
        #expect(first.targets == ["Applications", "Startup Items", "Running Processes", "Browser Extensions"])
        #expect(first.title == "Full Check" && first.trigger == .scheduled)
        #expect(first.fullCheck?.tracked == true && first.fullCheck?.changes == nil)
        #expect(first.fullCheck?.security == PostureSummary(passed: 1, total: 1, problems: []))
        #expect(f.notifier.sent.isEmpty)

        // The firewall goes off and Zoom gains Screen Recording.
        box.value = FullCheckExtras(checks: [PostureCheck(id: .firewall, title: "Firewall", status: .warning, summary: "Off.")],
                                    privacy: PrivacyReport(grants: [Self.grant("Zoom", .camera), Self.grant("Zoom", .screenRecording)], user: .read(2), system: .read(0)))
        let second = try #require(await BackgroundScanWorker.run(.scheduled, environment: f.env).first)
        #expect(second.fullCheck?.changes?.count == 2)
        #expect(f.notifier.sent.count == 1)
        #expect(f.notifier.sent.last?.title == "Full Check: 2 changes since the last check")
        #expect(f.notifier.sent.last?.body == "Firewall changed · Zoom: now uses Screen Recording")
        #expect(f.notifier.sent.last?.sessionID == second.id)

        // Nothing new: no notification. A fix alone doesn't notify either.
        _ = await BackgroundScanWorker.run(.scheduled, environment: f.env)
        box.value.checks = [firewallOn]
        let fixed = try #require(await BackgroundScanWorker.run(.scheduled, environment: f.env).first)
        #expect(fixed.fullCheck?.changes?.map(\.kind) == [.settingFixed])
        #expect(f.notifier.sent.count == 1)
    }

    @Test func scheduledScanWithoutFullCheck() async throws {
        let (f, _) = try fullCheckFixture(fullCheck: false)
        let session = try #require(await BackgroundScanWorker.run(.scheduled, environment: f.env).first)
        #expect(session.targets == ["Applications", "Startup Items"])
        #expect(session.fullCheck == nil)
        #expect(!FileManager.default.fileExists(atPath: f.dir.url.appendingPathComponent("fullcheck-baseline.json").path))
    }

    @Test func flaggedNotificationMentionsFullCheckChanges() {
        var session = ScanSession()
        session.trigger = .scheduled
        session.findings = [Finding(path: "/x/bad.sh", severity: .threat, engine: .yara, reason: "r")]
        var info = FullCheckInfo()
        info.changes = [FullCheckChange(kind: .newApp, title: "Foo", detail: "d"), FullCheckChange(kind: .settingFixed, title: "Firewall", detail: "On.")]
        session.fullCheck = info
        let note = BackgroundScanWorker.notification(for: session, previous: nil)
        #expect(note?.title == "MacScan found 1 threat")
        #expect(note?.body == "Scheduled scan: bad.sh · 1 change since the last Full Check")
        #expect(FullCheckChange(kind: .newApp, title: "Foo", detail: "d").shortText == "New app: Foo")
    }

    @Test func scheduledFullCheckSettingDefaultsOn() throws {
        let old = try JSONDecoder().decode(ScanSettings.self, from: Data(#"{"scheduledScanEnabled":true}"#.utf8))
        #expect(old.scheduledFullCheck && old.scheduledScanEnabled)
        var off = ScanSettings()
        off.scheduledFullCheck = false
        #expect(try JSONDecoder().decode(ScanSettings.self, from: JSONEncoder().encode(off)).scheduledFullCheck == false)
    }

    @Test func notificationWordingForWarningsAndManyItems() {
        var session = ScanSession()
        session.trigger = .downloads
        #expect(BackgroundScanWorker.notification(for: session, previous: nil) == nil)

        session.findings = [Finding(path: "/d/clean.txt", severity: .clean, engine: .scanner, reason: "No issues found")]
        #expect(BackgroundScanWorker.notification(for: session, previous: nil) == nil)

        session.findings = (1...5).map { Finding(path: "/d/App\($0).app/Contents/MacOS/x", severity: .warning, engine: .integrity, reason: "unsigned", unitPath: "/d/App\($0).app") }
            + [Finding(path: "/d/App1.app/Contents/MacOS/x", severity: .warning, engine: .yara, reason: "rule", unitPath: "/d/App1.app")]
        let note = BackgroundScanWorker.notification(for: session, previous: nil)
        #expect(note?.title == "MacScan found 5 items to review")
        #expect(note?.body == "In Downloads: App1.app, App2.app, App3.app and 2 more")
    }

    @Test func oldHistoryFilesWithoutATriggerStillLoad() throws {
        let dir = try TempDir()
        let store = HistoryStore(directory: dir.url)
        var session = ScanSession(targets: ["Applications"])
        session.trigger = .scheduled
        try store.save(session)
        #expect(store.loadAll().first?.trigger == .scheduled)

        // A file written before the trigger field existed.
        var json = try #require(try JSONSerialization.jsonObject(with: JSONEncoder.macScan.encode(ScanSession())) as? [String: Any])
        json.removeValue(forKey: "trigger")
        try JSONSerialization.data(withJSONObject: json).write(to: dir.url.appendingPathComponent("\(UUID().uuidString).json"))
        let all = store.loadAll()
        #expect(all.count == 2)
        #expect(all.contains { $0.trigger == nil })
    }
}

@Suite struct LiveWatcherTests {
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))

    func makeEnv(_ dir: TempDir, notifier: NotificationRecorder, configure: (inout ScanSettings) -> Void = { _ in }) throws -> BackgroundScanEnvironment {
        var settings = ScanSettings()
        configure(&settings)
        let locations = PersistenceLocations(home: dir.url.appendingPathComponent("Home"), root: dir.url.appendingPathComponent("Root"), includeCrontab: false)
        try FileManager.default.createDirectory(at: dir.url.appendingPathComponent("Applications"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: dir.url.appendingPathComponent("Home/Library/LaunchAgents"), withIntermediateDirectories: true)
        var env = BackgroundScanEnvironment(
            settings: settings, customFolders: [],
            coordinator: ScanCoordinator(engines: [FakeEngine()], settings: settings, logger: logger, persistenceLocations: locations),
            historyStore: HistoryStore(directory: dir.url.appendingPathComponent("History")),
            downloads: DownloadsTracker(folder: dir.url.appendingPathComponent("Downloads"), stateFile: dir.url.appendingPathComponent("seen.json")),
            notifier: notifier, logger: logger)
        env.appTrackers = [DownloadsTracker(folder: dir.url.appendingPathComponent("Applications"), stateFile: dir.url.appendingPathComponent("apps-seen.json"))]
        env.appSettleInterval = .milliseconds(20)
        env.settleTimeout = .seconds(5)
        env.startupSettle = .zero
        env.startupTracker = StartupChangeTracker(file: dir.url.appendingPathComponent("startup-baseline.json"))
        return env
    }

    func writeAgent(_ dir: TempDir, label: String, program: String) throws {
        let plist: [String: Any] = ["Label": label, "ProgramArguments": [program], "RunAtLoad": true]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: dir.url.appendingPathComponent("Home/Library/LaunchAgents/\(label).plist"))
    }

    @Test func newAppsAreScannedAndOnlyFlaggedOnesNotify() async throws {
        let dir = try TempDir()
        let notifier = NotificationRecorder()
        let env = try makeEnv(dir, notifier: notifier)
        try dir.write("Applications/Old.app/Contents/MacOS/Old", "x")

        // First run only remembers what's there.
        #expect(await BackgroundScanWorker.run(.newApps, environment: env).isEmpty)

        try dir.write("Applications/Fine.app/Contents/MacOS/Fine", "x")
        try dir.write("Applications/notes.txt", "not an app")
        let clean = await BackgroundScanWorker.run(.newApps, environment: env)
        #expect(clean.count == 1 && clean.first?.trigger == .newApps && clean.first?.flagged.isEmpty == true)
        #expect(notifier.sent.isEmpty)

        try dir.write("Applications/Evil.app/Contents/MacOS/bad", "x")
        let flagged = await BackgroundScanWorker.run(.newApps, environment: env)
        #expect(flagged.first?.flagged.count == 1)
        let note = try #require(notifier.sent.first)
        #expect(note.title == "MacScan found 1 threat")
        #expect(note.body == "New or updated app: Evil.app · bad file")

        // Turned off: nothing happens.
        var off = env
        off.settings.watchNewApps = false
        try dir.write("Applications/bad2.app/Contents/MacOS/bad", "x")
        #expect(await BackgroundScanWorker.run(.newApps, environment: off).isEmpty)
    }

    @Test func newStartupItemNotifiesButMacScansOwnDoesNot() async throws {
        let dir = try TempDir()
        let notifier = NotificationRecorder()
        let env = try makeEnv(dir, notifier: notifier)
        try writeAgent(dir, label: "com.example.known", program: "/usr/bin/true")

        // First run saves the starting point; nothing is new yet.
        #expect(await BackgroundScanWorker.run(.startupItems, environment: env).isEmpty)

        // MacScan's own agent appearing is not worth an alert.
        try writeAgent(dir, label: BackgroundAgent.label(for: .newApps), program: "/usr/bin/true")
        #expect(await BackgroundScanWorker.run(.startupItems, environment: env).isEmpty)
        #expect(notifier.sent.isEmpty)

        try writeAgent(dir, label: "com.foo.updater", program: "/tmp/updater.sh")
        let sessions = await BackgroundScanWorker.run(.startupItems, environment: env)
        let session = try #require(sessions.first)
        #expect(session.trigger == .startupItems)
        #expect(env.historyStore.loadAll().map(\.id) == [session.id])
        let note = try #require(notifier.sent.first)
        #expect(note.title.hasPrefix("New startup item") && note.title.hasSuffix(": com.foo.updater"))
        #expect(note.sessionID == session.id)

        // Nothing changed since: no scan saved, no alert.
        #expect(await BackgroundScanWorker.run(.startupItems, environment: env).isEmpty)
        #expect(notifier.sent.count == 1)
    }

    @Test func watcherAgentsWatchTheRightFolders() throws {
        let agent = BackgroundAgent(executable: URL(fileURLWithPath: "/Applications/MacScan.app/Contents/MacOS/MacScan"),
                                    startupFolders: [URL(fileURLWithPath: "/a")], appFolders: [URL(fileURLWithPath: "/b"), URL(fileURLWithPath: "/c")])
        let settings = ScanSettings()
        #expect(agent.job(for: .startupItems, settings: settings)?["WatchPaths"] as? [String] == ["/a"])
        #expect(agent.job(for: .newApps, settings: settings)?["WatchPaths"] as? [String] == ["/b", "/c"])
        #expect((agent.job(for: .newApps, settings: settings)?["ProgramArguments"] as? [String])?.last == "new-apps")
        #expect(agent.job(for: .startupItems, settings: .noWatchers) == nil)
        #expect(BackgroundAgent.label(for: .startupItems) == "com.local.MacScan.startup-watcher")
    }
}
