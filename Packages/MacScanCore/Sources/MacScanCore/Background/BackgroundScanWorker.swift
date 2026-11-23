import Foundation

/// A notification the background worker wants to show. The app target delivers it.
public struct BackgroundNotification: Sendable, Equatable {
    public var title: String
    public var body: String
    /// The scan to open when the notification is clicked.
    public var sessionID: UUID?

    public init(title: String, body: String, sessionID: UUID? = nil) {
        self.title = title
        self.body = body
        self.sessionID = sessionID
    }
}

public protocol BackgroundNotifying: Sendable {
    func notify(_ notification: BackgroundNotification) async
}

/// Everything a background scan reads and writes. `live` is the real thing; tests build their own.
public struct BackgroundScanEnvironment: Sendable {
    public var settings: ScanSettings
    public var customFolders: [URL]
    public var coordinator: ScanCoordinator
    public var historyStore: HistoryStore
    public var downloads: DownloadsTracker
    public var notifier: any BackgroundNotifying
    public var logger: FileLogger
    /// Marks new and changed startup items in scheduled scans. Nil turns that off (tests).
    public var startupTracker: StartupChangeTracker?
    /// Reads the security settings and permissions for a scheduled Full Check. Nil means plain scheduled scans only.
    public var fullCheckReader: (@Sendable () async -> FullCheckExtras)?
    public var fullCheckTracker = FullCheckChangeTracker()
    /// How long a new download must stay unchanged before it's scanned, and the longest wait for that.
    public var settleInterval: Duration = .seconds(2)
    public var settleTimeout: Duration = .seconds(600)
    /// One tracker per Applications folder for the new-app watcher.
    public var appTrackers: [DownloadsTracker] = AppPaths.applicationFolders.map {
        DownloadsTracker(folder: $0.url, stateFile: AppPaths.appsSeenFile($0.name))
    }
    /// An app must stay unchanged this long before it's scanned (installers and updates write in bursts).
    public var appSettleInterval: Duration = .seconds(10)
    /// Wait after a startup folder changes, so an installer can finish writing its items.
    public var startupSettle: Duration = .seconds(5)
    /// Where each agent's last run is noted for Settings.
    public var status = BackgroundStatusStore()

    public init(
        settings: ScanSettings,
        customFolders: [URL],
        coordinator: ScanCoordinator,
        historyStore: HistoryStore,
        downloads: DownloadsTracker,
        notifier: any BackgroundNotifying,
        logger: FileLogger
    ) {
        self.settings = settings
        self.customFolders = customFolders
        self.coordinator = coordinator
        self.historyStore = historyStore
        self.downloads = downloads
        self.notifier = notifier
        self.logger = logger
    }

    func with(startupTracker: StartupChangeTracker?) -> BackgroundScanEnvironment {
        var copy = self
        copy.startupTracker = startupTracker
        return copy
    }

    /// The user's real settings, ignore list, history and Downloads folder. Never elevated.
    public static func live(notifier: any BackgroundNotifying) -> BackgroundScanEnvironment {
        let settings = SettingsStore.load()
        let apiKey = settings.vtAutoLookupFlagged ? KeychainStore.virusTotal.read() : nil
        return BackgroundScanEnvironment(
            settings: settings,
            customFolders: TargetStore().load(),
            coordinator: ScanCoordinator(
                engines: EngineFactory.makeEngines(settings: settings),
                lookupEngine: EngineFactory.makeLookupEngine(apiKey: apiKey),
                settings: settings,
                ignoreList: IgnoreList.load()
            ),
            historyStore: HistoryStore(),
            downloads: DownloadsTracker(),
            notifier: notifier,
            logger: .shared
        )
        .with(startupTracker: StartupChangeTracker())
        .with(fullCheckReader: { await FullCheckExtras.read() })
    }

    func with(fullCheckReader: (@Sendable () async -> FullCheckExtras)?, tracker: FullCheckChangeTracker? = nil) -> BackgroundScanEnvironment {
        var copy = self
        copy.fullCheckReader = fullCheckReader
        if let tracker { copy.fullCheckTracker = tracker }
        return copy
    }
}

/// Headless mode of the MacScan executable, started by launchd (see `BackgroundAgent`). It runs one
/// scheduled scan, or scans what's new in ~/Downloads, saves the result to history, posts a
/// notification when something is flagged, and exits. It never moves, deletes or changes scanned files.
public enum BackgroundScanWorker {
    /// First argument that switches the MacScan executable into this mode.
    public static let flag = "--macscan-background-scan"
    /// Second argument that only posts a test notification.
    public static let testArgument = "test-notification"
    /// Clean background scans kept in history per trigger (flagged ones follow the normal history limit).
    static let cleanSessionsKept = 10

    /// Arguments after `flag`: `scheduled`, `downloads` or `test-notification`. Returns the exit code.
    public static func main(arguments: [String], notifier: any BackgroundNotifying) -> Int32 {
        guard let argument = arguments.first else { return 64 }
        let logger = FileLogger.shared
        defer { logger.flush() }

        if argument == testArgument {
            wait {
                await notifier.notify(BackgroundNotification(
                    title: "MacScan background scans are set up",
                    body: "You'll get a notification like this one when a background scan finds something."
                ))
            }
            return 0
        }
        guard let trigger = ScanTrigger(rawValue: argument) else { return 64 }

        // One background scan at a time: a second worker waits here until the first is done.
        let lock = open(AppPaths.backgroundLockFile.path, O_CREAT | O_RDWR | O_CLOEXEC, 0o600)
        if lock >= 0 { flock(lock, LOCK_EX) }
        defer { if lock >= 0 { close(lock) } }

        // launchd stops the job with SIGTERM (logout, agent removed). Take the scan tools down with us.
        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        term.setEventHandler {
            ProcessRegistry.shared.terminateAll()
            logger.info("Background scan (\(trigger.rawValue)) stopped by macOS")
            logger.flush()
            exit(0)
        }
        term.resume()

        wait { _ = await run(trigger, environment: .live(notifier: notifier)) }
        return 0
    }

    private static func wait(_ work: @escaping @Sendable () async -> Void) {
        let done = DispatchSemaphore(value: 0)
        Task.detached {
            await work()
            done.signal()
        }
        done.wait()
    }

    /// Runs the scans for one trigger and returns their sessions (already saved to history).
    @discardableResult
    public static func run(_ trigger: ScanTrigger, environment env: BackgroundScanEnvironment) async -> [ScanSession] {
        let sessions = switch trigger {
        case .scheduled: await runScheduled(env)
        case .downloads: await runDownloads(env)
        case .startupItems: await runStartupWatch(env)
        case .newApps: await runNewApps(env)
        }
        env.status.record(trigger, status(for: trigger, sessions: sessions, settings: env.settings))
        return sessions
    }

    // MARK: - Scheduled scan

    static func runScheduled(_ env: BackgroundScanEnvironment) async -> [ScanSession] {
        guard env.settings.scheduledScanEnabled else {
            env.logger.info("Scheduled scan skipped: it is turned off in Settings")
            return []
        }
        let folders = env.customFolders.filter { FileManager.default.fileExists(atPath: $0.path) }
        let reader = env.settings.scheduledFullCheck ? env.fullCheckReader : nil
        let base: [ScanTarget] = reader != nil ? FullCheck.targets : [.applications, .startupItems]
        let targets = base + folders.map { .path($0) }
        env.logger.info(reader != nil ? "Scheduled Full Check starting" : "Scheduled scan starting")
        let previous = env.historyStore.loadAll().first { $0.trigger == .scheduled }
        // Settings and permissions are read while the scan runs.
        let extras = reader.map { read in Task { await read() } }
        var session = await env.coordinator.run(targets: targets) { _ in }
        session.trigger = .scheduled
        if let tracker = env.startupTracker { tracker.apply(to: &session) } else { session.startupSnapshot = nil }
        if let extras { (await extras.value).attach(to: &session, tracker: env.fullCheckTracker, logger: env.logger) }
        await finish(session, previous: previous, env)
        return [session]
    }

    // MARK: - Downloads watcher

    static func runDownloads(_ env: BackgroundScanEnvironment) async -> [ScanSession] {
        guard env.settings.watchDownloads else {
            env.logger.info("Downloads scan skipped: it is turned off in Settings")
            return []
        }
        return await scanNewItems(in: env.downloads, include: { _ in true }, trigger: .downloads, interval: env.settleInterval, env)
    }

    /// Scans the items in `tracker`'s folder that are new or changed since last time. The first run only
    /// marks what's there as seen.
    static func scanNewItems(in tracker: DownloadsTracker, include: (String) -> Bool, trigger: ScanTrigger,
                             interval: Duration, _ env: BackgroundScanEnvironment) async -> [ScanSession] {
        let place = tracker.folder.path.replacingOccurrences(of: AppPaths.home.path, with: "~")
        var sessions: [ScanSession] = []
        // Keep going while new items arrive during a scan; the bound only guards against a loop.
        for _ in 0..<20 {
            let current: DownloadsTracker.Snapshot
            do {
                current = try tracker.current().filter { include($0.key) }
            } catch {
                env.logger.warning("\(trigger.title) scan: cannot read \(place): \(error.localizedDescription)")
                break
            }
            guard let seen = tracker.loadSeen() else {
                // First run: everything already there counts as seen.
                try? tracker.save(current)
                env.logger.info("\(trigger.title) watcher started for \(place): \(current.count) existing item(s) marked as seen")
                break
            }
            let new = DownloadsTracker.newItems(in: current, since: seen)
            guard !new.isEmpty else {
                if seen != current { try? tracker.save(current) }   // forget items that left the folder
                break
            }

            let settled = await tracker.waitUntilSettled(new, interval: interval, timeout: env.settleTimeout)
            // Record what is scanned *before* scanning: an item that changes during the scan is new again.
            var nowSeen = seen.filter { current[$0.key] != nil }
            nowSeen.merge(settled) { _, latest in latest }
            try? tracker.save(nowSeen)

            let names = settled.keys.sorted()
            guard !names.isEmpty else { continue }
            env.logger.info("\(trigger.title) scan starting in \(place): \(names.joined(separator: ", "))")
            let targets = names.map { ScanTarget.path(tracker.folder.appendingPathComponent($0)) }
            var session = await env.coordinator.run(targets: targets) { _ in }
            session.trigger = trigger
            await finish(session, previous: nil, env)
            sessions.append(session)
        }
        return sessions
    }

    // MARK: - New apps

    static func runNewApps(_ env: BackgroundScanEnvironment) async -> [ScanSession] {
        guard env.settings.watchNewApps else {
            env.logger.info("New-app scan skipped: it is turned off in Settings")
            return []
        }
        var sessions: [ScanSession] = []
        for tracker in env.appTrackers where FileManager.default.fileExists(atPath: tracker.folder.path) {
            sessions += await scanNewItems(in: tracker, include: { $0.lowercased().hasSuffix(".app") }, trigger: .newApps,
                                           interval: env.appSettleInterval, env)
        }
        return sessions
    }

    // MARK: - Startup watch

    static func runStartupWatch(_ env: BackgroundScanEnvironment) async -> [ScanSession] {
        guard env.settings.watchStartupItems else {
            env.logger.info("Startup watch skipped: it is turned off in Settings")
            return []
        }
        guard let tracker = env.startupTracker else { return [] }
        try? await Task.sleep(for: env.startupSettle)
        var session = await env.coordinator.run(targets: [.startupItems]) { _ in }
        session.trigger = .startupItems
        tracker.apply(to: &session)
        // Only worth keeping when something is new or different (a removed item isn't).
        guard !newStartupItems(in: session).isEmpty else {
            env.logger.info("Startup watch: nothing new")
            return []
        }
        await finish(session, previous: nil, env)
        return [session]
    }

    /// Startup items that are new or changed in this scan, without MacScan's own agents.
    static func newStartupItems(in session: ScanSession) -> [Finding] {
        session.findings.filter { $0.change != nil && !Self.isMacScanItem($0) }
    }

    static func isMacScanItem(_ finding: Finding) -> Bool {
        (finding.path as NSString).lastPathComponent.hasPrefix(BackgroundAgent.labelPrefix)
    }

    /// "com.foo.updater" for a launch item plist, the file name otherwise.
    static func itemName(_ finding: Finding) -> String {
        let name = (finding.path as NSString).lastPathComponent
        return name.hasSuffix(".plist") ? String(name.dropLast(6)) : name
    }

    // MARK: - Results

    private static func finish(_ session: ScanSession, previous: ScanSession?, _ env: BackgroundScanEnvironment) async {
        do {
            try env.historyStore.save(session)
            env.historyStore.pruneCleanBackgroundSessions(keeping: cleanSessionsKept)
            HistoryChangeSignal.post()
        } catch {
            env.logger.error("Could not save background scan to history: \(error.localizedDescription)")
        }
        if let notification = notification(for: session, previous: previous) {
            env.logger.info("Background scan notification: \(notification.title) — \(notification.body)")
            await env.notifier.notify(notification)
        }
    }

    /// The notification for a finished background scan, or nil when there's nothing new to report.
    /// A scheduled scan reports only results that the previous scheduled scan didn't already have,
    /// so a known warning doesn't notify again every day.
    static func notification(for session: ScanSession, previous: ScanSession?) -> BackgroundNotification? {
        if session.trigger == .startupItems { return startupNotification(for: session) }
        func key(_ f: Finding) -> String {
            // VirusTotal reasons contain changing counts.
            f.engine == .virustotal ? "\(f.engine.rawValue)|\(f.path)" : "\(f.engine.rawValue)|\(f.path)|\(f.reason)"
        }
        var flagged = session.flagged
        if session.trigger == .scheduled, let previous {
            let known = Set(previous.flagged.map(key))
            flagged = flagged.filter { !known.contains(key($0)) }
        }
        // Startup items that appeared or changed since the last scan are worth a notification on their
        // own, even when nothing about them is flagged.
        let startup = session.startupChanges.map { $0.added.count + $0.changed.count } ?? 0
        // What a Full Check found different from the last one (fixes alone don't notify).
        let changes = session.fullCheck?.changes?.filter(\.needsAttention) ?? []
        let changeNote = changes.isEmpty ? "" : " · \(changes.count) \(changes.count == 1 ? "change" : "changes") since the last Full Check"
        guard !flagged.isEmpty else {
            if !changes.isEmpty {
                var body = changes.prefix(3).map(\.shortText).joined(separator: " · ")
                if changes.count > 3 { body += " and \(changes.count - 3) more" }
                if startup > 0 { body += " · \(startup) new or changed startup \(startup == 1 ? "item" : "items")" }
                return BackgroundNotification(title: "Full Check: \(changes.count) \(changes.count == 1 ? "change" : "changes") since the last check",
                                              body: body, sessionID: session.id)
            }
            guard startup > 0, let changes = session.startupChanges else { return nil }
            var names = (changes.added + changes.changed).prefix(3).joined(separator: ", ")
            if startup > 3 { names += " and \(startup - 3) more" }
            let title = changes.changed.isEmpty
                ? "MacScan: \(startup) new startup \(startup == 1 ? "item" : "items")"
                : "MacScan: \(startup) new or changed startup \(startup == 1 ? "item" : "items")"
            return BackgroundNotification(title: title, body: names, sessionID: session.id)
        }

        var seenUnits = Set<String>()
        let units = flagged.map(\.unitPath).filter { seenUnits.insert($0).inserted }
        let threats = Set(flagged.filter { $0.severity == .threat }.map(\.unitPath)).count
        let title = threats > 0
            ? "MacScan found \(threats) \(threats == 1 ? "threat" : "threats")"
            : "MacScan found \(units.count) \(units.count == 1 ? "item" : "items") to review"

        var names = units.prefix(3).map { ($0 as NSString).lastPathComponent }.joined(separator: ", ")
        if units.count > 3 { names += " and \(units.count - 3) more" }
        let body: String = switch session.trigger {
        case .downloads: "In Downloads: \(names)"
        case .newApps: "New or updated app: \(names)" + (flagged.first.map { " · " + $0.reason } ?? "")
        case .startupItems: names
        case .scheduled: previous == nil ? "Scheduled scan: \(names)" : "New since the last scheduled scan: \(names)"
        case nil: names
        }
        let suffix = startup > 0 && session.trigger != .newApps ? " · \(startup) new or changed startup \(startup == 1 ? "item" : "items")" : ""
        return BackgroundNotification(title: title, body: body + suffix + changeNote, sessionID: session.id)
    }

    /// "New startup item: com.foo.updater" with why it's worth a look, or who signed it.
    static func startupNotification(for session: ScanSession) -> BackgroundNotification? {
        let items = newStartupItems(in: session)
        guard let first = items.first else { return nil }
        let flagged = items.filter { $0.severity > .clean }
        let lead = flagged.first ?? first
        let isNew = lead.change == .new
        let title: String
        if items.count == 1 {
            title = "\(isNew ? "New" : "Changed") startup item\(lead.severity > .clean ? " to review" : ""): \(itemName(lead))"
        } else {
            title = flagged.isEmpty
                ? "\(items.count) new or changed startup items"
                : "\(items.count) new or changed startup items, \(flagged.count) to review"
        }
        var body = lead.reason
        if items.count > 1 {
            let others = items.filter { $0 != lead }.prefix(3).map(itemName).joined(separator: ", ")
            body += " · Also: \(others)" + (items.count > 4 ? " and \(items.count - 4) more" : "")
        }
        return BackgroundNotification(title: title, body: body, sessionID: session.id)
    }
}
