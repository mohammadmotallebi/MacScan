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
    /// How long a new download must stay unchanged before it's scanned, and the longest wait for that.
    public var settleInterval: Duration = .seconds(2)
    public var settleTimeout: Duration = .seconds(600)

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
        switch trigger {
        case .scheduled: await runScheduled(env)
        case .downloads: await runDownloads(env)
        }
    }

    // MARK: - Scheduled scan

    static func runScheduled(_ env: BackgroundScanEnvironment) async -> [ScanSession] {
        guard env.settings.scheduledScanEnabled else {
            env.logger.info("Scheduled scan skipped: it is turned off in Settings")
            return []
        }
        let folders = env.customFolders.filter { FileManager.default.fileExists(atPath: $0.path) }
        let targets: [ScanTarget] = [.applications, .startupItems] + folders.map { .path($0) }
        env.logger.info("Scheduled scan starting")
        let previous = env.historyStore.loadAll().first { $0.trigger == .scheduled }
        var session = await env.coordinator.run(targets: targets) { _ in }
        session.trigger = .scheduled
        if let tracker = env.startupTracker { tracker.apply(to: &session) } else { session.startupSnapshot = nil }
        await finish(session, previous: previous, env)
        return [session]
    }

    // MARK: - Downloads watcher

    static func runDownloads(_ env: BackgroundScanEnvironment) async -> [ScanSession] {
        guard env.settings.watchDownloads else {
            env.logger.info("Downloads scan skipped: it is turned off in Settings")
            return []
        }
        var sessions: [ScanSession] = []
        // Keep going while new items arrive during a scan; the bound only guards against a loop.
        for _ in 0..<20 {
            let current: DownloadsTracker.Snapshot
            do {
                current = try env.downloads.current()
            } catch {
                env.logger.warning("Downloads scan: cannot read \(env.downloads.folder.path): \(error.localizedDescription)")
                break
            }
            guard let seen = env.downloads.loadSeen() else {
                // First run: everything already there counts as seen.
                try? env.downloads.save(current)
                env.logger.info("Downloads watcher started: \(current.count) existing item(s) marked as seen")
                break
            }
            let new = DownloadsTracker.newItems(in: current, since: seen)
            guard !new.isEmpty else {
                if seen != current { try? env.downloads.save(current) }   // forget items that left the folder
                break
            }

            let settled = await env.downloads.waitUntilSettled(new, interval: env.settleInterval, timeout: env.settleTimeout)
            // Record what is scanned *before* scanning: an item that changes during the scan is new again.
            var nowSeen = seen.filter { current[$0.key] != nil }
            nowSeen.merge(settled) { _, latest in latest }
            try? env.downloads.save(nowSeen)

            let names = settled.keys.sorted()
            guard !names.isEmpty else { continue }
            env.logger.info("Downloads scan starting: \(names.joined(separator: ", "))")
            let targets = names.map { ScanTarget.path(env.downloads.folder.appendingPathComponent($0)) }
            var session = await env.coordinator.run(targets: targets) { _ in }
            session.trigger = .downloads
            await finish(session, previous: nil, env)
            sessions.append(session)
        }
        return sessions
    }

    // MARK: - Results

    private static func finish(_ session: ScanSession, previous: ScanSession?, _ env: BackgroundScanEnvironment) async {
        do {
            try env.historyStore.save(session)
            env.historyStore.pruneCleanBackgroundSessions(keeping: cleanSessionsKept)
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
        guard !flagged.isEmpty else {
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
        case .scheduled: previous == nil ? "Scheduled scan: \(names)" : "New since the last scheduled scan: \(names)"
        case nil: names
        }
        let suffix = startup > 0 ? " · \(startup) new or changed startup \(startup == 1 ? "item" : "items")" : ""
        return BackgroundNotification(title: title, body: body + suffix, sessionID: session.id)
    }
}
