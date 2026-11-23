import Foundation

// Background scans without a background process: MacScan installs its own per-user launch agents
// (one for the schedule, one that watches ~/Downloads). launchd starts the MacScan executable in the
// headless `BackgroundScanWorker` mode when a scan is due; the worker exits when the scan ends.
// Both agents are off by default and exist only while their setting is on.

/// Runs `launchctl`. Tests replace it so they never touch the real launchd.
public protocol LaunchctlRunning: Sendable {
    /// Returns the exit code.
    func run(_ arguments: [String]) async -> Int32
}

public struct SystemLaunchctl: LaunchctlRunning {
    public init() {}

    public func run(_ arguments: [String]) async -> Int32 {
        let result = try? await ProcessRunner.run(URL(fileURLWithPath: "/bin/launchctl"), arguments)
        return result?.exitCode ?? -1
    }
}

public enum BackgroundAgentError: Error, LocalizedError, Equatable {
    case couldNotWrite(String)
    case couldNotLoad(label: String, exitCode: Int32)

    public var errorDescription: String? {
        switch self {
        case .couldNotWrite(let why): "MacScan could not save its launch agent: \(why)"
        case .couldNotLoad(let label, let code): "macOS did not accept the launch agent \(label) (launchctl exit \(code))."
        }
    }
}

/// Installs, updates and removes MacScan's own launch agents so they match the settings.
public struct BackgroundAgent: Sendable {
    /// Every MacScan agent label starts with this.
    public static let labelPrefix = "com.local.MacScan."
    public static let bundleIdentifier = "com.local.MacScan"

    public static func label(for trigger: ScanTrigger) -> String {
        switch trigger {
        case .scheduled: labelPrefix + "scheduled-scan"
        case .downloads: labelPrefix + "downloads-watcher"
        case .startupItems: labelPrefix + "startup-watcher"
        case .newApps: labelPrefix + "apps-watcher"
        }
    }

    /// The MacScan executable launchd should start.
    public let executable: URL
    /// ~/Library/LaunchAgents.
    public let directory: URL
    public let downloadsFolder: URL
    /// Folders the startup watcher and the new-app watcher watch.
    public let startupFolders: [URL]
    public let appFolders: [URL]
    let launchctl: any LaunchctlRunning
    let domain: String
    let retryDelay: Duration

    public init(
        executable: URL,
        directory: URL = AppPaths.launchAgents,
        downloadsFolder: URL = AppPaths.downloads,
        startupFolders: [URL] = [AppPaths.launchAgents, URL(fileURLWithPath: "/Library/LaunchAgents"), URL(fileURLWithPath: "/Library/LaunchDaemons")],
        appFolders: [URL] = AppPaths.applicationFolders.map(\.url),
        launchctl: any LaunchctlRunning = SystemLaunchctl(),
        domain: String = "gui/\(getuid())",
        retryDelay: Duration = .milliseconds(400)
    ) {
        self.executable = executable
        self.directory = directory
        self.downloadsFolder = downloadsFolder
        self.startupFolders = startupFolders
        self.appFolders = appFolders
        self.launchctl = launchctl
        self.domain = domain
        self.retryDelay = retryDelay
    }

    public func plistURL(for trigger: ScanTrigger) -> URL {
        directory.appendingPathComponent(Self.label(for: trigger) + ".plist")
    }

    /// The launchd job for a trigger, or nil when its setting is off.
    public func job(for trigger: ScanTrigger, settings: ScanSettings) -> [String: Any]? {
        var job: [String: Any] = [
            "Label": Self.label(for: trigger),
            "ProgramArguments": [executable.path, BackgroundScanWorker.flag, trigger.rawValue],
            // Shown under the app's name in System Settings › General › Login Items.
            "AssociatedBundleIdentifiers": [Self.bundleIdentifier],
            // Scan gently: low CPU and disk priority, never restarted on its own.
            "ProcessType": "Background",
            "LowPriorityIO": true,
            "Nice": 10,
            "RunAtLoad": false,
        ]
        switch trigger {
        case .scheduled:
            guard settings.scheduledScanEnabled else { return nil }
            var when: [String: Int] = [
                "Hour": min(23, max(0, settings.scheduleHour)),
                "Minute": min(59, max(0, settings.scheduleMinute)),
            ]
            if settings.scheduleFrequency == .weekly {
                when["Weekday"] = min(7, max(1, settings.scheduleWeekday))   // launchd: 1 = Monday, 7 = Sunday
            }
            job["StartCalendarInterval"] = when
        case .downloads:
            guard settings.watchDownloads else { return nil }
            job["WatchPaths"] = [downloadsFolder.path]
            job["ThrottleInterval"] = 15
        case .startupItems:
            guard settings.watchStartupItems else { return nil }
            job["WatchPaths"] = startupFolders.map(\.path)
            job["ThrottleInterval"] = 15
        case .newApps:
            guard settings.watchNewApps else { return nil }
            job["WatchPaths"] = appFolders.map(\.path)
            job["ThrottleInterval"] = 30
        }
        return job
    }

    /// True when the agent's plist is installed.
    public func isInstalled(_ trigger: ScanTrigger) -> Bool {
        FileManager.default.fileExists(atPath: plistURL(for: trigger).path)
    }

    /// The executable an installed agent starts, if any.
    public func installedExecutable(for trigger: ScanTrigger) -> String? {
        (installedJob(for: trigger)?["ProgramArguments"] as? [String])?.first
    }

    private func installedJob(for trigger: ScanTrigger) -> [String: Any]? {
        guard let data = try? Data(contentsOf: plistURL(for: trigger)) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }

    /// Makes the installed agents match `settings`: writes and loads what's turned on, unloads and
    /// deletes what's turned off. Only ever touches MacScan's own plists.
    public func sync(settings: ScanSettings, logger: FileLogger = .shared) async throws {
        for trigger in ScanTrigger.allCases {
            let label = Self.label(for: trigger)
            let url = plistURL(for: trigger)
            let fm = FileManager.default

            guard let wanted = job(for: trigger, settings: settings) else {
                if fm.fileExists(atPath: url.path) {
                    _ = await launchctl.run(["bootout", "\(domain)/\(label)"])
                    try? fm.removeItem(at: url)
                    logger.info("Background agent removed: \(label)")
                }
                continue
            }

            let unchanged = installedJob(for: trigger).map { NSDictionary(dictionary: $0).isEqual(to: wanted) } ?? false
            if unchanged, await launchctl.run(["print", "\(domain)/\(label)"]) == 0 {
                continue   // installed and loaded
            }

            do {
                try fm.createDirectory(at: directory, withIntermediateDirectories: true)
                let data = try PropertyListSerialization.data(fromPropertyList: wanted, format: .xml, options: 0)
                try data.write(to: url, options: .atomic)
            } catch {
                throw BackgroundAgentError.couldNotWrite(error.localizedDescription)
            }

            // Reload so launchd picks up the new schedule. bootout finishes asynchronously, so the
            // bootstrap right after it can fail once or twice.
            _ = await launchctl.run(["bootout", "\(domain)/\(label)"])
            var code: Int32 = -1
            for attempt in 0..<5 {
                if attempt > 0 { try? await Task.sleep(for: retryDelay) }
                code = await launchctl.run(["bootstrap", domain, url.path])
                if code == 0 { break }
            }
            guard code == 0 else {
                logger.error("Background agent \(label) did not load (launchctl exit \(code))")
                throw BackgroundAgentError.couldNotLoad(label: label, exitCode: code)
            }
            logger.info("Background agent installed: \(label)")
        }
    }
}
