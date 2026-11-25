import Foundation

// MARK: - Severity

public enum Severity: String, Codable, CaseIterable, Sendable, Comparable, Identifiable {
    case clean
    case warning
    case threat

    public var id: String { rawValue }

    private var rank: Int {
        switch self {
        case .clean: 0
        case .warning: 1
        case .threat: 2
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }

    public var title: String {
        switch self {
        case .clean: "Clean"
        case .warning: "Warning"
        case .threat: "Threat"
        }
    }
}

// MARK: - Engine identity

public enum EngineID: String, Codable, CaseIterable, Sendable, Identifiable {
    case clamav
    case yara
    case integrity
    case virustotal
    case persistence
    case processes
    case extensions
    /// Synthetic engine used for "no issues found" rows and scanner-level notes.
    case scanner

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .clamav: "ClamAV"
        case .yara: "YARA"
        case .integrity: "App Integrity"
        case .virustotal: "VirusTotal"
        case .persistence: "Startup Items"
        case .processes: "Running Processes"
        case .extensions: "Browser Extensions"
        case .scanner: "All engines"
        }
    }
}

// MARK: - Finding

public struct Finding: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    /// The file or bundle the finding is about.
    public var path: String
    public var severity: Severity
    public var engine: EngineID
    /// Short human-readable reason.
    public var reason: String
    /// Optional longer details (signing authority, quarantine info, rule metadata…).
    public var detail: String?
    /// SHA-256 of the file (for bundles: of the main executable). Filled in for flagged results.
    public var sha256: String?
    /// The "unit" this finding belongs to: the top-level .app for files inside bundles, otherwise `path`.
    public var unitPath: String
    public var date: Date
    /// Set on startup items that are new or changed since the previous Startup Items scan.
    public var change: FindingChange?
    /// Identity used for change tracking when it differs from `unitPath` (browser extensions).
    public var trackingKey: String?
    /// The part of the Mac this result belongs to (nil in history saved before areas existed).
    public var area: ScanArea?

    public init(
        id: UUID = UUID(),
        path: String,
        severity: Severity,
        engine: EngineID,
        reason: String,
        detail: String? = nil,
        sha256: String? = nil,
        unitPath: String? = nil,
        date: Date = Date(),
        trackingKey: String? = nil
    ) {
        self.trackingKey = trackingKey
        self.id = id
        self.path = path
        self.severity = severity
        self.engine = engine
        self.reason = reason
        self.detail = detail
        self.sha256 = sha256
        self.unitPath = unitPath ?? path
        self.date = date
    }

    public var fileName: String { (path as NSString).lastPathComponent }
}

// MARK: - Scan items & targets

public enum ScanItemKind: String, Codable, Sendable {
    case file
    case appBundle
}

/// One thing to scan: a regular file, or an .app bundle as a whole (for integrity checks).
public struct ScanItem: Hashable, Sendable {
    public let url: URL
    public let kind: ScanItemKind
    public let size: Int64
    /// True if the file is Mach-O executable code (executable, dylib, bundle, kext).
    public let isMachO: Bool
    /// The top-level .app bundle that contains this item (or the bundle itself for `.appBundle`).
    public let bundleURL: URL?

    public init(url: URL, kind: ScanItemKind, size: Int64 = 0, isMachO: Bool = false, bundleURL: URL? = nil) {
        self.url = url
        self.kind = kind
        self.size = size
        self.isMachO = isMachO
        self.bundleURL = bundleURL
    }

    public var path: String { url.path }
    public var unitPath: String { bundleURL?.path ?? url.path }
}

public enum ScanTarget: Codable, Hashable, Sendable {
    /// /Applications and ~/Applications.
    case applications
    /// A user-chosen file or folder.
    case path(URL)
    /// Everything set to start automatically (launch agents/daemons, helpers, shell files, plug-ins, cron).
    case startupItems
    /// The programs that are running right now.
    case runningProcesses
    /// Extensions of Chromium-based browsers, Firefox and Safari.
    case browserExtensions

    public var displayName: String {
        switch self {
        case .applications: "Applications"
        case .startupItems: "Startup Items"
        case .runningProcesses: "Running Processes"
        case .browserExtensions: "Browser Extensions"
        case .path(let url): url.path
        }
    }
}

/// A problem encountered while enumerating or reading files.
public struct ScanIssue: Codable, Hashable, Sendable {
    public var path: String
    public var message: String
    /// True when macOS refused access (usually means Full Disk Access is needed).
    public var isPermissionDenied: Bool

    public init(path: String, message: String, isPermissionDenied: Bool) {
        self.path = path
        self.message = message
        self.isPermissionDenied = isPermissionDenied
    }
}

// MARK: - Session

public enum ScanStatus: String, Codable, Sendable {
    case completed
    case cancelled
    case failed
}

/// What started a background scan. Scans the user starts in the app have no trigger.
public enum ScanTrigger: String, Codable, Sendable, CaseIterable {
    case scheduled
    case downloads
    /// Something changed in a LaunchAgents or LaunchDaemons folder.
    case startupItems = "startup-items"
    /// An app arrived in or changed in /Applications or ~/Applications.
    case newApps = "new-apps"
    /// A check every few minutes for apps using a lot of energy while on battery.
    case battery

    public var title: String {
        switch self {
        case .scheduled: "Scheduled"
        case .downloads: "New downloads"
        case .startupItems: "Startup watch"
        case .newApps: "New apps"
        case .battery: "Battery watch"
        }
    }
}

public struct ScanSession: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    /// Set for scans started by launchd (schedule or Downloads watcher); nil for scans started in the app.
    public var trigger: ScanTrigger?
    public var startedAt: Date
    public var finishedAt: Date?
    public var targets: [String]
    public var enginesUsed: [EngineID]
    /// Notes such as "ClamAV: not installed" or engine errors.
    public var notes: [String]
    public var status: ScanStatus
    public var itemsScanned: Int
    public var itemsTotal: Int
    public var skippedCount: Int
    public var ignoredCount: Int
    public var issues: [ScanIssue]
    public var findings: [Finding]
    /// Startup items as collected by this scan; consumed by `StartupChangeTracker.apply` and then cleared.
    public var startupSnapshot: StartupSnapshot?
    /// What was added, changed or removed since the previous Startup Items scan (nil for the first one).
    public var startupChanges: StartupChangeSummary?
    /// The same pair for a Browser Extensions scan.
    public var extensionSnapshot: [String: BrowserExtensionState]?
    public var extensionChanges: StartupChangeSummary?
    /// Set when this scan was a Full Check.
    public var fullCheck: FullCheckInfo?

    public init(
        id: UUID = UUID(),
        startedAt: Date = Date(),
        targets: [String] = []
    ) {
        self.id = id
        self.startedAt = startedAt
        self.finishedAt = nil
        self.targets = targets
        self.enginesUsed = []
        self.notes = []
        self.status = .completed
        self.itemsScanned = 0
        self.itemsTotal = 0
        self.skippedCount = 0
        self.ignoredCount = 0
        self.issues = []
        self.findings = []
    }

    public func count(_ severity: Severity) -> Int {
        findings.lazy.filter { $0.severity == severity }.count
    }

    /// Threats and warnings (everything that isn't a "clean" row).
    public var flagged: [Finding] { findings.filter { $0.severity > .clean } }

    public var worstSeverity: Severity {
        findings.map(\.severity).max() ?? .clean
    }

    public var hasPermissionIssues: Bool {
        issues.contains { $0.isPermissionDenied }
    }
}
