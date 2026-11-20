import Foundation

/// The part of the Mac a result belongs to. Lets a scan of several targets be summarised per area.
public enum ScanArea: String, Codable, CaseIterable, Sendable, Identifiable {
    case applications
    case startupItems
    case runningProcesses
    case browserExtensions
    /// Files and folders the user chose.
    case files

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .applications: "Applications"
        case .startupItems: "Startup Items"
        case .runningProcesses: "Running Processes"
        case .browserExtensions: "Browser Extensions"
        case .files: "Files"
        }
    }
}

extension ScanTarget {
    public var area: ScanArea {
        switch self {
        case .applications: .applications
        case .startupItems: .startupItems
        case .runningProcesses: .runningProcesses
        case .browserExtensions: .browserExtensions
        case .path: .files
        }
    }
}

/// Result counts for one area of a scan.
public struct AreaSummary: Hashable, Sendable, Identifiable {
    public var area: ScanArea
    public var threats: Int
    public var warnings: Int
    public var clean: Int

    public var id: ScanArea { area }

    public var worst: Severity {
        threats > 0 ? .threat : warnings > 0 ? .warning : .clean
    }

    public var isEmpty: Bool { threats + warnings + clean == 0 }
}

/// The macOS security settings as they were when a Full Check ran.
public struct PostureSummary: Codable, Hashable, Sendable {
    public var passed: Int
    public var total: Int
    /// Titles of the checks that didn't pass.
    public var problems: [String]

    public init(passed: Int, total: Int, problems: [String]) {
        self.passed = passed
        self.total = total
        self.problems = problems
    }

    public init(checks: [PostureCheck]) {
        self.init(
            passed: checks.lazy.filter { $0.status == .pass }.count,
            total: checks.count,
            problems: checks.filter { $0.status != .pass }.map(\.title)
        )
    }
}

/// The privacy permissions as they were when a Full Check ran.
public struct PrivacySummary: Codable, Hashable, Sendable {
    /// Apps allowed at least one permission.
    public var apps: Int
    public var warnings: Int
    /// Rows worth a look (leftovers included).
    public var review: Int
    /// Permissions of apps that are no longer installed.
    public var leftovers: Int
    /// False when nothing could be read (usually no Full Disk Access).
    public var readable: Bool
    /// Only part of the list could be read.
    public var partial: Bool

    public init(apps: Int, warnings: Int, review: Int, leftovers: Int, readable: Bool = true, partial: Bool = false) {
        self.apps = apps
        self.warnings = warnings
        self.review = review
        self.leftovers = leftovers
        self.readable = readable
        self.partial = partial
    }

    public init(report: PrivacyReport) {
        let unread: Set<PrivacyReport.Source> = [.noAccess, .missing]
        let nothingRead = unread.contains(report.user) && unread.contains(report.system)
            || (report.grants.isEmpty && report.needsFullDiskAccess)
        self.init(
            apps: Set(report.grants.filter { $0.decision != .denied }.map(\.client)).count,
            warnings: report.count(.warning),
            review: report.count(.review),
            leftovers: report.grants.lazy.filter(\.canRemove).count,
            readable: !nothingRead,
            partial: !nothingRead && report.needsFullDiskAccess)
    }
}

/// Marks a session as a Full Check and carries what isn't a finding.
public struct FullCheckInfo: Codable, Hashable, Sendable {
    /// Nil when the security settings weren't read.
    public var security: PostureSummary?
    /// Nil in Full Checks from before privacy was part of them.
    public var privacy: PrivacySummary?

    public init(security: PostureSummary? = nil, privacy: PrivacySummary? = nil) {
        self.security = security
        self.privacy = privacy
    }

    /// No checks (the settings couldn't be read at all) leaves the summary out instead of showing "0 of 0".
    public init(checks: [PostureCheck]) {
        self.init(security: checks.isEmpty ? nil : PostureSummary(checks: checks))
    }
}

/// One scan of everything MacScan can check without the user choosing a folder.
public enum FullCheck {
    /// Applications first: an app that is also running or set to start automatically is reported under Applications.
    public static let targets: [ScanTarget] = [.applications, .startupItems, .runningProcesses, .browserExtensions]
    public static var areas: [ScanArea] { targets.map(\.area) }
    public static let title = "Full Check"
}

extension ScanSession {
    /// "Full Check" for a full check, otherwise what was scanned.
    public var title: String {
        fullCheck != nil ? FullCheck.title : targets.joined(separator: ", ")
    }

    public func summary(of area: ScanArea) -> AreaSummary {
        var summary = AreaSummary(area: area, threats: 0, warnings: 0, clean: 0)
        for finding in findings where finding.area == area {
            switch finding.severity {
            case .threat: summary.threats += 1
            case .warning: summary.warnings += 1
            case .clean: summary.clean += 1
            }
        }
        return summary
    }
}
