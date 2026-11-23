import Foundation

/// Notices when an app gets a sensitive permission (camera, microphone, screen, keyboard, Full Disk Access)
/// between two reads of the permission list. Keeps what it saw last in `permission-watch.json`.
public struct PermissionWatcher: Sendable {
    var file: URL

    /// Permissions worth an alert the moment an app gets them.
    public static let watched: Set<PrivacyPermission> = [
        .camera, .microphone, .screenRecording, .accessibility, .inputMonitoring, .fullDiskAccess,
    ]

    public init(file: URL = AppPaths.permissionWatchFile) {
        self.file = file
    }

    /// Compares the report with the last one and saves it. Returns the newly allowed permissions, or nil when
    /// there was nothing to compare with yet or the list couldn't be read in full (nothing is saved then).
    public func check(_ report: PrivacyReport) -> [PrivacyGrant]? {
        let readable = [report.user, report.system].allSatisfy { if case .read = $0 { true } else { $0 == .missing } }
        guard readable else { return nil }
        let grants = report.grants.filter { Self.watched.contains($0.permission) && $0.decision != .denied }
        let keys = Set(grants.map(Self.key))
        let old = load()
        save(keys)
        guard let old else { return nil }
        var seen = Set<String>()
        return grants.filter { !old.contains(Self.key($0)) && seen.insert(Self.key($0)).inserted }
    }

    /// A short line for a notification, e.g. "Zoom can now use your camera."
    public static func message(for grant: PrivacyGrant) -> String {
        "\(grant.name) can now use \(phrase(grant.permission))."
    }

    static func phrase(_ permission: PrivacyPermission) -> String {
        switch permission {
        case .camera: "your camera"
        case .microphone: "your microphone"
        case .screenRecording: "your screen (it can record it)"
        case .accessibility: "Accessibility (it can control your Mac)"
        case .inputMonitoring: "Input Monitoring (it can see what you type)"
        case .fullDiskAccess: "all your files (Full Disk Access)"
        default: permission.title
        }
    }

    static func key(_ grant: PrivacyGrant) -> String { "\(grant.permission.rawValue)|\(grant.client)" }

    func load() -> Set<String>? {
        guard let data = try? Data(contentsOf: file), let keys = try? JSONDecoder().decode([String].self, from: data) else { return nil }
        return Set(keys)
    }

    func save(_ keys: Set<String>) {
        guard let data = try? JSONEncoder().encode(keys.sorted()) else { return }
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: file, options: .atomic)
    }
}
