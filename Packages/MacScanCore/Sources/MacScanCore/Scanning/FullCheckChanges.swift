import Foundation

/// One thing that is different from the previous Full Check.
public struct FullCheckChange: Codable, Hashable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        case newApp
        case newPermission
        /// A security check that got worse, or whose finding changed while it wasn't passing.
        case settingChanged
        /// A security check that passes now and didn't before.
        case settingFixed
    }

    public var kind: Kind
    public var title: String
    public var detail: String
    /// The app's path, for Reveal in Finder.
    public var path: String?

    public var id: String { "\(kind.rawValue)|\(title)|\(detail)" }

    public init(kind: Kind, title: String, detail: String, path: String? = nil) {
        self.kind = kind
        self.title = title
        self.detail = detail
        self.path = path
    }

    /// New things and worse settings; a fix is good news.
    public var needsAttention: Bool { kind != .settingFixed }
}

/// What a Full Check is compared with: the state after the previous completed one.
struct FullCheckBaseline: Codable {
    var date: Date
    var apps: [String]
    /// "permission|client" of sensitive permissions that were allowed.
    var permissions: [String]?
    /// Check ID → status and summary.
    var checks: [String: Check]

    struct Check: Codable, Equatable {
        var status: String
        var summary: String
    }
}

/// Keeps `fullcheck-baseline.json` and fills `FullCheckInfo.changes`.
public struct FullCheckChangeTracker: Sendable {
    var file: URL

    /// Permissions worth telling about when an app gains them.
    static let sensitive: Set<PrivacyPermission> = [
        .screenRecording, .accessibility, .fullDiskAccess, .inputMonitoring, .camera, .microphone,
        .automation, .appManagement, .developerTools,
    ]

    public init(file: URL = AppPaths.fullCheckBaselineFile) {
        self.file = file
    }

    /// Compares this Full Check with the previous one and saves it as the new starting point.
    /// A scan that didn't complete is neither compared nor saved.
    public func apply(to session: inout ScanSession, checks: [PostureCheck], privacy: PrivacyReport?) {
        guard session.status == .completed, var info = session.fullCheck else { return }

        let apps = Set(session.findings.filter { $0.area == .applications }.map(\.unitPath).filter { $0.lowercased().hasSuffix(".app") })
        // Permissions only count when both lists could be read; otherwise the old ones are kept.
        let readable = privacy.map { report in
            [report.user, report.system].allSatisfy { if case .read = $0 { true } else { $0 == .missing } }
        } ?? false
        let grants = (privacy?.grants ?? []).filter { Self.sensitive.contains($0.permission) && $0.decision != .denied }
        var checkStates: [String: FullCheckBaseline.Check] = [:]
        for check in checks where check.status != .unknown {
            checkStates[check.id.rawValue] = .init(status: check.status.rawValue, summary: check.summary)
        }

        let old = load()
        info.tracked = true
        if let old {
            info.comparedWith = old.date
            info.changes = Self.changes(old: old, apps: apps, findings: session.findings,
                                        grants: readable ? grants : nil, checks: checks)
        } else {
            info.comparedWith = nil
            info.changes = nil
        }
        session.fullCheck = info

        var checksToKeep = old?.checks ?? [:]
        checksToKeep.merge(checkStates) { _, new in new }
        let baseline = FullCheckBaseline(
            date: session.startedAt,
            apps: apps.sorted(),
            permissions: readable ? grants.map(Self.key).sorted() : old?.permissions,
            checks: checksToKeep)
        save(baseline)
    }

    static func key(_ grant: PrivacyGrant) -> String { "\(grant.permission.rawValue)|\(grant.client)" }

    static func changes(old: FullCheckBaseline, apps: Set<String>, findings: [Finding], grants: [PrivacyGrant]?, checks: [PostureCheck]) -> [FullCheckChange] {
        var result: [FullCheckChange] = []

        let oldApps = Set(old.apps)
        for path in apps.subtracting(oldApps).sorted() {
            let name = URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
            let worst = findings.filter { $0.unitPath == path }.map(\.severity).max() ?? .clean
            let verdict = switch worst {
            case .threat: "Installed since the last check, and flagged as a threat."
            case .warning: "Installed since the last check, with warnings."
            case .clean: "Installed since the last check."
            }
            result.append(FullCheckChange(kind: .newApp, title: name, detail: verdict, path: path))
        }

        if let grants, let oldPermissions = old.permissions.map(Set.init) {
            for grant in grants where !oldPermissions.contains(key(grant)) {
                var detail = "Can now use \(grant.permission.title)."
                if let extra = grant.detail { detail += " \(extra)." }
                if grant.risk == .warning, let reason = grant.reasons.first { detail += " " + reason }
                result.append(FullCheckChange(kind: .newPermission, title: grant.name, detail: detail, path: grant.path))
            }
        }

        for check in checks where check.status != .unknown {
            guard let before = old.checks[check.id.rawValue] else { continue }
            let wasPassing = before.status == PostureStatus.pass.rawValue
            if check.status == .pass {
                if !wasPassing {
                    result.append(FullCheckChange(kind: .settingFixed, title: check.title, detail: check.summary))
                }
            } else if wasPassing || before.summary != check.summary {
                result.append(FullCheckChange(kind: .settingChanged, title: check.title, detail: check.summary))
            }
        }

        let order: [FullCheckChange.Kind] = [.settingChanged, .newPermission, .newApp, .settingFixed]
        return result.enumerated().sorted { a, b in
            let ka = order.firstIndex(of: a.element.kind)!, kb = order.firstIndex(of: b.element.kind)!
            return ka != kb ? ka < kb : a.offset < b.offset
        }.map(\.element)
    }

    func load() -> FullCheckBaseline? {
        guard let data = try? Data(contentsOf: file) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(FullCheckBaseline.self, from: data)
    }

    func save(_ baseline: FullCheckBaseline) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(baseline) else { return }
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: file, options: .atomic)
    }

    /// Starts over: the next Full Check becomes the new starting point.
    public func forget() {
        try? FileManager.default.removeItem(at: file)
    }
}
