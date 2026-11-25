import Foundation

/// The last run of one background agent.
public struct BackgroundRunStatus: Codable, Equatable, Sendable {
    public var date: Date
    /// One line, e.g. "Nothing new" or "Scanned Zoom.app: no issues".
    public var summary: String
    /// The scan saved to History, if one was.
    public var sessionID: UUID?
    /// True when something was flagged or changed.
    public var noteworthy: Bool

    public init(date: Date, summary: String, sessionID: UUID? = nil, noteworthy: Bool = false) {
        self.date = date
        self.summary = summary
        self.sessionID = sessionID
        self.noteworthy = noteworthy
    }
}

/// Keeps `background-status.json`: when each agent last ran and what it found, even when the scan
/// itself wasn't kept in History.
public struct BackgroundStatusStore: Sendable {
    let file: URL

    public init(file: URL = AppPaths.backgroundStatusFile) {
        self.file = file
    }

    public func load() -> [ScanTrigger: BackgroundRunStatus] {
        guard let data = try? Data(contentsOf: file),
              let raw = try? Self.decoder.decode([String: BackgroundRunStatus].self, from: data) else { return [:] }
        var result: [ScanTrigger: BackgroundRunStatus] = [:]
        for (key, value) in raw { if let trigger = ScanTrigger(rawValue: key) { result[trigger] = value } }
        return result
    }

    public func record(_ trigger: ScanTrigger, _ status: BackgroundRunStatus) {
        var all = load()
        all[trigger] = status
        let raw = Dictionary(uniqueKeysWithValues: all.map { ($0.key.rawValue, $0.value) })
        guard let data = try? Self.encoder.encode(raw) else { return }
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: file, options: .atomic)
    }

    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }()

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

public enum BackgroundSchedule {
    /// When the scheduled scan runs next after `date`, or nil when it's off.
    public static func nextRun(_ settings: ScanSettings, after date: Date = Date(), calendar: Calendar = .current) -> Date? {
        guard settings.scheduledScanEnabled else { return nil }
        var parts = DateComponents()
        parts.hour = min(23, max(0, settings.scheduleHour))
        parts.minute = min(59, max(0, settings.scheduleMinute))
        parts.second = 0
        if settings.scheduleFrequency == .weekly {
            // Settings: 1 = Monday … 7 = Sunday. Calendar: 1 = Sunday … 7 = Saturday.
            parts.weekday = min(7, max(1, settings.scheduleWeekday)) % 7 + 1
        }
        return calendar.nextDate(after: date, matching: parts, matchingPolicy: .nextTime)
    }
}

extension BackgroundScanWorker {
    /// The status line for one run of an agent.
    static func status(for trigger: ScanTrigger, sessions: [ScanSession], settings: ScanSettings, at date: Date = Date()) -> BackgroundRunStatus {
        let enabled = switch trigger {
        case .scheduled: settings.scheduledScanEnabled
        case .downloads: settings.watchDownloads
        case .startupItems: settings.watchStartupItems
        case .newApps: settings.watchNewApps
        case .battery: settings.watchBattery
        }
        guard enabled else { return BackgroundRunStatus(date: date, summary: "Skipped: turned off") }
        guard let last = sessions.last else { return BackgroundRunStatus(date: date, summary: "Nothing new") }

        let flagged = sessions.flatMap(\.flagged)
        let threats = flagged.filter { $0.severity == .threat }.count
        let warnings = flagged.count - threats
        var result = [threats > 0 ? "\(threats) threat\(threats == 1 ? "" : "s")" : nil,
                      warnings > 0 ? "\(warnings) warning\(warnings == 1 ? "" : "s")" : nil].compactMap { $0 }.joined(separator: " · ")
        if result.isEmpty { result = "no issues" }

        let summary: String
        switch trigger {
        case .battery:
            summary = ""
        case .startupItems:
            let items = sessions.flatMap(newStartupItems(in:))
            let names = items.prefix(2).map(itemName).joined(separator: ", ") + (items.count > 2 ? " and \(items.count - 2) more" : "")
            summary = "\(items.count) new or changed startup item\(items.count == 1 ? "" : "s"): \(names)"
        case .newApps, .downloads:
            let targets = sessions.flatMap(\.targets).map { ($0 as NSString).lastPathComponent }
            let names = targets.prefix(2).joined(separator: ", ") + (targets.count > 2 ? " and \(targets.count - 2) more" : "")
            summary = "Scanned \(names): \(result)"
        case .scheduled:
            let changes = last.fullCheck?.changes?.filter(\.needsAttention).count ?? 0
            summary = "\(last.title): \(result)" + (changes > 0 ? " · \(changes) change\(changes == 1 ? "" : "s")" : "")
        }
        let noteworthy = !flagged.isEmpty || trigger == .startupItems
            || (last.fullCheck?.changes?.contains(where: \.needsAttention) ?? false)
        return BackgroundRunStatus(date: date, summary: summary, sessionID: last.id, noteworthy: noteworthy)
    }
}
