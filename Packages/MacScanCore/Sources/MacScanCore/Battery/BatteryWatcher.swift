import Foundation

/// Decides when an app has used a lot of energy for long enough to tell the user. launchd starts a check
/// every few minutes; only checks made on battery count.
public struct BatteryWatcher: Sendable {
    struct State: Codable, Equatable {
        /// High checks in a row, per app.
        var streaks: [String: Int] = [:]
        var lastCheck: Date?
        /// When each app was last alerted about.
        var alerted: [String: Date] = [:]
    }

    /// One check every `interval`; the alert comes after `checksNeeded` High checks in a row.
    public static let interval: TimeInterval = 300
    public static let checksNeeded = 3

    let file: URL

    public init(file: URL = AppPaths.batteryWatchFile) {
        self.file = file
    }

    /// Notes this check and returns the apps to alert about now.
    public func check(_ report: BatteryReport, now: Date = Date(), calendar: Calendar = .current) -> [EnergyApp] {
        var state = load()
        defer { save(state) }
        // On power, or a gap (sleep, the Mac was off): start counting again.
        let gap = state.lastCheck.map { now.timeIntervalSince($0) > Self.interval * 2.5 } ?? true
        state.lastCheck = now
        guard report.state.onBattery, report.problem == nil else {
            state.streaks = [:]
            return []
        }
        if gap { state.streaks = [:] }

        var streaks: [String: Int] = [:]
        var alert: [EnergyApp] = []
        for app in report.apps where !app.isSystem && app.level == .high {
            let streak = (state.streaks[app.id] ?? 0) + 1
            streaks[app.id] = streak
            let alertedToday = state.alerted[app.id].map { calendar.isDate($0, inSameDayAs: now) } ?? false
            if streak >= Self.checksNeeded, !alertedToday {
                alert.append(app)
                state.alerted[app.id] = now
            }
        }
        state.streaks = streaks
        // Forget old alert dates.
        state.alerted = state.alerted.filter { now.timeIntervalSince($0.value) < 7 * 86_400 }
        return alert
    }

    /// "Motrix has been using a lot of energy for 15 min."
    public static func message(for app: EnergyApp) -> String {
        let minutes = Int(interval) * checksNeeded / 60
        return "\(app.name) has been using a lot of energy for \(minutes) min."
    }

    func load() -> State {
        guard let data = try? Data(contentsOf: file) else { return State() }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode(State.self, from: data)) ?? State()
    }

    func save(_ state: State) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(state) else { return }
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: file, options: .atomic)
    }
}
