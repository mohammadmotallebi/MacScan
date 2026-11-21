import Foundation

/// What the menu bar icon shows: the result of the last Full Check, or that a scan is running.
public struct MenuBarStatus: Equatable, Sendable {
    public enum Level: Equatable, Sendable {
        /// No Full Check has finished yet.
        case unknown
        case clear
        /// Warnings, settings that are off, risky permissions or new changes.
        case attention
        case threat
        case scanning
    }

    public var level: Level
    /// First line in the menu, e.g. "Last Full Check: 2 hours ago".
    public var title: String
    /// Second line, e.g. "1 threat · 3 warnings", or nil.
    public var detail: String?
    /// The Full Check the lines are about.
    public var sessionID: UUID?

    /// SF Symbol for the menu bar.
    public var symbol: String {
        switch level {
        case .unknown: "shield"
        case .clear: "checkmark.shield"
        case .attention: "exclamationmark.shield"
        case .threat: "exclamationmark.shield.fill"
        case .scanning: "shield.lefthalf.filled"
        }
    }

    /// Hover text for the icon.
    public var tooltip: String {
        ["MacScan", title, detail].compactMap { $0 }.joined(separator: "\n")
    }

    /// `history` is newest first. Only completed Full Checks count.
    public init(history: [ScanSession], isScanning: Bool, now: Date = Date()) {
        let last = history.first { $0.fullCheck != nil && $0.status == .completed }
        sessionID = last?.id
        guard let last else {
            level = isScanning ? .scanning : .unknown
            title = isScanning ? "Scanning…" : "No Full Check yet"
            detail = isScanning ? nil : "Run one to see how your Mac is doing."
            return
        }

        let threats = last.count(.threat)
        let warnings = last.count(.warning)
        let info = last.fullCheck!
        let settingsOff = info.security.map { $0.total - $0.passed } ?? 0
        let riskyApps = info.privacy?.warnings ?? 0
        let changes = info.changes?.filter(\.needsAttention).count ?? 0

        var parts: [String] = []
        if threats > 0 { parts.append(Self.count(threats, "threat")) }
        if warnings > 0 { parts.append(Self.count(warnings, "warning")) }
        if settingsOff > 0 { parts.append(Self.count(settingsOff, "setting", plural: "settings") + " off") }
        if riskyApps > 0 { parts.append(Self.count(riskyApps, "risky permission")) }
        if changes > 0 { parts.append(Self.count(changes, "change")) }

        if isScanning {
            level = .scanning
            title = "Scanning…"
        } else {
            level = threats > 0 ? .threat : parts.isEmpty ? .clear : .attention
            title = "Last Full Check: " + Self.ago(last.finishedAt ?? last.startedAt, now: now)
        }
        detail = parts.isEmpty ? "Nothing needs attention." : parts.joined(separator: " · ")
    }

    static func count(_ n: Int, _ word: String, plural: String? = nil) -> String {
        "\(n) " + (n == 1 ? word : plural ?? word + "s")
    }

    /// "just now", "5 minutes ago", "3 hours ago", "yesterday", "4 days ago".
    static func ago(_ date: Date, now: Date) -> String {
        let seconds = max(0, now.timeIntervalSince(date))
        let minutes = Int(seconds / 60), hours = minutes / 60, days = hours / 24
        if minutes < 1 { return "just now" }
        if hours < 1 { return count(minutes, "minute") + " ago" }
        if days < 1 { return count(hours, "hour") + " ago" }
        if days == 1 { return "yesterday" }
        return "\(days) days ago"
    }
}

/// Lets an open MacScan know that a background scan saved something to History.
public enum HistoryChangeSignal {
    public static let name = Notification.Name("com.local.MacScan.historyChanged")

    public static func post() {
        DistributedNotificationCenter.default().postNotificationName(name, object: nil, userInfo: nil, deliverImmediately: true)
    }
}
