import Foundation

/// One Full Check on the home screen's trend chart.
public struct FullCheckPoint: Identifiable, Hashable, Sendable {
    /// The scan's ID, so a click can open it.
    public let id: UUID
    public let date: Date
    public let threats: Int
    public let warnings: Int
    /// Nil when the security settings weren't read.
    public let securityPassed: Int?
    public let securityTotal: Int?
}

public enum FullCheckTrend {
    /// The last `limit` finished Full Checks, oldest first.
    public static func points(from history: [ScanSession], limit: Int = 15) -> [FullCheckPoint] {
        let checks = history
            .filter { $0.fullCheck != nil && $0.status == .completed }
            .sorted { $0.startedAt > $1.startedAt }
            .prefix(limit)
        return checks.reversed().map { session in
            FullCheckPoint(id: session.id, date: session.finishedAt ?? session.startedAt,
                           threats: session.count(.threat), warnings: session.count(.warning),
                           securityPassed: session.fullCheck?.security?.passed,
                           securityTotal: session.fullCheck?.security?.total)
        }
    }
}
