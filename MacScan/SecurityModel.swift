import AppKit
import MacScanCore
import Observation

/// State for the Security section: the status of macOS's own protections. Read-only.
@MainActor
@Observable
final class SecurityModel {
    private(set) var checks: [PostureCheck] = []
    private(set) var isChecking = false
    private(set) var lastChecked: Date?

    func count(_ status: PostureStatus) -> Int {
        checks.lazy.filter { $0.status == status }.count
    }

    func refresh() {
        guard !isChecking else { return }
        isChecking = true
        Task {
            let result = await SecurityPosture().check()
            self.checks = result
            self.lastChecked = Date()
            self.isChecking = false
            let problems = result.filter { $0.status != .pass }.map { "\($0.id.rawValue)=\($0.status.rawValue)" }
            FileLogger.shared.info("Security check: \(result.count) checks, not passing: \(problems.isEmpty ? "none" : problems.joined(separator: ", "))")
        }
    }

    func openSettings(for check: PostureCheck) {
        guard let url = check.settingsURL else { return }
        NSWorkspace.shared.open(url)
    }
}
