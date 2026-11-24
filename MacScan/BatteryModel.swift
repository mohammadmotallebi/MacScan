import AppKit
import MacScanCore
import Observation

/// State for the Battery section: which programs use energy. Read-only; nothing is quit or slowed.
@MainActor
@Observable
final class BatteryModel {
    private(set) var report: BatteryReport?
    private(set) var isChecking = false
    /// Hide macOS's own programs.
    var hideSystem = false

    func refresh() {
        guard !isChecking else { return }
        Task { await run() }
    }

    @discardableResult
    func run() async -> BatteryReport {
        isChecking = true
        let result = await Task.detached { await BatteryScanner().scan() }.value
        report = result
        isChecking = false
        FileLogger.shared.info("Battery check: \(result.usingNow.count) using energy, \(result.heavy) high, \(result.blockers.count) keeping awake\(result.problem.map { ", problem: \($0)" } ?? "")")
        return result
    }

    func shown(_ apps: [EnergyApp]) -> [EnergyApp] {
        hideSystem ? apps.filter { !$0.isSystem } : apps
    }

    func reveal(_ app: EnergyApp) {
        guard let path = app.path else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    /// True for an app that is running without a window or Dock icon.
    func runsHidden(_ app: EnergyApp) -> Bool {
        guard let path = app.path, path.hasSuffix(".app"), !app.isSystem else { return false }
        let running = NSWorkspace.shared.runningApplications.filter { $0.bundleURL?.path == path }
        return !running.isEmpty && running.allSatisfy { $0.activationPolicy != .regular }
    }
}
