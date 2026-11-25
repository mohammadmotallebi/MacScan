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
    /// Measure again every few seconds while the section is open.
    var live = false {
        didSet { live ? startLive() : stopLive() }
    }
    private var liveTask: Task<Void, Never>?
    /// Looked up once per app, not on every redraw.
    @ObservationIgnored private var iconCache: [String: NSImage] = [:]
    /// Apps running without a window, worked out once per check.
    private(set) var hiddenApps: Set<String> = []

    func refresh() {
        guard !isChecking else { return }
        Task { await run() }
    }

    /// Starts the live loop if Live is on (the section just opened).
    func startLive() {
        guard live, liveTask == nil else { return }
        liveTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.run(quiet: true)
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    /// Stops the live loop (Live turned off or the section closed).
    func stopLive() {
        liveTask?.cancel()
        liveTask = nil
    }

    /// `quiet` is for Live: no busy spinner and no log line every few seconds.
    @discardableResult
    func run(quiet: Bool = false) async -> BatteryReport {
        if !quiet { isChecking = true }
        let result = await Task.detached { await BatteryScanner().scan() }.value
        let hidden = hiddenApps(in: result)
        if hidden != hiddenApps { hiddenApps = hidden }
        report = result
        isChecking = false
        if quiet { return result }
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
        hiddenApps.contains(app.id)
    }

    func icon(for path: String) -> NSImage {
        if let icon = iconCache[path] { return icon }
        let icon = NSWorkspace.shared.icon(forFile: path)
        iconCache[path] = icon
        return icon
    }

    private func hiddenApps(in report: BatteryReport) -> Set<String> {
        var policy: [String: Bool] = [:]   // bundle path → has a regular (windowed) instance
        for app in NSWorkspace.shared.runningApplications {
            guard let path = app.bundleURL?.path else { continue }
            policy[path] = (policy[path] ?? false) || app.activationPolicy == .regular
        }
        return Set(report.apps.compactMap { app in
            guard let path = app.path, path.hasSuffix(".app"), !app.isSystem, let regular = policy[path] else { return nil }
            return regular ? nil : app.id
        })
    }
}
