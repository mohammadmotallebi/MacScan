import AppKit
import MacScanCore
import Observation

/// State for the Network section: a snapshot of which programs use the network. Read-only.
@MainActor
@Observable
final class NetworkModel {
    private(set) var snapshot: NetworkSnapshot?
    private(set) var isChecking = false
    /// Show only the rows worth a look.
    var flaggedOnly = false
    /// Hide macOS's own programs.
    var hideApple = true

    func refresh() {
        guard !isChecking else { return }
        Task { await run() }
    }

    /// Takes a snapshot, updates the section and returns it (a Full Check stores a summary of it).
    @discardableResult
    func run() async -> NetworkSnapshot {
        isChecking = true
        let result = await Task.detached { await NetworkScanner().run() }.value
        snapshot = result
        isChecking = false
        FileLogger.shared.info("Network check: \(result.apps.count) programs, \(result.count(.warning)) warnings, \(result.count(.review)) to review\(result.problem.map { ", problem: \($0)" } ?? "")")
        return result
    }

    func shown(_ snapshot: NetworkSnapshot) -> [NetworkApp] {
        snapshot.apps.filter { (!flaggedOnly || $0.risk != .none) && (!hideApple || !$0.isApple || $0.risk != .none) }
    }

    func reveal(_ app: NetworkApp) {
        guard let path = app.path else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
