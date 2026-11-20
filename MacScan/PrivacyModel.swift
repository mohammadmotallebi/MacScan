import AppKit
import MacScanCore
import Observation

/// State for the Privacy section: which apps have which privacy permissions. Read-only.
@MainActor
@Observable
final class PrivacyModel {
    private(set) var report: PrivacyReport?
    private(set) var isChecking = false
    private(set) var lastChecked: Date?
    /// Show only the rows worth a look.
    var flaggedOnly = false
    /// Leftover permissions waiting for the user's confirmation before they are removed.
    var pendingRemoval: [PrivacyGrant] = []
    private(set) var isRemoving = false
    var removalError: String?

    /// Permissions of apps that are no longer installed.
    var leftovers: [PrivacyGrant] { report?.grants.filter(\.canRemove) ?? [] }

    func confirmRemoval(_ grants: [PrivacyGrant]) {
        guard !isRemoving, !grants.isEmpty else { return }
        isRemoving = true
        Task {
            var failures: [String] = []
            for grant in grants {
                do {
                    try await PrivacyLeftoverRemover().remove(grant)
                    FileLogger.shared.info("User removed leftover permission: \(grant.permission.title) for \(grant.client)")
                } catch {
                    FileLogger.shared.error("Removing permission \(grant.permission.title) for \(grant.client) failed: \(error.localizedDescription)")
                    failures.append("\(grant.name) (\(grant.permission.title)): \(error.localizedDescription)")
                }
            }
            isRemoving = false
            if !failures.isEmpty { removalError = failures.joined(separator: "\n") }
            refresh()
        }
    }

    func refresh() {
        guard !isChecking else { return }
        Task { await run() }
    }

    /// Reads the permissions, updates the section and returns the result (a Full Check stores a summary of it).
    @discardableResult
    func run() async -> PrivacyReport {
        isChecking = true
        let result = await Task.detached { PrivacyAudit().run() }.value
        report = result
        lastChecked = Date()
        isChecking = false
        FileLogger.shared.info("Privacy check: \(result.grants.count) permissions, \(result.count(.warning)) warnings, \(result.count(.review)) to review, user list \(result.user), system list \(result.system)")
        return result
    }

    func openSettings(for permission: PrivacyPermission) {
        guard let url = permission.settingsURL else { return }
        NSWorkspace.shared.open(url)
    }

    func reveal(_ grant: PrivacyGrant) {
        guard let path = grant.path else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }
}
