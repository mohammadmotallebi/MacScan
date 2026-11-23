import AppKit
import MacScanCore
import Observation

struct UninstallResult: Identifiable {
    let id = UUID()
    let report: UninstallReport
}

/// State for the Uninstall section. Nothing is removed until the user confirms.
@MainActor
@Observable
final class UninstallModel {
    var apps: [InstalledApp] = []
    /// Apps already in the Trash (they can still have registered background items).
    var trashApps: [InstalledApp] = []
    /// Apps that are already deleted, added by bundle ID / name so their leftovers can be found.
    var removedApps: [InstalledApp] = []
    /// Apps that seem removed but left files in the Library, found on their own. Biggest first.
    var probablyRemoved: [InstalledApp] = []
    /// Size of what each probably-removed app left, by app ID.
    var leftoverSizes: [String: Int64] = [:]
    var showingRemovedAppSheet = false
    /// Delete instead of moving to the Trash (items already in the Trash are always deleted).
    var deletePermanently = false
    var search = ""
    var selectedAppID: String?
    var plan: UninstallPlan?
    /// Paths of leftovers the user wants removed.
    var selection: Set<String> = []
    var isLoadingApps = false
    var isFinding = false
    var isUninstalling = false
    var status: String?
    var result: UninstallResult?
    var errorMessage: String?

    private var findTask: Task<Void, Never>?

    var selectedApp: InstalledApp? {
        guard let selectedAppID else { return nil }
        return apps.first { $0.id == selectedAppID } ?? trashApps.first { $0.id == selectedAppID }
            ?? removedApps.first { $0.id == selectedAppID } ?? probablyRemoved.first { $0.id == selectedAppID }
    }

    private func matches(_ app: InstalledApp) -> Bool {
        let q = search.trimmingCharacters(in: .whitespaces)
        return q.isEmpty || app.name.localizedCaseInsensitiveContains(q) || (app.bundleID ?? "").localizedCaseInsensitiveContains(q)
    }

    var filteredApps: [InstalledApp] { apps.filter(matches) }
    var filteredTrashApps: [InstalledApp] { trashApps.filter(matches) }
    var filteredRemovedApps: [InstalledApp] { removedApps.filter(matches) }
    var filteredProbablyRemoved: [InstalledApp] {
        probablyRemoved.filter { app in matches(app) && !removedApps.contains { $0.id == app.id } }
    }

    /// Adds an already-deleted app by bundle ID and/or name and looks for its leftovers.
    /// Returns an error message to show in the sheet, or nil on success.
    func addRemovedApp(bundleID: String, name: String) -> String? {
        let id = bundleID.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if id.isEmpty && trimmedName.isEmpty { return "Enter the app's bundle ID, its name, or both." }
        if !id.isEmpty && !InstalledApp.isPlausibleBundleID(id) {
            return "“\(id)” doesn't look like a bundle ID. Bundle IDs look like com.vendor.AppName."
        }
        if !id.isEmpty, let installed = (apps + trashApps).first(where: { $0.bundleID?.caseInsensitiveCompare(id) == .orderedSame }) {
            return "\(installed.name) is still \(installed.isInTrash ? "in the Trash" : "installed"). Select it in the list instead."
        }
        guard let app = InstalledApp.removed(bundleID: id, name: trimmedName) else {
            return "Enter a bundle ID like com.vendor.AppName, or the app's name."
        }
        if let reason = app.protectionReason { return "MacScan won't remove this: \(reason)." }
        removedApps.removeAll { $0.id == app.id }
        removedApps.append(app)
        selectedAppID = app.id
        findLeftovers()
        return nil
    }

    /// True when the uninstall will delete (not move to Trash) the given item.
    func willDelete(_ item: Leftover) -> Bool {
        deletePermanently || item.path.hasPrefix(AppPaths.home.path + "/.Trash/")
    }

    var selectedLeftovers: [Leftover] {
        plan?.leftovers.filter { selection.contains($0.path) } ?? []
    }

    func loadApps() {
        guard !isLoadingApps else { return }
        isLoadingApps = true
        Task {
            let (list, trash) = await Task.detached { (InstalledApp.listInstalled(), InstalledApp.listTrash()) }.value
            self.trashApps = trash
            // Keep apps opened from elsewhere (drag & drop, scan results) in the list.
            let extra = self.apps.filter { app in !list.contains { $0.id == app.id } && FileManager.default.fileExists(atPath: app.id) }
            self.apps = (list + extra).sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            self.isLoadingApps = false
            self.findProbablyRemoved(installedIDs: Set((list + trash).flatMap(\.allBundleIDs)))
        }
    }

    /// Looks in the Library for leftovers of apps that are gone. Only reads.
    private func findProbablyRemoved(installedIDs: Set<String>) {
        Task {
            let found = await Task.detached { RemovedAppFinder(installedIDs: installedIDs).find() }.value
            var sizes: [String: Int64] = [:]
            self.probablyRemoved = found.compactMap { candidate in
                guard let app = InstalledApp.removed(bundleID: candidate.bundleID, name: nil), !app.isProtected else { return nil }
                sizes[app.id] = candidate.size
                return app
            }
            self.leftoverSizes = sizes
            FileLogger.shared.info("Probably removed apps: \(found.count)")
        }
    }

    /// Opens an app that may not be in /Applications (e.g. dropped or chosen).
    func open(_ url: URL) {
        guard let app = InstalledApp.load(url) else {
            errorMessage = "“\(url.lastPathComponent)” is not an application bundle."
            return
        }
        if app.isInTrash {
            if !trashApps.contains(where: { $0.id == app.id }) { trashApps.append(app) }
        } else if !apps.contains(where: { $0.id == app.id }) {
            apps.append(app)
            apps.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        }
        selectedAppID = app.id
        findLeftovers()
    }

    func chooseApp() {
        let panel = NSOpenPanel()
        panel.title = "Choose an app to uninstall"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.application]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        open(url)
    }

    /// Called when the selected app changes.
    func findLeftovers() {
        findTask?.cancel()
        plan = nil
        selection = []
        guard let app = selectedApp, !app.isProtected else { return }
        isFinding = true
        findTask = Task {
            do {
                let found = try await Task.detached { try LeftoverFinder().find(app) }.value
                guard !Task.isCancelled, self.selectedAppID == app.id else { return }
                self.plan = found
                // Preselect everything except lower-confidence matches (e.g. shared with the developer's other apps).
                self.selection = Set(found.leftovers.filter(\.selectedByDefault).map(\.path))
            } catch is CancellationError {
            } catch {
                self.errorMessage = error.localizedDescription
            }
            if self.selectedAppID == app.id { self.isFinding = false }
        }
    }

    func setSelected(_ leftover: Leftover, _ on: Bool) {
        if on { selection.insert(leftover.path) } else { selection.remove(leftover.path) }
    }

    func selectAll() { selection = Set(plan?.leftovers.map(\.path) ?? []) }
    func selectNone() { selection = [] }

    /// Performs the uninstall. Only called after the user confirmed.
    func uninstall() {
        guard let plan, !selection.isEmpty, !isUninstalling else { return }
        isUninstalling = true
        status = "Starting…"
        let chosen = selection
        let permanently = deletePermanently
        Task {
            do {
                let report = try await Uninstaller().uninstall(plan, selected: chosen, permanently: permanently) { message in
                    Task { @MainActor in self.status = message }
                }
                self.result = UninstallResult(report: report)
            } catch {
                self.errorMessage = error.localizedDescription
            }
            self.isUninstalling = false
            self.status = nil
            // Refresh: the app may be gone now, or leftovers may remain.
            if let app = self.selectedApp, app.isMissing {
                // Look again so anything that couldn't be removed (e.g. protected by macOS) stays visible.
                self.findLeftovers()
            } else if let app = self.selectedApp, !FileManager.default.fileExists(atPath: app.id) {
                self.apps.removeAll { $0.id == app.id }
                self.trashApps.removeAll { $0.id == app.id }
                self.selectedAppID = nil
                self.plan = nil
                self.selection = []
            } else {
                self.findLeftovers()
            }
            // An app moved to the Trash shows up under "In the Trash".
            self.trashApps = await Task.detached { InstalledApp.listTrash() }.value
        }
    }
}
