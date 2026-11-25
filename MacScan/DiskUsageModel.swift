import AppKit
import MacScanCore
import Observation

/// State for the Disk Usage section: find the folders and files that take the most space.
/// Read-only until the user confirms "Move to Trash" for a single item.
@MainActor
@Observable
final class DiskUsageModel {
    enum Tab: String, CaseIterable, Identifiable {
        case cleanup = "Cleanup"
        case folders = "Folders"
        case largestFiles = "Largest Files"
        case largestFolders = "Largest Folders"
        var id: String { rawValue }
    }

    struct PendingTrash: Identifiable {
        let id = UUID()
        /// One or more items picked in a list.
        let items: [DiskItem]
        var size: Int64 { items.reduce(0) { $0 + $1.size } }
    }

    /// "Move All to Trash" for a group of suggestions (e.g. every node_modules), waiting for confirmation.
    struct PendingGroupTrash: Identifiable {
        let id = UUID()
        let title: String
        let members: [CleanupSuggestion]
    }

    /// "Move contents to Trash" for a suggestion like Caches, waiting for confirmation.
    struct PendingEmpty: Identifiable {
        let id = UUID()
        let suggestion: CleanupSuggestion
    }

    /// Folder being measured (home folder by default).
    var location: URL = AppPaths.home
    var report: DiskUsageReport?
    var isScanning = false
    var progress: DiskUsageProgress?
    var tab: Tab = .folders
    /// Folder whose contents the Folders tab shows (drill-down).
    var currentFolder: String?
    var pendingTrash: PendingTrash?
    var pendingEmpty: PendingEmpty?
    var pendingGroupTrash: PendingGroupTrash?
    /// Folders and files that are usually safe or worthwhile to delete, most worthwhile first.
    var suggestions: [CleanupSuggestion] = []
    /// Suggestion per path, for badges in the other lists.
    var suggestionByPath: [String: CleanupSuggestion] = [:]
    var isCleaning = false
    var infoMessage: String?
    var errorMessage: String?

    private var scanTask: Task<Void, Never>?
    private let logger = FileLogger.shared

    var locationName: String {
        location.path == "/" ? "Macintosh HD" : (location.path == AppPaths.home.path ? "Home (\(location.lastPathComponent))" : location.lastPathComponent)
    }

    func scan(_ url: URL? = nil) {
        if let url { location = url }
        guard !isScanning else { return }
        isScanning = true
        report = nil
        suggestions = []
        suggestionByPath = [:]
        currentFolder = nil
        progress = DiskUsageProgress(filesScanned: 0, bytesCounted: 0, currentFolder: location.path)
        let scanner = DiskUsageScanner(root: location)
        logger.info("Disk usage scan started: \(location.path)")
        // Detached so the (synchronous, multi-threaded) walk stays off the main thread; cancelling this task
        // is what the scanner checks.
        scanTask = Task.detached(priority: .userInitiated) { [weak self] in
            let result = scanner.scan { p in
                Task { @MainActor in if self?.isScanning == true { self?.progress = p } }
            }
            let suggestions = result.cancelled ? [] : CleanupAdvisor().suggestions(for: result)
            await MainActor.run {
                guard let self else { return }
                self.report = result
                self.setSuggestions(suggestions)
                self.tab = suggestions.isEmpty ? .folders : .cleanup
                self.currentFolder = result.root
                self.isScanning = false
                self.progress = nil
                self.logger.info("Disk usage scan \(result.cancelled ? "cancelled" : "finished"): \(result.fileCount) files, \(result.totalSize) bytes in \(result.duration)")
            }
        }
    }

    private func setSuggestions(_ list: [CleanupSuggestion]) {
        suggestions = list
        suggestionByPath = Dictionary(list.map { ($0.item.path, $0) }, uniquingKeysWith: { a, _ in a })
    }

    /// Recomputes suggestions in the background after something was removed.
    private func refreshSuggestions() {
        guard let report else { return }
        Task.detached(priority: .userInitiated) { [weak self] in
            let list = CleanupAdvisor().suggestions(for: report)
            await MainActor.run { self?.setSuggestions(list) }
        }
    }

    /// Suggestions as list rows: repeated kinds (node_modules, .venv, Pods) are grouped into one row.
    var entries: [CleanupEntry] { CleanupEntry.entries(for: suggestions) }

    func requestTrashGroup(_ title: String, _ members: [CleanupSuggestion]) {
        let movable = members.filter { $0.action == .trashItem && trashRefusal($0.item) == nil }
        guard !movable.isEmpty else { return }
        pendingGroupTrash = PendingGroupTrash(title: title, members: movable)
    }

    /// Called only after the user confirms.
    func confirmTrashGroup(_ pending: PendingGroupTrash) {
        runCleanup(pending.members, showSummary: false)
    }

    func size(of priority: CleanupPriority) -> Int64 {
        suggestions.filter { $0.priority == priority }.reduce(0) { $0 + $1.item.size }
    }

    /// Starts the clean-up action a suggestion calls for (always behind a confirmation).
    func clean(_ suggestion: CleanupSuggestion) {
        switch suggestion.action {
        case .trashItem: requestTrash(suggestion.item)
        case .trashContents: pendingEmpty = PendingEmpty(suggestion: suggestion)
        case .manual(let how): infoMessage = how
        }
    }

    /// Called only after the user confirms: moves everything inside the folder to the Trash, keeping the folder.
    func confirmEmpty(_ pending: PendingEmpty) {
        runCleanup([pending.suggestion], showSummary: false)
    }

    // MARK: - Clean Up (several suggestions at once)

    struct CleanupProgress: Equatable {
        var done: Int
        var total: Int
        var current: String
    }

    struct CleanupSummary: Equatable {
        var freed: Int64
        var cleaned: Int
        /// Path → reason for everything that couldn't be moved.
        var failures: [String: String]
    }

    var showingCleanupSheet = false
    /// Paths of the suggestions ticked in the Clean Up sheet.
    var cleanupSelection: Set<String> = []
    var cleanupProgress: CleanupProgress?
    var cleanupSummary: CleanupSummary?

    /// Suggestions the app can clean by itself (not the ones that need manual steps).
    var cleanableSuggestions: [CleanupSuggestion] {
        suggestions.filter { $0.action == .trashItem || $0.action == .trashContents }
    }

    /// Opens the Clean Up sheet with every "Safe to clean" item ticked and "Review first" items unticked.
    func openCleanup() {
        cleanupSelection = Set(cleanableSuggestions.filter { $0.priority == .safe }.map(\.id))
        cleanupSummary = nil
        cleanupProgress = nil
        showingCleanupSheet = true
    }

    func selectForCleanup(_ priority: CleanupPriority?) {
        let pool = cleanableSuggestions.filter { priority == nil || $0.priority == priority }
        cleanupSelection = Set(pool.map(\.id))
    }

    var selectedForCleanup: [CleanupSuggestion] {
        cleanableSuggestions.filter { cleanupSelection.contains($0.id) }
    }

    /// Called only after the user confirms. Moves the selected suggestions to the Trash in the background.
    func runCleanup(_ selected: [CleanupSuggestion], showSummary: Bool = true) {
        guard !isCleaning, !selected.isEmpty else { return }
        isCleaning = true
        cleanupSummary = nil
        cleanupProgress = CleanupProgress(done: 0, total: selected.count, current: selected[0].title)
        logger.info("Disk usage clean-up started: \(selected.count) item(s), \(selected.reduce(Int64(0)) { $0 + $1.item.size }) bytes")
        Task.detached(priority: .userInitiated) { [weak self] in
            let outcomes = CleanupRunner().run(selected) { done, total, title in
                Task { @MainActor in self?.cleanupProgress = CleanupProgress(done: done, total: total, current: title) }
            }
            await MainActor.run {
                guard let self else { return }
                // Freed space: what the report says before and after applying the outcomes.
                let before = self.report?.totalSize ?? 0
                self.report?.apply(outcomes)
                let freed = before - (self.report?.totalSize ?? before)
                var failures: [String: String] = [:]
                for outcome in outcomes { failures.merge(outcome.failed) { a, _ in a } }
                let summary = CleanupSummary(freed: freed, cleaned: outcomes.filter(\.complete).count, failures: failures)
                for outcome in outcomes {
                    self.logger.info("Clean-up: \(outcome.suggestion.item.path): \(outcome.moved.count) moved to Trash, \(outcome.failed.count) not moved")
                }
                self.isCleaning = false
                self.cleanupProgress = nil
                if showSummary {
                    self.cleanupSummary = summary
                } else if !failures.isEmpty {
                    self.errorMessage = "\(failures.count) item\(failures.count == 1 ? "" : "s") couldn't be moved (in use, or protected by macOS). Quit the apps that use them and try again."
                }
                self.refreshSuggestions()
            }
        }
    }

    func cancel() {
        scanTask?.cancel()
    }

    func chooseLocation() {
        let panel = NSOpenPanel()
        panel.title = "Choose a folder to measure"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = location
        panel.prompt = "Measure"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        scan(url)
    }

    // MARK: - Navigation

    func open(_ item: DiskItem) {
        guard item.isDirectory, !item.isAggregate else { return }
        currentFolder = item.path
        tab = .folders
    }

    /// Breadcrumb from the scanned root down to the current folder.
    var breadcrumb: [DiskItem] {
        guard let report, let current = currentFolder else { return [] }
        var items: [DiskItem] = []
        var path = current
        while path.count >= report.root.count, let item = report.folder(path) {
            items.insert(item, at: 0)
            if path == report.root { break }
            path = (path as NSString).deletingLastPathComponent
        }
        return items
    }

    // MARK: - Actions (never automatic)

    func reveal(_ item: DiskItem) {
        guard !item.isAggregate else {
            if let currentFolder { NSWorkspace.shared.open(URL(fileURLWithPath: currentFolder)) }
            return
        }
        NSWorkspace.shared.activateFileViewerSelecting([item.url])
    }

    func copyPath(_ item: DiskItem) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(item.path, forType: .string)
    }

    /// Why an item can't be moved to the Trash from here, or nil if it can.
    func trashRefusal(_ item: DiskItem) -> String? {
        if item.isAggregate { return "Select individual files instead." }
        if item.path == report?.root { return "That's the folder being measured." }
        if !Uninstaller.isSafeToRemove(item.path) { return "MacScan doesn't remove system or top-level folders." }
        if Self.isStandardHomeFolder(item.path) { return "MacScan doesn't remove your standard folders. Open it and remove what's inside instead." }
        return nil
    }

    /// The home folder's standard folders (Downloads, Movies, …): big, but never something to trash as a whole.
    static func isStandardHomeFolder(_ path: String) -> Bool {
        let home = AppPaths.home.path
        let standard = ["Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures", "Public", "Library", "Applications", ".Trash"]
        return path == home || standard.contains { path == home + "/" + $0 }
    }

    func requestTrash(_ item: DiskItem) {
        requestTrash([item])
    }

    /// Asks to move several items. Items that can't be moved are left out (with a note if none can);
    /// an item inside another picked folder goes with that folder.
    func requestTrash(_ items: [DiskItem]) {
        let allowed = items.filter { trashRefusal($0) == nil }
        guard !allowed.isEmpty else {
            errorMessage = items.first.flatMap(trashRefusal)
            return
        }
        let paths = allowed.map(\.path)
        let outermost = allowed.filter { item in !paths.contains { item.path.hasPrefix($0 + "/") } }
        pendingTrash = PendingTrash(items: outermost)
    }

    /// The items in `items` that can be moved to the Trash.
    func movable(_ items: [DiskItem]) -> [DiskItem] {
        items.filter { trashRefusal($0) == nil }
    }

    /// Called only after the user confirms.
    func confirmTrash(_ pending: PendingTrash) {
        var failures: [String] = []
        var denied = false
        for item in pending.items {
            do {
                var resulting: NSURL?
                try FileManager.default.trashItem(at: item.url, resultingItemURL: &resulting)
                report?.markRemoved(item)
                logger.info("Disk usage: user moved to Trash \(item.path) (\(item.size) bytes)")
            } catch {
                logger.error("Disk usage: Move to Trash failed for \(item.path): \(error.localizedDescription)")
                failures.append(pending.items.count == 1 ? error.localizedDescription : "\(item.name): \(error.localizedDescription)")
                denied = denied || PermissionErrors.isPermissionDenied(error)
            }
        }
        refreshSuggestions()
        guard !failures.isEmpty else { return }
        var message = failures.prefix(5).joined(separator: "\n") + (failures.count > 5 ? "\n…and \(failures.count - 5) more" : "")
        if denied {
            message += "\n\nIt may belong to another user or be protected by macOS. Full Disk Access for MacScan can help, or move it yourself in Finder."
        }
        errorMessage = message
    }
}
