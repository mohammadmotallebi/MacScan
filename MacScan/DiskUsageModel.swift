import AppKit
import MacScanCore
import Observation

/// State for the Disk Usage section: find the folders and files that take the most space.
/// Read-only until the user confirms "Move to Trash" for a single item.
@MainActor
@Observable
final class DiskUsageModel {
    enum Tab: String, CaseIterable, Identifiable {
        case folders = "Folders"
        case largestFiles = "Largest Files"
        case largestFolders = "Largest Folders"
        var id: String { rawValue }
    }

    struct PendingTrash: Identifiable {
        let id = UUID()
        let item: DiskItem
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
            await MainActor.run {
                guard let self else { return }
                self.report = result
                self.currentFolder = result.root
                self.isScanning = false
                self.progress = nil
                self.logger.info("Disk usage scan \(result.cancelled ? "cancelled" : "finished"): \(result.fileCount) files, \(result.totalSize) bytes in \(result.duration)")
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
        if let why = trashRefusal(item) {
            errorMessage = why
            return
        }
        pendingTrash = PendingTrash(item: item)
    }

    /// Called only after the user confirms.
    func confirmTrash(_ pending: PendingTrash) {
        let item = pending.item
        do {
            var resulting: NSURL?
            try FileManager.default.trashItem(at: item.url, resultingItemURL: &resulting)
            report?.markRemoved(item)
            logger.info("Disk usage: user moved to Trash \(item.path) (\(item.size) bytes)")
        } catch {
            logger.error("Disk usage: Move to Trash failed for \(item.path): \(error.localizedDescription)")
            var message = error.localizedDescription
            if PermissionErrors.isPermissionDenied(error) {
                message += "\n\nIt may belong to another user or be protected by macOS. Full Disk Access for MacScan can help, or move it yourself in Finder."
            }
            errorMessage = message
        }
    }
}
