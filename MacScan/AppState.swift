import AppKit
import MacScanCore
import Observation
import SwiftUI
import UniformTypeIdentifiers

enum AppSection: Hashable {
    case scan
    case history
    case uninstall
    case diskUsage
}

enum SeverityFilter: String, CaseIterable, Identifiable {
    case all, threat, warning, clean

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "All"
        case .threat: "Threats"
        case .warning: "Warnings"
        case .clean: "Clean"
        }
    }

    func matches(_ s: Severity) -> Bool {
        switch self {
        case .all: true
        case .threat: s == .threat
        case .warning: s == .warning
        case .clean: s == .clean
        }
    }
}

struct FDAPrompt: Identifiable {
    let id = UUID()
    let paths: [String]
}

struct AppAlert: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

struct PendingTrash: Identifiable {
    let id = UUID()
    let finding: Finding
    let sessionID: UUID
}

/// A launch item whose program is gone, waiting for the user's confirmation before it's removed.
struct PendingOrphanRemoval: Identifiable {
    let id = UUID()
    let finding: Finding
    let item: OrphanedLaunchItem
}

struct FreshclamRun {
    var lines: [String] = []
    var running = true
    var succeeded = false
    var error: String?
}

@MainActor
@Observable
final class AppState {
    // MARK: Persisted state

    var settings: ScanSettings {
        didSet {
            guard settings != oldValue else { return }
            SettingsStore.save(settings)
            refreshEngineStatus()
        }
    }

    var customFolders: [URL] {
        didSet { targetStore.save(customFolders) }
    }

    var ignoreList: IgnoreList
    var history: [ScanSession] = []
    let uninstall = UninstallModel()
    let diskUsage = DiskUsageModel()

    // MARK: UI state

    var selectedSection: AppSection? = .scan
    var isScanning = false
    var progress: ScanProgress?
    var currentSession: ScanSession?
    var engineStatus: [EngineID: EngineAvailability] = [:]
    var hasVirusTotalKey = false
    var fullDiskAccessLikelyGranted = true
    var trashedPaths: Set<String> = []
    var vtLookupsInFlight: Set<UUID> = []

    var fdaPrompt: FDAPrompt?
    var installHelp: EngineID?
    var alert: AppAlert?
    var pendingTrash: PendingTrash?
    var pendingOrphanRemoval: PendingOrphanRemoval?
    /// Plists of orphaned launch items being removed right now.
    var orphanRemovalsInFlight: Set<String> = []
    var freshclam: FreshclamRun?
    var showFreshclam = false

    // MARK: Private

    private var scanTask: Task<Void, Never>?
    private var freshclamTask: Task<Void, Never>?
    private let historyStore = HistoryStore()
    private let targetStore = TargetStore()
    private let logger = FileLogger.shared

    init() {
        settings = SettingsStore.load()
        customFolders = TargetStore().load()
        ignoreList = IgnoreList.load()
        history = historyStore.loadAll()
        currentSession = nil
        hasVirusTotalKey = KeychainStore.virusTotal.read() != nil
        logger.info("MacScan launched")
        refreshEngineStatus()
    }

    // MARK: - Engine status

    func refreshEngineStatus() {
        let settings = settings
        let hasKey = hasVirusTotalKey
        Task {
            var status: [EngineID: EngineAvailability] = [:]
            status[.clamav] = settings.enableClamAV ? await ClamAVEngine(settings: settings).availability() : .disabled
            status[.yara] = settings.enableYara ? await YaraEngine(settings: settings).availability() : .disabled
            status[.integrity] = settings.enableIntegrity ? await AppIntegrityEngine().availability() : .disabled
            status[.persistence] = .available(detail: "Launch agents & daemons, helpers, shell files, plug-ins, cron")
            status[.virustotal] = hasKey
                ? .available(detail: settings.vtAutoLookupFlagged ? "Auto-lookup for flagged files" : "Manual lookups only")
                : .needsSetup("Optional: add your own API key in Settings")
            self.engineStatus = status
            self.fullDiskAccessLikelyGranted = FullDiskAccess.isLikelyGranted()
        }
    }

    var clamscanInstalled: Bool { ToolLocator.locate(.clamscan, override: settings.clamscanPath) != nil }
    var freshclamInstalled: Bool { ToolLocator.locate(.freshclam, override: settings.freshclamPath) != nil }

    // MARK: - Scanning

    func scanApplications() {
        startScan([.applications])
    }

    func scanStartupItems() {
        startScan([.startupItems])
    }

    func scanCustomFolders() {
        startScan(customFolders.map { .path($0) })
    }

    func scan(urls: [URL]) {
        startScan(urls.map { .path($0) })
    }

    func chooseAndScan() {
        let panel = NSOpenPanel()
        panel.title = "Choose files or folders to scan"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.treatsFilePackagesAsDirectories = false
        panel.prompt = "Scan"
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        scan(urls: panel.urls)
    }

    func startScan(_ targets: [ScanTarget]) {
        guard !isScanning, !targets.isEmpty else { return }
        selectedSection = .scan
        isScanning = true
        progress = ScanProgress(phase: .enumerating)
        currentSession = nil
        trashedPaths = []

        let settings = settings
        let apiKey = hasVirusTotalKey ? KeychainStore.virusTotal.read() : nil
        let coordinator = ScanCoordinator(
            engines: EngineFactory.makeEngines(settings: settings),
            lookupEngine: EngineFactory.makeLookupEngine(apiKey: apiKey),
            settings: settings,
            ignoreList: ignoreList
        )
        let onProgress: @Sendable (ScanProgress) -> Void = { progress in
            Task { @MainActor in
                guard self.isScanning else { return }
                self.progress = progress
            }
        }

        // AppState lives for the whole app lifetime, so strong captures are fine here.
        if settings.elevatedScans, let executable = Bundle.main.executableURL {
            let request = ElevatedScanRequest.make(targets: targets, settings: settings, ignoreList: ignoreList)
            progress?.status = "Waiting for your administrator password…"
            logger.info("Starting administrator scan")
            scanTask = Task {
                do {
                    let session = try await ElevatedScanLauncher(executable: executable).run(request, onProgress: onProgress)
                    // VirusTotal runs here, as the user: the root worker never sees the API key.
                    self.scanFinished(await coordinator.lookUpFlagged(in: session, onProgress: onProgress))
                } catch {
                    self.logger.warning("Administrator scan did not run: \(error.localizedDescription)")
                    self.isScanning = false
                    self.progress = nil
                    self.scanTask = nil
                    if error as? ElevatedScanError != .passwordCancelled {
                        self.alert = AppAlert(title: "Administrator scan failed", message: error.localizedDescription)
                    }
                }
            }
            return
        }

        scanTask = Task {
            let session = await coordinator.run(targets: targets, onProgress: onProgress)
            self.scanFinished(session)
        }
    }

    func cancelScan() {
        scanTask?.cancel()
        progress?.status = "Cancelling…"
    }

    private func scanFinished(_ session: ScanSession) {
        isScanning = false
        progress = nil
        scanTask = nil
        currentSession = session
        history.insert(session, at: 0)
        do {
            try historyStore.save(session)
        } catch {
            logger.error("Could not save scan history: \(error.localizedDescription)")
            alert = AppAlert(title: "Could not save scan history", message: error.localizedDescription)
        }
        let denied = session.issues.filter(\.isPermissionDenied).map(\.path)
        if !denied.isEmpty {
            fdaPrompt = FDAPrompt(paths: denied)
        }
        refreshEngineStatus()
    }

    // MARK: - Uninstall

    /// The .app a result belongs to, if any.
    func owningApp(of finding: Finding) -> URL? {
        for candidate in [finding.unitPath, finding.path] {
            if let app = PersistenceScanner.enclosingApp(of: candidate) ?? (candidate.lowercased().hasSuffix(".app") ? URL(fileURLWithPath: candidate) : nil),
               FileManager.default.fileExists(atPath: app.path) {
                return app
            }
        }
        return nil
    }

    func openUninstaller(for appURL: URL) {
        selectedSection = .uninstall
        uninstall.open(appURL)
    }

    // MARK: - Folders

    func addFolders() {
        let panel = NSOpenPanel()
        panel.title = "Add folders to scan"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Add"
        guard panel.runModal() == .OK else { return }
        var denied: [String] = []
        for url in panel.urls where !customFolders.contains(url) {
            do {
                _ = try FileManager.default.contentsOfDirectory(atPath: url.path)
            } catch where PermissionErrors.isPermissionDenied(error) {
                denied.append(url.path)
            } catch {}
            customFolders.append(url)
        }
        if !denied.isEmpty { fdaPrompt = FDAPrompt(paths: denied) }
    }

    func removeFolder(_ url: URL) {
        customFolders.removeAll { $0 == url }
    }

    // MARK: - Result actions (never automatic)

    func reveal(_ finding: Finding) {
        let url = URL(fileURLWithPath: finding.path)
        if FileManager.default.fileExists(atPath: url.path) {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } else {
            alert = AppAlert(title: "File not found", message: "\(finding.path) no longer exists.")
        }
    }

    func requestTrash(_ finding: Finding, sessionID: UUID) {
        pendingTrash = PendingTrash(finding: finding, sessionID: sessionID)
    }

    /// Called only after the user confirms in the dialog.
    func confirmTrash(_ pending: PendingTrash) {
        let url = URL(fileURLWithPath: pending.finding.path)
        do {
            var resulting: NSURL?
            try FileManager.default.trashItem(at: url, resultingItemURL: &resulting)
            trashedPaths.insert(pending.finding.path)
            logger.info("User moved to Trash: \(pending.finding.path)")
        } catch {
            logger.error("Move to Trash failed for \(pending.finding.path): \(error.localizedDescription)")
            var message = error.localizedDescription
            if PermissionErrors.isPermissionDenied(error) {
                message += "\n\nThe item may be owned by another user or protected by macOS. You can move it to the Trash yourself in Finder."
            }
            alert = AppAlert(title: "Could not move to Trash", message: message)
        }
    }

    /// True for Startup Items results whose program no longer exists (offered "Remove Orphaned Startup Item…").
    func isOrphanedLaunchItem(_ finding: Finding) -> Bool {
        finding.engine == .persistence && finding.reason == PersistenceScanner.missingProgramReason
            && finding.path.hasSuffix(".plist") && !trashedPaths.contains(finding.path)
    }

    func requestOrphanRemoval(_ finding: Finding) {
        guard let item = OrphanedLaunchItem.inspect(finding.path) else {
            alert = AppAlert(title: "Not removed",
                             message: OrphanedLaunchItemError.noLongerOrphaned(finding.fileName).errorDescription ?? "")
            return
        }
        pendingOrphanRemoval = PendingOrphanRemoval(finding: finding, item: item)
    }

    /// Called only after the user confirms. Stops the job and moves its plist to the Trash.
    func confirmOrphanRemoval(_ pending: PendingOrphanRemoval) {
        let path = pending.item.plist.path
        orphanRemovalsInFlight.insert(path)
        Task {
            defer { self.orphanRemovalsInFlight.remove(path) }
            do {
                let report = try await pending.item.remove()
                if report.removedCount > 0 {
                    trashedPaths.insert(path)
                    logger.info("User removed orphaned startup item \(pending.item.displayName): \(path)")
                } else if let failure = report.failures.first {
                    let why: String = switch failure.outcome {
                    case .skipped(let reason): reason
                    case .failed(let reason): reason
                    case .blockedByMacOS: UninstallReport.blockedExplanation
                    default: "Unknown reason"
                    }
                    alert = AppAlert(title: "Could not remove \(pending.item.displayName)", message: why)
                }
            } catch {
                alert = AppAlert(title: "Could not remove \(pending.item.displayName)", message: error.localizedDescription)
            }
        }
    }

    func ignore(_ finding: Finding, sessionID: UUID) {
        var f = finding
        if f.sha256 == nil { f.sha256 = FileHasher.fingerprint(for: f.path) }
        let entry = IgnoreEntry(finding: f)
        ignoreList.entries.append(entry)
        saveIgnoreList()
        updateSession(sessionID) { session in
            session.findings.removeAll { entry.matches($0) }
            session.ignoredCount += 1
        }
    }

    func unignore(_ entry: IgnoreEntry) {
        ignoreList.entries.removeAll { $0.id == entry.id }
        saveIgnoreList()
    }

    private func saveIgnoreList() {
        do { try ignoreList.save() } catch {
            alert = AppAlert(title: "Could not save ignore list", message: error.localizedDescription)
        }
    }

    func lookUpOnVirusTotal(_ finding: Finding, sessionID: UUID) {
        guard let key = KeychainStore.virusTotal.read() else {
            alert = AppAlert(title: "No VirusTotal API key", message: "Add your own VirusTotal API key in Settings › VirusTotal. Only the file's SHA-256 hash is sent; files are never uploaded.")
            return
        }
        vtLookupsInFlight.insert(finding.id)
        let engine = HashLookupEngine(client: VirusTotalClient(apiKey: key))
        Task {
            defer { self.vtLookupsInFlight.remove(finding.id) }
            do {
                let result = try await engine.lookup(path: finding.path, unitPath: finding.unitPath)
                self.updateSession(sessionID) { session in
                    session.findings.removeAll { $0.engine == .virustotal && $0.path == finding.path }
                    session.findings.append(result)
                    if !session.enginesUsed.contains(.virustotal) { session.enginesUsed.append(.virustotal) }
                }
            } catch {
                self.logger.warning("VirusTotal lookup failed: \(error.localizedDescription)")
                self.alert = AppAlert(title: "VirusTotal lookup failed", message: error.localizedDescription)
            }
        }
    }

    private func updateSession(_ id: UUID, _ mutate: (inout ScanSession) -> Void) {
        if currentSession?.id == id, var s = currentSession {
            mutate(&s)
            currentSession = s
        }
        if let i = history.firstIndex(where: { $0.id == id }) {
            mutate(&history[i])
            try? historyStore.save(history[i])
        }
    }

    // MARK: - History & export

    func deleteHistory(_ session: ScanSession) {
        try? historyStore.delete(session.id)
        history.removeAll { $0.id == session.id }
        if currentSession?.id == session.id { currentSession = nil }
    }

    func export(_ sessions: [ScanSession], format: ExportFormat) {
        guard !sessions.isEmpty else { return }
        let panel = NSSavePanel()
        let stamp = (sessions.count == 1 ? sessions[0].startedAt : Date())
            .formatted(.iso8601.year().month().day().dateSeparator(.dash))
        panel.nameFieldStringValue = sessions.count == 1 ? "MacScan-\(stamp).\(format.fileExtension)" : "MacScan-history-\(stamp).\(format.fileExtension)"
        panel.allowedContentTypes = [format == .json ? .json : .commaSeparatedText]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try ScanExporter.export(sessions, as: format).write(to: url, options: .atomic)
            logger.info("Exported \(sessions.count) scan(s) to \(url.path)")
        } catch {
            alert = AppAlert(title: "Export failed", message: error.localizedDescription)
        }
    }

    // MARK: - ClamAV database update (only on click)

    func updateDatabase() {
        guard freshclam?.running != true else { showFreshclam = true; return }
        guard freshclamInstalled else {
            installHelp = .clamav
            return
        }
        freshclam = FreshclamRun()
        showFreshclam = true
        let engine = ClamAVEngine(settings: settings)
        freshclamTask = Task {
            do {
                try await engine.updateDatabase { line in
                    await self.appendFreshclamLine(line)
                }
                self.freshclam?.succeeded = true
            } catch is CancellationError {
                self.freshclam?.error = "Cancelled."
            } catch {
                self.freshclam?.error = error.localizedDescription
            }
            self.freshclam?.running = false
            self.refreshEngineStatus()
        }
    }

    private func appendFreshclamLine(_ line: String) {
        freshclam?.lines.append(line)
    }

    func cancelDatabaseUpdate() {
        freshclamTask?.cancel()
    }

    // MARK: - VirusTotal key

    func saveVirusTotalKey(_ key: String) {
        KeychainStore.virusTotal.save(key)
        hasVirusTotalKey = KeychainStore.virusTotal.read() != nil
        refreshEngineStatus()
    }
}
