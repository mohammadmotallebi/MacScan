import AppKit
import MacScanCore
import Observation

/// State for the Install section: open a download, check every app in it, and install after the user agrees.
@MainActor
@Observable
final class InstallModel {
    enum Phase: Equatable {
        case idle
        case opening
        case checking
        case ready
        case installing
        case installed(URL)
    }

    private(set) var phase: Phase = .idle
    private(set) var source: URL?
    private(set) var kind: InstallerKind?
    private(set) var candidates: [InstallCandidate] = []
    /// What the scan engines found inside.
    private(set) var session: ScanSession?
    private(set) var package: PackageReview?
    private(set) var progress: ScanProgress?
    private(set) var recent: [URL] = []
    var errorMessage: String?
    /// Set when the app to replace is running.
    var mustQuit: NSRunningApplication?
    /// Waiting for "Install Anyway" on a flagged app.
    var pendingRisky: InstallCandidate?

    @ObservationIgnored private var opened: OpenedInstaller?
    @ObservationIgnored private let opener = InstallerOpener()
    @ObservationIgnored private var task: Task<Void, Never>?
    private let logger = FileLogger.shared

    var isBusy: Bool { [.opening, .checking, .installing].contains(phase) }

    // MARK: Picking

    /// Installers in Downloads from the last 30 days, newest first.
    func refreshRecent() {
        let folder = AppPaths.downloads
        let keys: [URLResourceKey] = [.contentModificationDateKey]
        let items = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles])) ?? []
        let cutoff = Date().addingTimeInterval(-30 * 86_400)
        recent = items
            .filter { InstallerKind.of($0) != nil }
            .compactMap { url -> (URL, Date)? in
                let date = (try? url.resourceValues(forKeys: Set(keys)))?.contentModificationDate ?? .distantPast
                return date > cutoff ? (url, date) : nil
            }
            .sorted { $0.1 > $1.1 }
            .prefix(8)
            .map(\.0)
    }

    func choose(state: AppState) {
        let panel = NSOpenPanel()
        panel.title = "Choose an app or installer"
        panel.allowedContentTypes = [.diskImage, .zip, .applicationBundle, .init(filenameExtension: "pkg")!]
        panel.treatsFilePackagesAsDirectories = false
        panel.directoryURL = AppPaths.downloads
        panel.prompt = "Check"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        load(url, state: state)
    }

    // MARK: Checking

    func load(_ url: URL, state: AppState) {
        guard !isBusy else { return }
        task = Task { await self.check(url, state: state) }
    }

    private func check(_ url: URL, state: AppState) async {
        await close()
        source = url
        kind = InstallerKind.of(url)
        candidates = []
        session = nil
        package = nil
        phase = .opening
        logger.info("Install: checking \(url.path)")
        do {
            let opened = try await opener.open(url)
            self.opened = opened
            phase = .checking
            if let expanded = opened.expandedPackage {
                package = await PackageReview.review(package: url, expanded: expanded)
            }
            candidates = await withTaskGroup(of: InstallCandidate.self) { group in
                for app in opened.apps { group.addTask { await AppInspector().inspect(app) } }
                var result: [InstallCandidate] = []
                for await c in group { result.append(c) }
                return result.sorted { $0.name < $1.name }
            }
            // Scan everything inside: the apps, or the whole unpacked package (scripts too).
            let targets: [ScanTarget] = opened.expandedPackage.map { [.path($0)] } ?? opened.apps.map { .path($0) }
            if !targets.isEmpty {
                var result = await scan(targets, state: state)
                result.targets = ["Install check: \(url.lastPathComponent)"]
                session = result
                state.saveToHistory(result)
            }
            if candidates.isEmpty && opened.expandedPackage == nil {
                errorMessage = InstallError.noApp.localizedDescription
            }
            phase = .ready
            logger.info("Install: \(candidates.count) app(s), \(session?.flagged.count ?? 0) flagged")
        } catch {
            errorMessage = error.localizedDescription
            logger.warning("Install: \(error.localizedDescription)")
            phase = .idle
            source = nil
        }
    }

    private func scan(_ targets: [ScanTarget], state: AppState) async -> ScanSession {
        let settings = state.settings
        let apiKey = state.hasVirusTotalKey ? KeychainStore.virusTotal.read() : nil
        let coordinator = ScanCoordinator(
            engines: EngineFactory.makeEngines(settings: settings),
            lookupEngine: EngineFactory.makeLookupEngine(apiKey: apiKey),
            settings: settings,
            ignoreList: state.ignoreList)
        return await coordinator.run(targets: targets) { progress in
            Task { @MainActor in self.progress = progress }
        }
    }

    /// Problems the scan found in one app.
    func findings(for candidate: InstallCandidate) -> [Finding] {
        (session?.flagged ?? []).filter { $0.path == candidate.url.path || $0.path.hasPrefix(candidate.url.path + "/") }
    }

    /// Everything flagged in a package (scripts and payload).
    var flagged: [Finding] { session?.flagged ?? [] }

    /// Red when the scan found a threat or something serious about the app itself.
    func isRisky(_ candidate: InstallCandidate) -> Bool {
        candidate.worst == .danger || !findings(for: candidate).isEmpty
    }

    // MARK: Installing

    func install(_ candidate: InstallCandidate, state: AppState, confirmedRisk: Bool = false) {
        guard phase == .ready else { return }
        if isRisky(candidate) && !confirmedRisk {
            pendingRisky = candidate
            return
        }
        if let existing = candidate.existing,
           let running = NSWorkspace.shared.runningApplications.first(where: { $0.bundleURL?.standardizedFileURL.path == existing.path }) {
            mustQuit = running
            return
        }
        phase = .installing
        task = Task {
            do {
                let target = try await AppInstaller().install(candidate.url)
                logger.info("Install: user installed \(candidate.name) \(candidate.version ?? "") to \(target.path)")
                state.markAppsSeen()
                // The image stays open until the user is done, in case it holds more than one app.
                phase = .installed(target)
            } catch {
                errorMessage = error.localizedDescription
                logger.warning("Install failed: \(error.localizedDescription)")
                phase = .ready
            }
        }
    }

    /// A package is installed by Apple's Installer, after the check.
    func openInInstaller() {
        guard let source else { return }
        logger.info("Install: opening \(source.lastPathComponent) in Installer")
        NSWorkspace.shared.open([source], withApplicationAt: URL(fileURLWithPath: "/System/Library/CoreServices/Installer.app"),
                                configuration: NSWorkspace.OpenConfiguration())
    }

    func quitAndInstall(_ candidate: InstallCandidate, state: AppState) {
        guard let app = mustQuit else { return }
        mustQuit = nil
        app.terminate()
        Task {
            for _ in 0..<40 where !app.isTerminated { try? await Task.sleep(for: .milliseconds(250)) }
            if app.isTerminated {
                install(candidate, state: state, confirmedRisk: true)
            } else {
                errorMessage = "\(app.localizedName ?? "The app") didn't quit. Quit it yourself, then try again."
            }
        }
    }

    func trashInstaller() {
        guard let source else { return }
        Task {
            await close()
            do {
                try FileManager.default.trashItem(at: source, resultingItemURL: nil)
                logger.info("Install: user moved \(source.lastPathComponent) to the Trash")
                reset()
                refreshRecent()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    func reset() {
        task?.cancel()
        Task { await close() }
        phase = .idle
        source = nil
        kind = nil
        candidates = []
        session = nil
        package = nil
        progress = nil
    }

    /// Ejects the disk image and deletes the temporary copy.
    private func close() async {
        guard let opened else { return }
        self.opened = nil
        await opener.close(opened)
    }
}
