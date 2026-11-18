import Foundation

public struct ScanProgress: Codable, Sendable, Equatable {
    public enum Phase: String, Codable, Sendable, Equatable {
        case enumerating = "Collecting files…"
        case scanning = "Scanning…"
        case lookingUp = "Looking up hashes on VirusTotal…"
        case finishing = "Finishing…"
    }

    public var phase: Phase
    public var itemsDone: Int
    public var itemsTotal: Int
    public var currentFile: String?
    public var status: String?

    public init(phase: Phase, itemsDone: Int = 0, itemsTotal: Int = 0, currentFile: String? = nil, status: String? = nil) {
        self.phase = phase
        self.itemsDone = itemsDone
        self.itemsTotal = itemsTotal
        self.currentFile = currentFile
        self.status = status
    }

    public var fraction: Double? {
        guard phase == .scanning || phase == .lookingUp, itemsTotal > 0 else { return nil }
        return min(1, Double(itemsDone) / Double(itemsTotal))
    }
}

/// Builds the enabled engines from settings. Register new engines here.
public enum EngineFactory {
    public static func makeEngines(settings: ScanSettings) -> [any ScanEngine] {
        var engines: [any ScanEngine] = []
        if settings.enableClamAV { engines.append(ClamAVEngine(settings: settings)) }
        if settings.enableYara { engines.append(YaraEngine(settings: settings)) }
        if settings.enableIntegrity { engines.append(AppIntegrityEngine()) }
        return engines
    }

    public static func makeLookupEngine(apiKey: String?) -> HashLookupEngine? {
        guard let apiKey, !apiKey.isEmpty else { return nil }
        return HashLookupEngine(client: VirusTotalClient(apiKey: apiKey))
    }
}

/// Runs a scan: enumerate → run all engines concurrently → post-process (hashes, ignore list, clean rows, VT).
public struct ScanCoordinator: Sendable {
    let engines: [any ScanEngine]
    let lookupEngine: HashLookupEngine?
    let settings: ScanSettings
    let ignoreList: IgnoreList
    let logger: FileLogger
    let persistenceLocations: PersistenceLocations
    let processLister: any ProcessListing
    let browserLocations: BrowserLocations

    public init(
        engines: [any ScanEngine],
        lookupEngine: HashLookupEngine? = nil,
        settings: ScanSettings,
        ignoreList: IgnoreList = IgnoreList(),
        logger: FileLogger = .shared,
        persistenceLocations: PersistenceLocations = .system,
        processLister: any ProcessListing = SystemProcessList(),
        browserLocations: BrowserLocations = .system
    ) {
        self.browserLocations = browserLocations
        self.processLister = processLister
        self.persistenceLocations = persistenceLocations
        self.engines = engines
        self.lookupEngine = lookupEngine
        self.settings = settings
        self.ignoreList = ignoreList
        self.logger = logger
    }

    /// Never throws: cancellation and engine failures are recorded in the returned session.
    public func run(targets: [ScanTarget], onProgress: @escaping @Sendable (ScanProgress) -> Void) async -> ScanSession {
        var session = ScanSession(targets: targets.map(\.displayName))
        logger.info("Scan started: \(session.targets.joined(separator: ", "))")
        onProgress(ScanProgress(phase: .enumerating))

        // 1. Enumerate.
        let enumeration: EnumerationResult
        do {
            enumeration = try FileEnumerator(settings: settings, persistenceLocations: persistenceLocations, processLister: processLister, browserLocations: browserLocations).enumerate(targets)
        } catch {
            return finish(&session, status: .cancelled)
        }
        session.issues = enumeration.issues
        session.skippedCount = enumeration.skippedCount
        session.notes += enumeration.notes
        session.startupSnapshot = enumeration.startupSnapshot
        session.extensionSnapshot = enumeration.extensionSnapshot
        session.itemsTotal = enumeration.items.count
        for issue in enumeration.issues.prefix(50) {
            logger.warning("Cannot read \(issue.path): \(issue.message)")
        }

        // 2. Which engines can run?
        var active: [any ScanEngine] = []
        for engine in engines {
            let availability = await engine.availability()
            if availability.isAvailable {
                active.append(engine)
                session.enginesUsed.append(engine.id)
            } else {
                session.notes.append("\(engine.displayName) not used: \(availability.summary)")
            }
        }
        if active.isEmpty {
            session.notes.append("No scan engines are available. Install ClamAV/YARA or enable App Integrity checks in Settings.")
            return finish(&session, status: .failed)
        }

        // 3. Run engines concurrently over their items.
        let items = enumeration.items
        let tracker = ProgressTracker(items: items, engines: active, onProgress: onProgress)
        await tracker.emit(force: true)
        let context = ScanContext(settings: settings, logger: logger)

        let errors: [(EngineID, Error)] = await withTaskGroup(of: (EngineID, Error?).self) { group in
            for engine in active {
                let handled = items.filter { engine.handles($0) }
                let engineID = engine.id
                group.addTask {
                    do {
                        try await engine.scan(handled, context: context) { event in
                            await tracker.handle(event, from: engineID)
                        }
                        await tracker.engineFinished(engineID, handled: handled)
                        return (engineID, nil)
                    } catch {
                        // Items this engine never reached stay unscanned (honest partial counts).
                        return (engineID, error)
                    }
                }
            }
            var errors: [(EngineID, Error)] = []
            for await (id, error) in group {
                if let error { errors.append((id, error)) }
            }
            return errors
        }

        let cancelled = Task.isCancelled
        for (id, error) in errors where !(error is CancellationError) {
            session.notes.append("\(id.title) failed: \(error.localizedDescription)")
            logger.error("\(id.title) failed: \(error.localizedDescription)")
        }
        session.notes += await tracker.notes
        session.itemsScanned = await tracker.done
        onProgress(ScanProgress(phase: .finishing, itemsDone: session.itemsScanned, itemsTotal: session.itemsTotal))

        // 4. Post-process.
        // A running program's signature verdict is in its process finding; drop the integrity engine's
        // duplicate for the same executable.
        let engineFindings = await tracker.findings.filter {
            !($0.engine == .integrity && enumeration.processExecutables.contains($0.path))
        }
        var findings = enumeration.persistenceFindings + enumeration.processFindings + enumeration.extensionFindings + engineFindings
        if targets.contains(.browserExtensions) { session.enginesUsed.append(.extensions) }
        if targets.contains(.runningProcesses) { session.enginesUsed.append(.processes) }
        if targets.contains(.startupItems) {
            session.enginesUsed.append(.persistence)
            session.notes.append("Login items managed in System Settings › General › Login Items, and configuration profiles in System Settings › Privacy & Security › Profiles, need admin rights to list — review those there.")
        }
        let completedUnits = await tracker.completedUnits
        addFingerprints(&findings)
        let (kept, ignored) = ignoreList.filter(findings)
        findings = kept
        session.ignoredCount = ignored

        // 5. Optional VirusTotal lookups for flagged items.
        if !cancelled, settings.vtAutoLookupFlagged, let lookupEngine {
            findings += await lookUpFlagged(findings, engine: lookupEngine, session: &session, onProgress: onProgress)
            let (vtKept, vtIgnored) = ignoreList.filter(findings)
            findings = vtKept
            session.ignoredCount += vtIgnored
        }

        // 6. One "clean" row per fully scanned unit (file or app) that has no findings at all.
        let unitsWithFindings = Set(findings.map(\.unitPath)).union(enumeration.coveredUnits)
        let engineNames = active.map(\.displayName).joined(separator: ", ")
        for unit in completedUnits.sorted() where !unitsWithFindings.contains(unit) {
            findings.append(Finding(path: unit, severity: .clean, engine: .scanner, reason: "No issues found", detail: "Checked by: \(engineNames)", unitPath: unit))
        }

        findings.sort(by: Self.displayOrder)
        session.findings = findings
        return finish(&session, status: cancelled ? .cancelled : .completed)
    }

    static func displayOrder(_ a: Finding, _ b: Finding) -> Bool {
        a.severity != b.severity ? a.severity > b.severity : a.path.localizedStandardCompare(b.path) == .orderedAscending
    }

    /// Step 5 on its own, for a session scanned by the elevated (root) worker, which never sees the API key.
    public func lookUpFlagged(in session: ScanSession, onProgress: @escaping @Sendable (ScanProgress) -> Void) async -> ScanSession {
        guard settings.vtAutoLookupFlagged, let lookupEngine, session.status != .cancelled, !Task.isCancelled else { return session }
        var session = session
        let results = await lookUpFlagged(session.findings, engine: lookupEngine, session: &session, onProgress: onProgress)
        let (kept, ignored) = ignoreList.filter(results)
        session.ignoredCount += ignored
        session.findings = (session.findings + kept).sorted(by: Self.displayOrder)
        return session
    }

    private func finish(_ session: inout ScanSession, status: ScanStatus) -> ScanSession {
        session.status = status
        session.finishedAt = Date()
        logger.info("Scan \(status.rawValue): \(session.itemsScanned)/\(session.itemsTotal) items, \(session.count(.threat)) threat(s), \(session.count(.warning)) warning(s), \(session.issues.count) unreadable")
        return session
    }

    private func addFingerprints(_ findings: inout [Finding]) {
        var cache: [String: String?] = [:]
        for i in findings.indices where findings[i].severity > .clean && findings[i].sha256 == nil {
            let path = findings[i].path
            if let cached = cache[path] {
                findings[i].sha256 = cached
            } else {
                let hash = FileHasher.fingerprint(for: path)
                cache[path] = hash
                findings[i].sha256 = hash
            }
        }
    }

    private func lookUpFlagged(
        _ findings: [Finding],
        engine: HashLookupEngine,
        session: inout ScanSession,
        onProgress: @escaping @Sendable (ScanProgress) -> Void
    ) async -> [Finding] {
        var seen = Set<String>()
        let flaggedPaths = findings.filter { $0.severity > .clean && $0.engine != .virustotal }
            .compactMap { seen.insert($0.path).inserted ? ($0.path, $0.unitPath) : nil }
        guard !flaggedPaths.isEmpty else { return [] }

        var results: [Finding] = []
        for (index, (path, unit)) in flaggedPaths.enumerated() {
            if Task.isCancelled { break }
            onProgress(ScanProgress(phase: .lookingUp, itemsDone: index, itemsTotal: flaggedPaths.count, currentFile: path))
            do {
                results.append(try await engine.lookup(path: path, unitPath: unit))
            } catch is CancellationError {
                break
            } catch {
                session.notes.append("VirusTotal: \(error.localizedDescription)")
                if case VirusTotalError.quotaExceeded = error { break }
                if case VirusTotalError.invalidAPIKey = error { break }
            }
        }
        if !results.isEmpty { session.enginesUsed.append(.virustotal) }
        return results
    }
}

// MARK: - Progress tracking

/// Counts an item as scanned when every engine that handles it has finished with it.
actor ProgressTracker {
    private var remaining: [String: Int] = [:]
    private var unitOf: [String: String] = [:]
    private var unitRemaining: [String: Int] = [:]
    private var finishedBy: [EngineID: Set<String>] = [:]
    private let onProgress: @Sendable (ScanProgress) -> Void
    private var lastEmit = ContinuousClock.now - .seconds(1)
    private var current: String?
    private var status: String?

    let total: Int
    private(set) var done = 0
    private(set) var findings: [Finding] = []
    private(set) var notes: [String] = []
    private(set) var completedUnits = Set<String>()

    init(items: [ScanItem], engines: [any ScanEngine], onProgress: @escaping @Sendable (ScanProgress) -> Void) {
        self.onProgress = onProgress
        self.total = items.count
        var done = 0
        var remaining: [String: Int] = [:]
        var unitOf: [String: String] = [:]
        var unitRemaining: [String: Int] = [:]
        var completed = Set<String>()
        for item in items {
            let count = engines.filter { $0.handles(item) }.count
            unitOf[item.path] = item.unitPath
            if count == 0 {
                done += 1   // nothing to do for this item; it doesn't hold its unit open
                unitRemaining[item.unitPath, default: 0] += 0
            } else {
                remaining[item.path, default: 0] += count
                unitRemaining[item.unitPath, default: 0] += 1
            }
        }
        for (unit, count) in unitRemaining where count == 0 {
            completed.insert(unit)
        }
        self.done = done
        self.remaining = remaining
        self.unitOf = unitOf
        self.unitRemaining = unitRemaining
        self.completedUnits = completed
    }

    func handle(_ event: EngineEvent, from engine: EngineID) {
        switch event {
        case .itemStarted(let path):
            current = path
            emit()
        case .itemFinished(let path):
            markFinished(path, by: engine)
            emit()
        case .finding(let f):
            findings.append(f)
        case .note(let n):
            if n.hasSuffix("…") {
                status = n
                emit(force: true)
            } else {
                notes.append(n)
            }
        }
    }

    func engineFinished(_ engine: EngineID, handled: [ScanItem]) {
        for item in handled { markFinished(item.path, by: engine) }
        emit(force: true)
    }

    private func markFinished(_ path: String, by engine: EngineID) {
        guard finishedBy[engine, default: []].insert(path).inserted, let r = remaining[path], r > 0 else { return }
        remaining[path] = r - 1
        if r - 1 == 0 {
            done += 1
            current = path
            status = nil
            if let unit = unitOf[path] { decrementUnit(unit) }
        }
    }

    private func decrementUnit(_ unit: String) {
        guard let r = unitRemaining[unit] else { return }
        if r <= 1 {
            unitRemaining[unit] = 0
            completedUnits.insert(unit)
        } else {
            unitRemaining[unit] = r - 1
        }
    }

    func emit(force: Bool = false) {
        let now = ContinuousClock.now
        guard force || now - lastEmit > .milliseconds(100) else { return }
        lastEmit = now
        onProgress(ScanProgress(phase: .scanning, itemsDone: done, itemsTotal: total, currentFile: current, status: status))
    }
}
