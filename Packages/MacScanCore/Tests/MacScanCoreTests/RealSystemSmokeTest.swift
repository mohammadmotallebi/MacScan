// Opt-in smoke test that scans your real /Applications (read-only, no ClamAV):
//   MACSCAN_REAL_PROBE=/tmp/macscan-probe.txt swift test --filter realApplicationsProbe
import Foundation
import Testing
@testable import MacScanCore

@Test(.enabled(if: ProcessInfo.processInfo.environment["MACSCAN_REAL_PROBE"] != nil))
func realApplicationsProbe() async throws {
    var settings = ScanSettings()
    settings.enableClamAV = false
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))
    let start = ContinuousClock.now
    let session = await ScanCoordinator(engines: EngineFactory.makeEngines(settings: settings), settings: settings, logger: logger)
        .run(targets: [.applications]) { _ in }
    var out = "elapsed: \(ContinuousClock.now - start)\nstatus: \(session.status) items: \(session.itemsScanned)/\(session.itemsTotal) skipped: \(session.skippedCount) issues: \(session.issues.count)\n"
    out += "threat: \(session.count(.threat)) warning: \(session.count(.warning)) clean: \(session.count(.clean))\nnotes: \(session.notes)\n"
    for f in session.findings where f.severity > .clean { out += "\(f.severity) | \(f.engine.title) | \(f.reason) | \(f.path)\n" }
    try out.write(toFile: ProcessInfo.processInfo.environment["MACSCAN_REAL_PROBE"]!, atomically: true, encoding: .utf8)
}

// Opt-in: scan your real startup items (read-only, no ClamAV):
//   MACSCAN_STARTUP_PROBE=/tmp/macscan-startup.txt swift test --filter realStartupItemsProbe
@Test(.enabled(if: ProcessInfo.processInfo.environment["MACSCAN_STARTUP_PROBE"] != nil))
func realStartupItemsProbe() async throws {
    var settings = ScanSettings()
    settings.enableClamAV = false
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))
    var targets: [ScanTarget] = [.startupItems]
    if let extra = ProcessInfo.processInfo.environment["MACSCAN_EXTRA_PATH"] { targets.append(.path(URL(fileURLWithPath: extra))) }
    let start = ContinuousClock.now
    let session = await ScanCoordinator(engines: EngineFactory.makeEngines(settings: settings), settings: settings, logger: logger)
        .run(targets: targets) { _ in }
    var out = "elapsed: \(ContinuousClock.now - start) engines: \(session.enginesUsed.map(\.title))\n"
    out += "threat: \(session.count(.threat)) warning: \(session.count(.warning)) clean: \(session.count(.clean)) items: \(session.itemsTotal)\n"
    for f in session.findings where f.severity > .clean { out += "\(f.severity) | \(f.engine.title) | \(f.reason) | \(f.path)\n" }
    out += "--- clean startup items:\n"
    for f in session.findings where f.severity == .clean && f.engine == .persistence { out += "\(f.reason) | \(f.path)\n" }
    try out.write(toFile: ProcessInfo.processInfo.environment["MACSCAN_STARTUP_PROBE"]!, atomically: true, encoding: .utf8)
}

// Opt-in, read-only: list what uninstalling an app would remove (nothing is moved):
//   MACSCAN_UNINSTALL_PROBE="/Applications/Foo.app" swift test --filter realUninstallProbe
@Test(.enabled(if: ProcessInfo.processInfo.environment["MACSCAN_UNINSTALL_PROBE"] != nil))
func realUninstallProbe() throws {
    for path in ProcessInfo.processInfo.environment["MACSCAN_UNINSTALL_PROBE"]!.split(separator: ":") {
        guard let app = InstalledApp.load(URL(fileURLWithPath: String(path))) else { print("cannot load \(path)"); continue }
        let plan = try LeftoverFinder().find(app)
        print("=== \(app.name) \(app.bundleID ?? "-") team=\(app.teamID ?? "-") protected=\(app.protectionReason ?? "no") nested=\(app.nestedBundleIDs)")
        print("jobs to stop: \(plan.launchJobs.map { "\($0.domain.rawValue)/\($0.label)" })")
        print("processes: \(plan.processes.map { "\($0.pid) \($0.isOwnedByUser ? "user" : "root") \(($0.path as NSString).lastPathComponent)" })  receipts: \(plan.packageReceipts)")
        for l in plan.leftovers {
            print(String(format: "%-18@ %8.1f MB %@ %@  [%@]", l.category.rawValue as NSString, Double(l.size) / 1_048_576, l.requiresAdmin ? "🔒" : "  ", l.path, l.matchedBy))
        }
    }
}

// Opt-in, read-only: scan the programs running right now (no ClamAV):
//   MACSCAN_PROCESS_PROBE=/tmp/macscan-processes.txt swift test --filter realProcessProbe
@Test(.enabled(if: ProcessInfo.processInfo.environment["MACSCAN_PROCESS_PROBE"] != nil))
func realProcessProbe() async throws {
    var settings = ScanSettings()
    settings.enableClamAV = false
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))
    var start = ContinuousClock.now
    let inventory = try ProcessScanner().collect()
    var out = "inventory: \(ContinuousClock.now - start), \(inventory.findings.count) programs\n"
    start = ContinuousClock.now
    let session = await ScanCoordinator(engines: EngineFactory.makeEngines(settings: settings), settings: settings, logger: logger)
        .run(targets: [.runningProcesses]) { _ in }
    out += "scan: \(ContinuousClock.now - start) engines: \(session.enginesUsed.map(\.title))\n"
    out += "threat: \(session.count(.threat)) warning: \(session.count(.warning)) clean: \(session.count(.clean)) items: \(session.itemsTotal)\nnotes: \(session.notes)\n"
    for f in session.findings where f.severity > .clean { out += "\(f.severity) | \(f.engine.title) | \(f.reason) | \(f.path)\n" }
    out += "--- clean running programs:\n"
    for f in session.findings where f.severity == .clean && f.engine == .processes { out += "\(f.reason) | \(f.path)\n" }
    try out.write(toFile: ProcessInfo.processInfo.environment["MACSCAN_PROCESS_PROBE"]!, atomically: true, encoding: .utf8)
}

// Opt-in, read-only: a Full Check of this Mac without ClamAV and YARA (per-area counts):
//   MACSCAN_FULLCHECK_PROBE=/tmp/macscan-fullcheck.txt swift test --filter realFullCheckProbe
@Test(.enabled(if: ProcessInfo.processInfo.environment["MACSCAN_FULLCHECK_PROBE"] != nil))
func realFullCheckProbe() async throws {
    var settings = ScanSettings()
    settings.enableClamAV = false
    settings.enableYara = false
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))
    let start = ContinuousClock.now
    var session = await ScanCoordinator(engines: EngineFactory.makeEngines(settings: settings), settings: settings, logger: logger)
        .run(targets: FullCheck.targets) { _ in }
    session.fullCheck = FullCheckInfo(checks: await SecurityPosture().check())
    var out = "\(session.title): \(ContinuousClock.now - start), status \(session.status.rawValue), items \(session.itemsScanned)/\(session.itemsTotal)\n"
    for area in FullCheck.areas {
        let s = session.summary(of: area)
        out += "\(area.title): threats \(s.threats) warnings \(s.warnings) clean \(s.clean)\n"
    }
    out += "no area: \(session.findings.filter { $0.area == nil }.count)\n"
    out += "security: \(String(describing: session.fullCheck?.security))\n"
    for f in session.findings where f.severity > .clean { out += "\(f.area?.title ?? "-") | \(f.severity) | \(f.engine.title) | \(f.reason) | \(f.path)\n" }
    for f in session.findings where f.area == nil { out += "NO AREA | \(f.engine.title) | \(f.path) | unit \(f.unitPath)\n" }
    try out.write(toFile: ProcessInfo.processInfo.environment["MACSCAN_FULLCHECK_PROBE"]!, atomically: true, encoding: .utf8)
}

// Opt-in: list apps that seem removed but left files in your Library (read-only):
//   MACSCAN_REMOVED_PROBE=/tmp/macscan-removed.txt swift test --filter realRemovedAppsProbe
@Test(.enabled(if: ProcessInfo.processInfo.environment["MACSCAN_REMOVED_PROBE"] != nil))
func realRemovedAppsProbe() throws {
    let start = ContinuousClock.now
    let installed = (InstalledApp.listInstalled() + InstalledApp.listTrash()).flatMap(\.allBundleIDs)
    let found = RemovedAppFinder(installedIDs: Set(installed)).find()
    var out = "elapsed: \(ContinuousClock.now - start), installed IDs: \(installed.count), found: \(found.count)\n"
    for c in found {
        out += "\(c.bundleID) | \(ByteCountFormatter.string(fromByteCount: c.size, countStyle: .file)) | \(c.paths.map { ($0 as NSString).lastPathComponent == c.bundleID ? ($0 as NSString).deletingLastPathComponent.components(separatedBy: "/Library/").last! : ($0 as NSString).lastPathComponent }.joined(separator: ", "))\n"
    }
    try out.write(toFile: ProcessInfo.processInfo.environment["MACSCAN_REMOVED_PROBE"]!, atomically: true, encoding: .utf8)
}
