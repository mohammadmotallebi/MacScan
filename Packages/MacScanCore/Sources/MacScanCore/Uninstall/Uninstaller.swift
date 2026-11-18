import AppKit
import Foundation

/// Moves an item to the Trash. Injectable so tests never touch the real Trash.
public protocol Trasher: Sendable {
    func trash(_ url: URL) throws
}

public struct SystemTrasher: Trasher {
    public init() {}
    public func trash(_ url: URL) throws {
        try FileManager.default.trashItem(at: url, resultingItemURL: nil)
    }
}

/// Runs a shell script as root after macOS asks for an administrator password. Injectable for tests.
public protocol AdminRunner: Sendable {
    /// Returns stdout, or throws `UninstallError.adminCancelled` if the user cancels the password prompt.
    func run(script: String, prompt: String) async throws -> String
}

public struct OsascriptAdminRunner: AdminRunner {
    public init() {}

    public func run(script: String, prompt: String) async throws -> String {
        let source = "do shell script \"\(Uninstaller.appleScriptEscape(script))\" with prompt \"\(Uninstaller.appleScriptEscape(prompt))\" with administrator privileges"
        let result = try await ProcessRunner.run(URL(fileURLWithPath: "/usr/bin/osascript"), ["-e", source])
        if result.exitCode != 0 {
            if result.stderr.contains("-128") || result.stderr.lowercased().contains("user canceled") {
                throw UninstallError.adminCancelled
            }
            throw UninstallError.adminFailed(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return result.stdout
    }
}

public enum UninstallError: Error, LocalizedError, Equatable {
    case protectedApp(String)
    case adminCancelled
    case adminFailed(String)

    public var errorDescription: String? {
        switch self {
        case .protectedApp(let why): "This app can't be uninstalled: \(why)."
        case .adminCancelled: "The administrator password prompt was cancelled, so system-owned items were left in place."
        case .adminFailed(let message): "Removing system-owned items failed: \(message)"
        }
    }
}

public struct UninstallReport: Sendable {
    public enum Outcome: Sendable, Equatable {
        case movedToTrash
        case deleted
        case failed(String)
        case skipped(String)

        public var succeeded: Bool { self == .movedToTrash || self == .deleted }
    }

    public var appName: String
    public var results: [(leftover: Leftover, outcome: Outcome)] = []
    public var stoppedLaunchItems: [String] = []
    public var quitProcesses: [String] = []
    public var forgottenReceipts: [String] = []
    public var notes: [String] = []

    public var movedCount: Int { results.filter { $0.outcome == .movedToTrash }.count }
    public var deletedCount: Int { results.filter { $0.outcome == .deleted }.count }
    public var removedCount: Int { movedCount + deletedCount }
    public var failures: [(leftover: Leftover, outcome: Outcome)] { results.filter { !$0.outcome.succeeded } }
    public var freedBytes: Int64 { results.filter { $0.outcome.succeeded }.reduce(0) { $0 + $1.leftover.size } }
}

/// Performs an uninstall the user has reviewed and confirmed:
/// quit the app → stop its launch items → move the selected items to the Trash
/// (system-owned ones in one administrator step) → forget its installer receipts.
public struct Uninstaller: Sendable {
    let trasher: any Trasher
    let admin: any AdminRunner
    let logger: FileLogger
    let trashDirectory: URL
    let manageProcesses: Bool

    public init(
        trasher: any Trasher = SystemTrasher(),
        admin: any AdminRunner = OsascriptAdminRunner(),
        logger: FileLogger = .shared,
        trashDirectory: URL = AppPaths.home.appendingPathComponent(".Trash"),
        manageProcesses: Bool = true
    ) {
        self.trasher = trasher
        self.admin = admin
        self.logger = logger
        self.trashDirectory = trashDirectory
        self.manageProcesses = manageProcesses
    }

    /// - Parameter permanently: delete instead of moving to the Trash. Items already in the Trash are always deleted.
    public func uninstall(_ plan: UninstallPlan, selected: Set<String>, permanently: Bool = false,
                          progress: @escaping @Sendable (String) -> Void = { _ in }) async throws -> UninstallReport {
        if let reason = plan.app.protectionReason { throw UninstallError.protectedApp(reason) }
        var report = UninstallReport(appName: plan.app.name)
        let chosen = plan.leftovers.filter { selected.contains($0.path) }
        logger.info("Uninstall \(plan.app.name) (\(plan.app.bundleID ?? "no bundle ID")): \(chosen.count) item(s) selected")

        // 1. Quit the app's own processes (user-owned; root ones are stopped by launchd below).
        if manageProcesses, !plan.processes.isEmpty {
            progress("Quitting \(plan.app.name)…")
            report.quitProcesses = await quit(plan.processes.filter(\.isOwnedByUser))
        }

        // 2. Stop and unregister the app's background jobs in the user session (no password needed):
        //    by plist for selected launch agents, and by label for everything the app registered
        //    (including helpers embedded in the bundle via SMAppService).
        let uid = getuid()
        let launchctl = URL(fileURLWithPath: "/bin/launchctl")
        var stopped = Set<String>()
        for item in chosen where item.launchDomain == .gui {
            progress("Stopping \(item.launchLabel ?? item.url.lastPathComponent)…")
            let r = try? await ProcessRunner.run(launchctl, ["bootout", "gui/\(uid)", item.path])
            if r?.exitCode == 0, stopped.insert(item.launchLabel ?? item.url.lastPathComponent).inserted {
                report.stoppedLaunchItems.append(item.launchLabel ?? item.url.lastPathComponent)
            }
        }
        if manageProcesses {
            for job in plan.launchJobs where job.domain == .gui && !stopped.contains(job.label) {
                progress("Unregistering \(job.label)…")
                let r = try? await ProcessRunner.run(launchctl, ["bootout", "gui/\(uid)/\(job.label)"])
                if r?.exitCode == 0, stopped.insert(job.label).inserted { report.stoppedLaunchItems.append(job.label) }
            }
        }

        // 3. Move user-owned items to the Trash (keeps Finder's "Put Back").
        //    Launch items first, the app bundle last.
        let ordered = chosen.sorted { order($0) < order($1) }
        var adminItems: [Leftover] = []
        for item in ordered {
            try Task.checkCancellation()
            guard FileManager.default.fileExists(atPath: item.path) || isSymlink(item.path) else {
                report.results.append((item, .skipped("Already gone")))
                continue
            }
            guard Self.isSafeToRemove(item.path) else {
                report.results.append((item, .skipped("Refused: protected location")))
                logger.error("Uninstall: refused to remove protected path \(item.path)")
                continue
            }
            if item.requiresAdmin || item.launchDomain == .system {
                adminItems.append(item)
                continue
            }
            let deleting = permanently || isInTrash(item.path)
            progress(deleting ? "Deleting \(item.url.lastPathComponent)…" : "Moving \(item.url.lastPathComponent) to the Trash…")
            do {
                if deleting {
                    try FileManager.default.removeItem(at: item.url)
                    report.results.append((item, .deleted))
                    logger.info("Uninstall: deleted permanently \(item.path)")
                } else {
                    try trasher.trash(item.url)
                    report.results.append((item, .movedToTrash))
                    logger.info("Uninstall: moved to Trash \(item.path)")
                }
            } catch {
                if PermissionErrors.isPermissionDenied(error) {
                    adminItems.append(item)
                } else {
                    report.results.append((item, .failed(error.localizedDescription)))
                    logger.error("Uninstall: could not trash \(item.path): \(error.localizedDescription)")
                }
            }
        }

        // 4. One administrator step for system-owned items, root daemons and receipts.
        let rootPIDs = manageProcesses ? plan.processes.filter { !$0.isOwnedByUser }.map(\.pid) : []
        let systemJobs = manageProcesses ? plan.launchJobs.filter { $0.domain == .system }.map(\.label) : []
        if !adminItems.isEmpty || !plan.packageReceipts.isEmpty || !systemJobs.isEmpty {
            progress("Waiting for your administrator password…")
            let deleteFlags = adminItems.map { permanently || isInTrash($0.path) }
            let script = Self.adminScript(items: adminItems, delete: deleteFlags, rootPIDs: rootPIDs, systemJobs: systemJobs,
                                          receipts: plan.packageReceipts, trashDirectory: trashDirectory, owner: uid)
            let prompt = "MacScan needs your password to remove the system components of \(plan.app.name)."
            do {
                let output = try await admin.run(script: script.text, prompt: prompt)
                let (ok, failed) = Self.parseAdminOutput(output)
                for (index, item) in adminItems.enumerated() {
                    if ok.contains(index) {
                        report.results.append((item, deleteFlags[index] ? .deleted : .movedToTrash))
                        if item.launchDomain == .system { report.stoppedLaunchItems.append(item.launchLabel ?? item.url.lastPathComponent) }
                        logger.info("Uninstall (admin): moved to Trash \(item.path)")
                    } else {
                        let why = failed.contains(index) ? "Could not be moved" : "Not processed"
                        report.results.append((item, .failed(why)))
                        logger.error("Uninstall (admin): \(why): \(item.path)")
                    }
                }
                report.forgottenReceipts = plan.packageReceipts
            } catch UninstallError.adminCancelled {
                for item in adminItems { report.results.append((item, .skipped("Password prompt cancelled"))) }
                report.notes.append(UninstallError.adminCancelled.errorDescription ?? "")
            }
        }

        // 5. Make sure nothing the app started is still around.
        if manageProcesses {
            let leftoverPIDs = LeftoverFinder.runningProcesses()
                .filter { $0.isOwnedByUser && $0.path.hasPrefix(plan.app.url.path + "/") }
            for p in leftoverPIDs { kill(p.pid, SIGKILL) }
        }

        report.notes += plan.notes
        if report.results.contains(where: { $0.outcome == .movedToTrash }) {
            report.notes.append("Moved items are in the Trash. Items that needed your password can't use Finder's “Put Back”; drag them back if you need to restore them.")
            if report.results.contains(where: { $0.outcome == .movedToTrash && $0.leftover.category == .application }) {
                report.notes.append("macOS keeps listing an app's background items in Login Items while the app is still in the Trash. Empty the Trash, or open the app under “In the Trash” in MacScan's Uninstall list and delete it permanently.")
            }
        }
        logger.info("Uninstall \(plan.app.name) finished: \(report.movedCount) moved, \(report.failures.count) not moved")
        return report
    }

    private func isInTrash(_ path: String) -> Bool {
        path.hasPrefix(trashDirectory.path + "/")
    }

    /// Last line of defence: never remove top-level or system locations, whatever the plan says.
    static func isSafeToRemove(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        let components = url.pathComponents.filter { $0 != "/" }
        guard components.count >= 2 else { return false }
        let p = url.path
        let home = AppPaths.home.path
        let critical: Set<String> = [
            home, home + "/Library", home + "/Library/Application Support", home + "/Library/Preferences",
            home + "/Library/Caches", home + "/Library/Containers", home + "/Library/Group Containers",
            home + "/Library/LaunchAgents", home + "/Applications", home + "/.Trash", home + "/Documents", home + "/Desktop",
            "/Applications", "/Library", "/Library/Application Support", "/Library/LaunchAgents", "/Library/LaunchDaemons",
            "/Library/PrivilegedHelperTools", "/Library/Preferences", "/Library/Caches", "/Users", "/private", "/private/var", "/opt", "/opt/homebrew", "/usr/local",
        ]
        if critical.contains(p) { return false }
        let forbiddenPrefixes = ["/System/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/usr/share/", "/private/etc/", "/etc/", "/private/var/db/", "/Library/Apple/"]
        return !forbiddenPrefixes.contains { p.hasPrefix($0) }
    }

    private func order(_ item: Leftover) -> Int {
        switch item.category {
        case .launchAgent, .launchDaemon: 0
        case .privilegedHelper: 1
        case .application: 9
        default: 5
        }
    }

    private func isSymlink(_ path: String) -> Bool {
        (try? FileManager.default.destinationOfSymbolicLink(atPath: path)) != nil
    }

    /// Asks apps to quit, then force-quits anything still running after a few seconds.
    func quit(_ processes: [RunningProcess]) async -> [String] {
        var names: [String] = []
        for p in processes {
            if let app = NSRunningApplication(processIdentifier: p.pid) {
                _ = await MainActor.run { app.terminate() }
            } else {
                kill(p.pid, SIGTERM)
            }
            names.append((p.path as NSString).lastPathComponent)
        }
        for _ in 0..<30 {
            if processes.allSatisfy({ kill($0.pid, 0) != 0 }) { break }
            try? await Task.sleep(for: .milliseconds(100))
        }
        for p in processes where kill(p.pid, 0) == 0 {
            kill(p.pid, SIGKILL)
        }
        return names
    }

    // MARK: - Admin script

    public struct AdminScript: Sendable {
        public let text: String
        public let destinations: [String]
    }

    /// Builds a /bin/sh script that stops root daemons, moves items into the user's Trash (owned by the user
    /// so emptying the Trash works), and forgets installer receipts. Each move prints "OK:<i>" or "FAIL:<i>".
    static func adminScript(items: [Leftover], delete: [Bool]? = nil, rootPIDs: [Int32], systemJobs: [String] = [],
                            receipts: [String], trashDirectory: URL, owner: uid_t) -> AdminScript {
        var lines: [String] = []
        var destinations: [String] = []
        var used = Set<String>()
        let stamp = Date().formatted(.iso8601.year().month().day().time(includingFractionalSeconds: false).timeSeparator(.omitted))

        for item in items where item.launchDomain == .system {
            lines.append("/bin/launchctl bootout system \(shellQuote(item.path)) 2>/dev/null")
        }
        for label in systemJobs {
            lines.append("/bin/launchctl bootout \(shellQuote("system/" + label)) 2>/dev/null")
        }
        for pid in rootPIDs { lines.append("/bin/kill -9 \(pid) 2>/dev/null") }

        for (index, item) in items.enumerated() {
            if delete?[index] == true {
                destinations.append("")
                lines.append("if /bin/rm -rf \(shellQuote(item.path)); then echo OK:\(index); else echo FAIL:\(index); fi")
                continue
            }
            var name = item.url.lastPathComponent
            var dest = trashDirectory.appendingPathComponent(name).path
            if FileManager.default.fileExists(atPath: dest) || used.contains(dest) {
                let base = (name as NSString).deletingPathExtension
                let ext = (name as NSString).pathExtension
                name = "\(base) (MacScan \(stamp)\(index))" + (ext.isEmpty ? "" : ".\(ext)")
                dest = trashDirectory.appendingPathComponent(name).path
            }
            used.insert(dest)
            destinations.append(dest)
            lines.append("if /bin/mv -f \(shellQuote(item.path)) \(shellQuote(dest)); then /usr/sbin/chown -R \(owner) \(shellQuote(dest)) 2>/dev/null; echo OK:\(index); else echo FAIL:\(index); fi")
        }
        for receipt in receipts {
            lines.append("/usr/sbin/pkgutil --forget \(shellQuote(receipt)) >/dev/null 2>&1")
        }
        lines.append("exit 0")
        return AdminScript(text: lines.joined(separator: "\n"), destinations: destinations)
    }

    static func parseAdminOutput(_ output: String) -> (ok: Set<Int>, failed: Set<Int>) {
        var ok = Set<Int>()
        var failed = Set<Int>()
        for line in output.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            if line.hasPrefix("OK:"), let i = Int(line.dropFirst(3)) { ok.insert(i) }
            if line.hasPrefix("FAIL:"), let i = Int(line.dropFirst(5)) { failed.insert(i) }
        }
        return (ok, failed)
    }

    /// Single-quotes a string for /bin/sh.
    static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Escapes a string for an AppleScript string literal.
    static func appleScriptEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}
