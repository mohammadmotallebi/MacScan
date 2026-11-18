import Darwin
import Foundation

/// One process that is running right now.
public struct LiveProcess: Hashable, Sendable {
    public var pid: Int32
    public var parentPID: Int32
    /// Effective user ID (0 = root).
    public var uid: UInt32
    /// Short process name from the kernel (at most 16 characters).
    public var name: String
    /// The executable file, or nil when it can't be read (see `executableDeleted`).
    public var path: String?
    /// The executable file was deleted or replaced after the process started.
    public var executableDeleted: Bool
    /// For a deleted executable: the path it was started from, when macOS still reveals it.
    public var launchPath: String?

    public init(pid: Int32, parentPID: Int32 = 1, uid: UInt32, name: String, path: String?,
                executableDeleted: Bool = false, launchPath: String? = nil) {
        self.pid = pid
        self.parentPID = parentPID
        self.uid = uid
        self.name = name
        self.path = path
        self.executableDeleted = executableDeleted
        self.launchPath = launchPath
    }
}

/// Where the process list comes from. Tests pass a fixed list.
public protocol ProcessListing: Sendable {
    func runningProcesses() -> [LiveProcess]
}

/// The real process table, read with sysctl and libproc. Read-only: no process is signalled or inspected
/// beyond its ID, owner, name and executable path.
public struct SystemProcessList: ProcessListing {
    public init() {}

    public func runningProcesses() -> [LiveProcess] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0 else { return [] }
        let stride = MemoryLayout<kinfo_proc>.stride
        let capacity = size / stride + 64   // room for processes that start in between
        var table = [kinfo_proc](repeating: kinfo_proc(), count: capacity)
        size = capacity * stride
        guard sysctl(&mib, 3, &table, &size, nil, 0) == 0 else { return [] }

        var result: [LiveProcess] = []
        for info in table.prefix(size / stride) where info.kp_proc.p_pid > 0 {
            let pid = info.kp_proc.p_pid
            var process = LiveProcess(
                pid: pid, parentPID: info.kp_eproc.e_ppid, uid: info.kp_eproc.e_ucred.cr_uid,
                name: Self.name(of: info), path: nil)
            var buffer = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
            if proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 {
                process.path = String(decoding: buffer.prefix { $0 != 0 }, as: UTF8.self)
            } else {
                switch errno {
                case ESRCH: continue   // exited meanwhile, or a zombie: nothing is running
                case ENOENT:
                    process.executableDeleted = true
                    process.launchPath = Self.launchPath(of: pid)
                default: break
                }
            }
            result.append(process)
        }
        return result
    }

    static func name(of info: kinfo_proc) -> String {
        withUnsafeBytes(of: info.kp_proc.p_comm) { bytes in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
    }

    /// The path a process was started with (first entry of KERN_PROCARGS2). Only readable for the
    /// user's own processes, or for all of them as root.
    static func launchPath(of pid: Int32) -> String? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        let bytes = buffer[MemoryLayout<Int32>.size..<size]
        let path = String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        return path.hasPrefix("/") ? path : nil
    }
}

public struct ProcessInventory: Sendable {
    /// One finding per running program (engine `.processes`), any severity.
    public var findings: [Finding] = []
    /// Executables to run through the scan engines (plus their enclosing app's integrity).
    public var programPaths: [String] = []
    /// Paths already described by a process finding (no extra "No issues found" rows needed).
    public var coveredUnits: Set<String> = []
    public var notes: [String] = []
}

/// Lists the programs that are running right now and flags risky ones: untrusted signatures (worse as
/// root), temporary/Downloads/hidden locations, deleted program files and publisher impersonation.
/// Read-only: no process is stopped, suspended or changed.
public struct ProcessScanner: Sendable {
    public let lister: any ProcessListing
    public let home: URL

    public init(lister: any ProcessListing = SystemProcessList(), home: URL = AppPaths.home) {
        self.lister = lister
        self.home = home
    }

    public static let cleanReason = "Running program"
    public static let deletedReason = "Running program's file has been deleted"

    /// Folders on the signed, read-only system volume (and its cryptexes). Nothing can be added there.
    static let sealedSystemPrefixes = [
        "/System/Library/", "/System/Applications/", "/System/iOSSupport/", "/System/DriverKit/", "/System/Developer/",
        "/System/Cryptexes/", "/System/Volumes/Preboot/Cryptexes/",
        "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/usr/share/", "/usr/standalone/", "/bin/", "/sbin/",
    ]

    static func isSealedSystemPath(_ path: String) -> Bool {
        sealedSystemPrefixes.contains { path.hasPrefix($0) }
    }

    static let temporaryPrefixes = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/", "/private/var/folders/", "/var/folders/"]

    public func collect() throws -> ProcessInventory {
        var inv = ProcessInventory()
        let all = lister.runningProcesses()
        let nameOf = Dictionary(all.map { ($0.pid, $0.name) }, uniquingKeysWith: { first, _ in first })

        // Group by program: a browser's twenty helper processes are one row.
        var groups: [String: [LiveProcess]] = [:]
        var uninspected = 0
        for process in all {
            if let path = process.path {
                groups[path, default: []].append(process)
            } else if process.executableDeleted {
                groups["deleted:" + (process.launchPath ?? process.name), default: []].append(process)
            } else {
                uninspected += 1
            }
        }

        var systemProcesses = 0
        for key in groups.keys.sorted() {
            try Task.checkCancellation()
            let processes = groups[key]!.sorted { $0.pid < $1.pid }
            guard let path = processes[0].path else {
                inv.findings.append(deletedFinding(processes, nameOf: nameOf, inventory: &inv))
                continue
            }
            let status = CodeSigning.status(of: URL(fileURLWithPath: path))
            if Self.isSealedSystemPath(path), case .signed = status {
                systemProcesses += processes.count
                continue
            }
            inv.findings.append(finding(path: path, processes: processes, status: status, nameOf: nameOf))
            addProgram(path, to: &inv)
        }

        inv.notes.append("Running processes: \(all.count) running, \(inv.findings.count) program\(inv.findings.count == 1 ? "" : "s") listed. The \(systemProcesses) that are Apple system software on the sealed system volume are not listed. Nothing is stopped or changed; quit a program yourself (Activity Monitor) if you don't trust it.")
        if uninspected > 0 {
            inv.notes.append("\(uninspected) process\(uninspected == 1 ? "" : "es") couldn't be inspected: macOS didn't reveal the program file.")
        }
        return inv
    }

    private func addProgram(_ path: String, to inv: inout ProcessInventory) {
        inv.coveredUnits.insert(path)
        guard FileManager.default.fileExists(atPath: path) else { return }
        inv.programPaths.append(path)
        if let app = PersistenceScanner.enclosingApp(of: path) { inv.coveredUnits.insert(app.path) }
    }

    // MARK: - Analysis

    /// What is wrong with a running program, given its signature, owner and location.
    func problems(path: String, status: SigningStatus, runsAsRoot: Bool) -> [(Severity, String)] {
        var problems: [(Severity, String)] = []
        switch (status, runsAsRoot) {
        case (.unsigned, true), (.selfSigned, true):
            problems.append((.threat, "Running as root, but isn't signed by a trusted developer"))
        case (.selfSigned, false):
            problems.append((.threat, "Running program is self-signed (certificate not issued by Apple)"))
        case (.unsigned, false):
            problems.append((.warning, "Running program isn't code signed"))
        case (.adhoc, true) where !PersistenceScanner.isPackageManagerPath(path):
            problems.append((.warning, "Running as root with an ad-hoc signed program"))
        default:
            // Ad-hoc programs run by the user are common (locally built tools); noted in details only.
            break
        }

        // Location only counts against programs without an Apple-issued signature: macOS itself runs
        // signed apps from temporary folders (App Translocation, code-sign clones, iPhone app wrappers).
        if status.isUntrusted, let location = locationProblem(path) {
            problems.append((.warning, location))
        }
        return problems
    }

    func locationProblem(_ path: String) -> String? {
        if path.hasPrefix(home.appendingPathComponent("Downloads").path + "/") {
            return "Untrusted program running from the Downloads folder"
        }
        if Self.temporaryPrefixes.contains(where: { path.hasPrefix($0) }) {
            return "Untrusted program running from a temporary or shared folder"
        }
        if PersistenceScanner.isUnusualLocation(path) {
            return "Untrusted program running from a hidden folder"
        }
        return nil
    }

    func finding(path: String, processes: [LiveProcess], status: SigningStatus, nameOf: [Int32: String]) -> Finding {
        let runsAsRoot = processes.contains { $0.uid == 0 }
        var problems = problems(path: path, status: status, runsAsRoot: runsAsRoot)
        var notes = Self.processNotes(processes, nameOf: nameOf)
        notes.append("Signature: \(status.description)")
        if let team = status.teamID { notes.append("Team ID: \(team)") }
        if case .signed = status, let location = locationProblem(path) {
            notes.append("Location: " + location.replacingOccurrences(of: "Untrusted program running from ", with: "runs from ") + " (not flagged: it is signed with an Apple-issued certificate).")
        }
        if path.contains("/AppTranslocation/") {
            notes.append("macOS runs this app from a temporary read-only copy (App Translocation) because it was opened straight from where it was downloaded. Move it to Applications to stop that.")
        }
        if case .adhoc = status, PersistenceScanner.isPackageManagerPath(path) {
            notes.append("Homebrew/MacPorts build: package-manager builds are ad-hoc signed by design.")
        }
        if let impersonation = AppIntegrityEngine.impersonationProblem(bundleID: status.identifier, status: status) {
            problems.append((impersonation.0, impersonation.1))
            notes.append(impersonation.2)
        }
        return Self.makeFinding(path: path, problems: problems, notes: notes)
    }

    private func deletedFinding(_ processes: [LiveProcess], nameOf: [Int32: String], inventory inv: inout ProcessInventory) -> Finding {
        let first = processes[0]
        var notes = Self.processNotes(processes, nameOf: nameOf)
        guard let launchPath = first.launchPath else {
            notes.append("The file this process was started from no longer exists, and macOS doesn't reveal where it was. Malware sometimes deletes its own file after starting; an app updated while running looks the same.")
            return Self.makeFinding(path: first.name, problems: [(.warning, Self.deletedReason)], notes: notes)
        }
        notes.append("Started from: \(launchPath)")
        if FileManager.default.fileExists(atPath: launchPath) {
            // Replaced in place: almost always an app that was updated while it was running.
            let status = CodeSigning.status(of: URL(fileURLWithPath: launchPath))
            notes.append("Signature of the file there now: \(status.description)")
            addProgram(launchPath, to: &inv)
            if case .signed = status {
                notes.append("The program file was replaced after this process started, usually by an app update. The process still runs the old copy; quit and reopen the app to run the new one.")
                return Self.makeFinding(path: launchPath, problems: [], notes: notes, cleanReason: "Running an older copy (the app was updated while running)")
            }
            notes.append("The program file was replaced after this process started, and the file there now isn't signed by a trusted developer.")
            return Self.makeFinding(path: launchPath, problems: [(.warning, "Running program's file was replaced after it started")], notes: notes)
        }
        inv.coveredUnits.insert(launchPath)
        notes.append("The file this process was started from no longer exists. Malware sometimes deletes its own file after starting; an app removed or updated while running looks the same.")
        return Self.makeFinding(path: launchPath, problems: [(.warning, Self.deletedReason)], notes: notes)
    }

    static func processNotes(_ processes: [LiveProcess], nameOf: [Int32: String]) -> [String] {
        let pids = processes.prefix(8).map { String($0.pid) }.joined(separator: ", ")
        var notes = ["Running now: \(processes.count) process\(processes.count == 1 ? "" : "es") (PID \(pids)\(processes.count > 8 ? ", …" : ""))"]
        var users: [String] = []
        for uid in processes.map(\.uid) where !users.contains(userName(uid)) { users.append(userName(uid)) }
        notes.append("User: " + users.joined(separator: ", "))
        var parents: [String] = []
        for process in processes {
            let parent = nameOf[process.parentPID] ?? "process \(process.parentPID)"
            if !parents.contains(parent), parent != processes[0].name { parents.append(parent) }
        }
        if !parents.isEmpty { notes.append("Started by: " + parents.prefix(4).joined(separator: ", ")) }
        return notes
    }

    static func userName(_ uid: UInt32) -> String {
        guard let entry = getpwuid(uid), let name = entry.pointee.pw_name else { return "user \(uid)" }
        return String(cString: name)
    }

    static func makeFinding(path: String, problems: [(Severity, String)], notes: [String], cleanReason: String = ProcessScanner.cleanReason) -> Finding {
        let worst = problems.max { $0.0 < $1.0 }
        return Finding(
            path: path,
            severity: worst?.0 ?? .clean,
            engine: .processes,
            reason: worst.map { problems.count > 1 ? "\($0.1) (+\(problems.count - 1) more)" : $0.1 } ?? cleanReason,
            detail: (problems.count > 1 ? problems.map { "• \($0.1)" } + [""] : []).joined(separator: "\n") + notes.joined(separator: "\n"),
            unitPath: path
        )
    }
}
