import Foundation

public enum LeftoverCategory: String, Codable, CaseIterable, Sendable {
    case application
    case launchAgent
    case launchDaemon
    case privilegedHelper
    case appSupport
    case caches
    case preferences
    case containers
    case groupContainers
    case logs
    case savedState
    case webData
    case packageFiles
    case other

    public var title: String {
        switch self {
        case .application: "Application"
        case .launchAgent: "Launch Agents (start at login)"
        case .launchDaemon: "Launch Daemons (start at boot as root)"
        case .privilegedHelper: "Privileged Helpers"
        case .appSupport: "Application Support"
        case .caches: "Caches"
        case .preferences: "Preferences"
        case .containers: "Containers"
        case .groupContainers: "Group Containers"
        case .logs: "Logs"
        case .savedState: "Saved State"
        case .webData: "Cookies & Web Data"
        case .packageFiles: "Installed by Package"
        case .other: "Other"
        }
    }
}

/// How a launchd job must be stopped before its plist is removed.
public enum LaunchDomain: String, Codable, Sendable {
    /// ~/Library/LaunchAgents or /Library/LaunchAgents → the user's GUI domain.
    case gui
    /// /Library/LaunchDaemons → the system domain (needs admin).
    case system
}

public struct Leftover: Identifiable, Hashable, Sendable {
    public var id: String { url.path }
    public let url: URL
    public let category: LeftoverCategory
    /// Why MacScan thinks it belongs to the app.
    public let matchedBy: String
    /// Matched only by the app's name (lower confidence than a bundle-ID match).
    public let matchedByNameOnly: Bool
    /// Moving it needs an administrator password.
    public let requiresAdmin: Bool
    public var size: Int64
    public let launchLabel: String?
    public let launchDomain: LaunchDomain?
    /// Preselected in the checklist. False for lower-confidence matches (e.g. shared with the developer's other apps).
    public var selectedByDefault: Bool = true

    public var path: String { url.path }
}

/// A launchd job to stop (and unregister) during uninstall.
public struct LaunchJob: Hashable, Sendable {
    public let label: String
    public let domain: LaunchDomain
}

public struct RunningProcess: Hashable, Sendable {
    public let pid: Int32
    public let path: String
    public let isOwnedByUser: Bool
}

public struct UninstallPlan: Sendable {
    public let app: InstalledApp
    public var leftovers: [Leftover]
    public var processes: [RunningProcess]
    /// pkgutil receipt IDs that belong to the app (forgotten after removal).
    public var packageReceipts: [String]
    public var notes: [String]
    /// Background jobs registered by the app (incl. helpers embedded in the bundle via SMAppService).
    public var launchJobs: [LaunchJob] = []

    public var totalSize: Int64 { leftovers.reduce(0) { $0 + $1.size } }
}

public struct UninstallLocations: Sendable {
    public let home: URL
    public let root: URL
    /// Query pkgutil receipts and running processes (only meaningful on the real system).
    public let isRealSystem: Bool

    public init(home: URL, root: URL, isRealSystem: Bool) {
        self.home = home
        self.root = root
        self.isRealSystem = isRealSystem
    }

    public static var system: UninstallLocations {
        UninstallLocations(home: AppPaths.home, root: URL(fileURLWithPath: "/"), isRealSystem: true)
    }
}

/// Finds everything that belongs to an app: launch items, helpers, support files, caches, preferences,
/// containers, logs, saved state, web data and package-installed files. Read-only.
public struct LeftoverFinder: Sendable {
    public let locations: UninstallLocations
    /// Background Task Management records; nil means read them from the system (real system only).
    let backgroundItems: [BTMRecord]?

    public init(locations: UninstallLocations = .system, backgroundItems: [BTMRecord]? = nil) {
        self.locations = locations
        self.backgroundItems = backgroundItems
    }

    /// Names too generic to match by app name alone (vendor folders shared by several apps).
    static let genericNames: Set<String> = [
        "apple", "google", "microsoft", "adobe", "mozilla", "oracle", "java", "python", "jetbrains",
        "app", "apps", "application", "helper", "update", "updater", "data", "temp", "cache", "caches",
        "logs", "settings", "preferences", "support", "shared", "default", "library", "utilities", "tools",
    ]

    static let userDirectories: [(String, LeftoverCategory)] = [
        ("Library/Application Support", .appSupport),
        ("Library/Caches", .caches),
        ("Library/Preferences", .preferences),
        ("Library/Preferences/ByHost", .preferences),
        ("Library/Containers", .containers),
        ("Library/Group Containers", .groupContainers),
        ("Library/Logs", .logs),
        ("Library/Saved Application State", .savedState),
        ("Library/HTTPStorages", .webData),
        ("Library/WebKit", .webData),
        ("Library/Cookies", .webData),
        ("Library/Application Scripts", .other),
        ("Library/Application Support/CrashReporter", .logs),
        ("Library/Logs/DiagnosticReports", .logs),
    ]

    static let systemDirectories: [(String, LeftoverCategory)] = [
        ("Library/Application Support", .appSupport),
        ("Library/Caches", .caches),
        ("Library/Preferences", .preferences),
        ("Library/Logs", .logs),
        ("Library/PrivilegedHelperTools", .privilegedHelper),
        ("Library/Logs/DiagnosticReports", .logs),
    ]

    /// Never offered for removal (shared system locations).
    static let protectedPrefixes = ["/System/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/usr/share/", "/private/etc/", "/etc/"]

    // MARK: - Find

    public func find(_ app: InstalledApp) throws -> UninstallPlan {
        let ids = app.allBundleIDs.map { $0.lowercased() }
        let names = app.names.map { $0.lowercased() }.filter { $0.count >= 4 && !Self.genericNames.contains($0) }
        var leftovers: [Leftover] = []
        var launchPrograms: [String] = []
        var launchJobs: [LaunchJob] = []
        var notes: [String] = []

        // The app itself.
        leftovers.append(makeLeftover(app.url, .application, matchedBy: "The application bundle", byName: false, label: nil, domain: nil))

        // Launch agents / daemons: match by file name, label, or by what they launch.
        let launchDirs: [(URL, LeftoverCategory, LaunchDomain)] = [
            (locations.home.appendingPathComponent("Library/LaunchAgents"), .launchAgent, .gui),
            (locations.root.appendingPathComponent("Library/LaunchAgents"), .launchAgent, .gui),
            (locations.root.appendingPathComponent("Library/LaunchDaemons"), .launchDaemon, .system),
        ]
        var unmatchedLaunchItems: [(url: URL, category: LeftoverCategory, domain: LaunchDomain, label: String?, paths: [String])] = []
        for (dir, category, domain) in launchDirs {
            for name in (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? [] where name.hasSuffix(".plist") {
                try Task.checkCancellation()
                let url = dir.appendingPathComponent(name)
                let plist = (try? Data(contentsOf: url)).flatMap {
                    (try? PropertyListSerialization.propertyList(from: $0, format: nil)) as? [String: Any]
                } ?? [:]
                let label = plist["Label"] as? String
                let args = plist["ProgramArguments"] as? [String] ?? []
                let program = (plist["Program"] as? String) ?? args.first
                let associated = (plist["AssociatedBundleIdentifiers"] as? [String]) ?? (plist["AssociatedBundleIdentifiers"] as? String).map { [$0] } ?? []

                var reason: String?
                if let program, program.hasPrefix(app.url.path + "/") {
                    reason = "Starts a program inside the app"
                } else if associated.contains(where: { ids.contains($0.lowercased()) }) {
                    reason = "Declares the app as its owner"
                } else if Self.matchesIdentifier(name, ids: ids) || label.map({ Self.matchesIdentifier($0, ids: ids) }) == true {
                    reason = "Bundle ID match (\(label ?? name))"
                }
                guard let reason else {
                    unmatchedLaunchItems.append((url, category, domain, label, ([program].compactMap { $0 } + args).filter { $0.hasPrefix("/") }))
                    continue
                }
                leftovers.append(makeLeftover(url, category, matchedBy: reason, byName: false, label: label, domain: domain))
                if let label { launchJobs.append(LaunchJob(label: label, domain: domain)) }
                if let program, !program.hasPrefix(app.url.path + "/") { launchPrograms.append(program) }
            }
        }

        // macOS's background-items database: everything the app registered to run in the background,
        // including helpers embedded in the bundle (SMAppService) and differently named legacy agents.
        let records = backgroundItems ?? (locations.isRealSystem ? BackgroundItems.load() : [])
        let (owned, sameDeveloper) = BackgroundItems.items(for: app, in: records)
        for r in owned {
            if let domain = r.launchDomain, let label = r.label {
                launchJobs.append(LaunchJob(label: label, domain: domain))
            }
            if !r.isEmbedded, let path = r.url, FileManager.default.fileExists(atPath: path),
               !path.hasPrefix(app.url.path + "/"), !isProtectedPath(path) {
                let category: LeftoverCategory = r.launchDomain == .system ? .launchDaemon : (r.launchDomain == .gui ? .launchAgent : .other)
                leftovers.append(makeLeftover(URL(fileURLWithPath: path), category,
                                              matchedBy: "Registered by the app as a background item (\(r.name))",
                                              byName: false, label: r.label, domain: r.launchDomain))
            }
            if let exe = r.executablePath, exe.hasPrefix("/"), !exe.hasPrefix(app.url.path + "/") {
                launchPrograms.append(exe)
            }
        }
        for r in sameDeveloper {
            guard let path = r.url, !r.isEmbedded, FileManager.default.fileExists(atPath: path), !isProtectedPath(path) else { continue }
            var item = makeLeftover(URL(fileURLWithPath: path), r.launchDomain == .system ? .launchDaemon : .launchAgent,
                                    matchedBy: "Same developer (\(r.developerName ?? r.teamID ?? "?")) — may be shared with their other apps",
                                    byName: true, label: r.label, domain: r.launchDomain)
            item.selectedByDefault = false
            leftovers.append(item)
        }

        // Programs launched by those items that live outside the app (e.g. privileged helpers).
        for program in launchPrograms where FileManager.default.fileExists(atPath: program) && !isProtectedPath(program) {
            let category: LeftoverCategory = program.contains("/PrivilegedHelperTools/") ? .privilegedHelper : .other
            leftovers.append(makeLeftover(URL(fileURLWithPath: program), category, matchedBy: "Started by one of the app's launch items", byName: false, label: nil, domain: nil))
        }

        // Support folders.
        let scopes: [(URL, [(String, LeftoverCategory)])] = [
            (locations.home, Self.userDirectories),
            (locations.root, Self.systemDirectories),
        ]
        for (base, dirs) in scopes {
            for (relative, category) in dirs {
                let dir = base.appendingPathComponent(relative)
                for name in (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? [] where !name.hasPrefix(".") {
                    try Task.checkCancellation()
                    let url = dir.appendingPathComponent(name)
                    // Sub-directories that are themselves scanned as a location are not leftovers.
                    if dirs.contains(where: { base.appendingPathComponent($0.0).path == url.path }) { continue }
                    if Self.matchesIdentifier(name, ids: ids, teamID: app.teamID) {
                        leftovers.append(makeLeftover(url, category, matchedBy: "Bundle ID match", byName: false, label: nil, domain: nil))
                    } else if names.contains(Self.stripExtensions(name).lowercased()) {
                        leftovers.append(makeLeftover(url, category, matchedBy: "Same name as the app", byName: true, label: nil, domain: nil))
                    }
                }
            }
        }

        // Launch items that run a program from a folder that's being removed (e.g. ~/Library/Application Support/<App>/…).
        let removedFolders = leftovers.filter { $0.category != .application }.map(\.path)
        for item in unmatchedLaunchItems {
            guard let inside = item.paths.first(where: { p in removedFolders.contains { p.hasPrefix($0 + "/") } }) else { continue }
            leftovers.append(makeLeftover(item.url, item.category, matchedBy: "Starts \((inside as NSString).lastPathComponent) from the app's support files",
                                          byName: false, label: item.label, domain: item.domain))
            if let label = item.label { launchJobs.append(LaunchJob(label: label, domain: item.domain)) }
        }

        // Files installed by the app's .pkg installer.
        var receipts: [String] = []
        if locations.isRealSystem {
            receipts = Self.packageReceipts(matching: ids)
            for pkg in receipts {
                for path in Self.packageFiles(pkg) where !isProtectedPath(path) && !path.hasPrefix(app.url.path + "/") && path != app.url.path {
                    leftovers.append(makeLeftover(URL(fileURLWithPath: path), .packageFiles, matchedBy: "Installed by package \(pkg)", byName: false, label: nil, domain: nil))
                }
            }
        }

        // Running processes.
        var processes: [RunningProcess] = []
        if locations.isRealSystem {
            let programs = Set(launchPrograms.map { Paths.canonical(URL(fileURLWithPath: $0)).path } + launchPrograms)
            processes = Self.runningProcesses().filter { $0.path.hasPrefix(app.url.path + "/") || programs.contains($0.path) }
        }

        notes.append("Login items you added in System Settings › General › Login Items are removed by macOS once the app is gone; check that list afterwards.")
        if app.bundleID == nil { notes.append("The app has no bundle identifier, so only name-based matches were possible.") }

        leftovers = Self.deduplicate(leftovers)
        for i in leftovers.indices { leftovers[i].size = Self.allocatedSize(of: leftovers[i].url) }
        var seenJobs = Set<LaunchJob>()
        var plan = UninstallPlan(app: app, leftovers: leftovers, processes: processes, packageReceipts: receipts, notes: notes)
        plan.launchJobs = launchJobs.filter { seenJobs.insert($0).inserted }
        if app.url.path.hasPrefix(AppPaths.home.path + "/.Trash/") {
            plan.notes.insert("This app is already in the Trash, so its items are deleted permanently instead of being moved to the Trash.", at: 0)
        }
        return plan
    }

    // MARK: - Matching

    static func stripExtensions(_ name: String) -> String {
        var n = name
        for ext in [".plist", ".savedState", ".binarycookies", ".lockfile", ".log", ".crash", ".ips", ".diag"] where n.lowercased().hasSuffix(ext.lowercased()) {
            n = String(n.dropLast(ext.count))
        }
        return n
    }

    /// True if a file/folder name refers to one of the app's bundle IDs, e.g. `com.x.App`, `com.x.App.plist`,
    /// `com.x.App.helper`, `TEAMID.com.x.App`, `group.com.x.App`, `com.x.App.<UUID>.plist` (ByHost).
    static func matchesIdentifier(_ name: String, ids: [String], teamID: String? = nil) -> Bool {
        var n = stripExtensions(name).lowercased()
        if n.hasPrefix("group.") { n.removeFirst("group.".count) }
        if let teamID, n.hasPrefix(teamID.lowercased() + ".") {
            n.removeFirst(teamID.count + 1)
        } else if let dot = n.firstIndex(of: "."),
                  n.distance(from: n.startIndex, to: dot) == 10,
                  n[..<dot].allSatisfy({ $0.isLetter || $0.isNumber }),
                  n[..<dot].contains(where: \.isNumber) {
            // Unknown team-ID prefix (10 alphanumerics with a digit).
            n = String(n[n.index(after: dot)...])
        }
        // Diagnostic reports are named "<Process>_<date>…"; handled by name matching instead.
        return ids.contains { id in n == id || n.hasPrefix(id + ".") || n.hasPrefix(id + "_") || n.hasPrefix(id + "-") }
    }

    func isProtectedPath(_ path: String) -> Bool {
        Self.protectedPrefixes.contains { path.hasPrefix($0) }
    }

    /// Removes entries nested inside another entry.
    static func deduplicate(_ items: [Leftover]) -> [Leftover] {
        var seen = Set<String>()
        let unique = items.filter { seen.insert($0.path).inserted }
        return unique.filter { item in
            !unique.contains { other in other.path != item.path && item.path.hasPrefix(other.path + "/") }
        }
    }

    func makeLeftover(_ url: URL, _ category: LeftoverCategory, matchedBy: String, byName: Bool, label: String?, domain: LaunchDomain?) -> Leftover {
        Leftover(
            url: url, category: category, matchedBy: matchedBy, matchedByNameOnly: byName,
            requiresAdmin: Self.requiresAdmin(url), size: 0, launchLabel: label, launchDomain: domain
        )
    }

    /// Moving an item needs write access to its parent, and for directories to the directory itself.
    static func requiresAdmin(_ url: URL) -> Bool {
        let parent = url.deletingLastPathComponent().path
        if access(parent, W_OK) != 0 { return true }
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue, access(url.path, W_OK) != 0 {
            return true
        }
        return false
    }

    static func allocatedSize(of url: URL) -> Int64 {
        let keys: Set<URLResourceKey> = [.totalFileAllocatedSizeKey, .fileAllocatedSizeKey, .isDirectoryKey]
        guard let values = try? url.resourceValues(forKeys: keys) else { return 0 }
        if values.isDirectory != true {
            return Int64(values.totalFileAllocatedSize ?? values.fileAllocatedSize ?? 0)
        }
        var total: Int64 = 0
        if let e = FileManager.default.enumerator(at: url, includingPropertiesForKeys: Array(keys), options: [], errorHandler: { _, _ in true }) {
            for case let child as URL in e {
                let v = try? child.resourceValues(forKeys: keys)
                total += Int64(v?.totalFileAllocatedSize ?? v?.fileAllocatedSize ?? 0)
            }
        }
        return total
    }

    // MARK: - System queries

    static func run(_ path: String, _ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return p.terminationStatus == 0 ? String(decoding: data, as: UTF8.self) : nil
    }

    static func packageReceipts(matching ids: [String]) -> [String] {
        guard let output = run("/usr/sbin/pkgutil", ["--pkgs"]) else { return [] }
        return output.split(separator: "\n").map(String.init).filter { pkg in
            let p = pkg.lowercased()
            return ids.contains { p == $0 || p.hasPrefix($0 + ".") }
        }
    }

    /// Top-level items a package installed (bundles as a whole, plain files), excluding directories it merely used.
    static func packageFiles(_ pkg: String) -> [String] {
        guard let info = run("/usr/sbin/pkgutil", ["--pkg-info", pkg]),
              let files = run("/usr/sbin/pkgutil", ["--files", pkg, "--only-files"]) else { return [] }
        var volume = "/"
        var location = ""
        for line in info.split(separator: "\n") {
            if line.hasPrefix("volume: ") { volume = String(line.dropFirst(8)) }
            if line.hasPrefix("location: ") { location = String(line.dropFirst(10)) }
        }
        let base = URL(fileURLWithPath: volume).appendingPathComponent(location)
        let bundleExtensions: Set<String> = ["app", "plugin", "kext", "bundle", "framework", "appex", "qlgenerator", "mdimporter", "prefPane", "systemextension", "xpc"]
        var result: [String] = []
        var seen = Set<String>()
        for rel in files.split(separator: "\n") {
            let full = base.appendingPathComponent(String(rel)).standardizedFileURL
            // Collapse to the outermost bundle, if the file is inside one.
            var path = full.path
            var current = URL(fileURLWithPath: "/")
            for component in full.pathComponents.dropFirst() {
                current.appendPathComponent(component)
                if bundleExtensions.contains((component as NSString).pathExtension.lowercased()) {
                    path = current.path
                    break
                }
            }
            guard FileManager.default.fileExists(atPath: path), seen.insert(path).inserted else { continue }
            result.append(path)
        }
        return result
    }

    static func runningProcesses() -> [RunningProcess] {
        guard let output = run("/bin/ps", ["-axww", "-o", "pid=,uid=,comm="]) else { return [] }
        let uid = getuid()
        return output.split(separator: "\n").compactMap { line in
            let parts = line.trimmingCharacters(in: .whitespaces).split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard parts.count == 3, let pid = Int32(parts[0]), let owner = UInt32(parts[1]) else { return nil }
            // `comm` is sometimes just argv[0]; ask the kernel for the real executable path.
            return RunningProcess(pid: pid, path: executablePath(of: pid) ?? String(parts[2]), isOwnedByUser: owner == uid)
        }
    }

    static func executablePath(of pid: Int32) -> String? {
        var buffer = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(decoding: buffer.prefix(Int(length)), as: UTF8.self)
    }
}
