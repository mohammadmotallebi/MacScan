import Foundation

/// How a piece of software makes itself start automatically.
public enum PersistenceKind: String, Codable, Sendable {
    case userLaunchAgent
    case launchAgent
    case launchDaemon
    case privilegedHelper
    case shellStartup
    case cronJob
    case plugin

    public var runsAsRoot: Bool {
        self == .launchDaemon || self == .privilegedHelper
    }

    public var headline: String {
        switch self {
        case .userLaunchAgent: "Starts when you log in (LaunchAgent)"
        case .launchAgent: "Starts when any user logs in (LaunchAgent)"
        case .launchDaemon: "Runs as root at startup (LaunchDaemon)"
        case .privilegedHelper: "Privileged helper tool (runs as root)"
        case .shellStartup: "Runs in every new Terminal shell"
        case .cronJob: "Scheduled job (cron)"
        case .plugin: "Loaded automatically by macOS"
        }
    }
}

public struct PersistenceEntry: Codable, Hashable, Sendable {
    public var kind: PersistenceKind
    /// The plist / file / bundle that creates the persistence.
    public var source: String
    public var label: String?
    public var program: String?
    public var arguments: [String]
    public var runAtLoad: Bool
    public var keepAlive: Bool
    public var disabled: Bool
    /// SMAppService-style program path relative to the owning app.
    public var bundleProgram: String?

    public init(kind: PersistenceKind, source: String, label: String? = nil, program: String? = nil,
                arguments: [String] = [], runAtLoad: Bool = false, keepAlive: Bool = false, disabled: Bool = false,
                bundleProgram: String? = nil) {
        self.bundleProgram = bundleProgram
        self.kind = kind
        self.source = source
        self.label = label
        self.program = program
        self.arguments = arguments
        self.runAtLoad = runAtLoad
        self.keepAlive = keepAlive
        self.disabled = disabled
    }
}

/// Where to look. `.system` is the real Mac; tests point `root`/`home` at temporary folders.
public struct PersistenceLocations: Sendable {
    public let home: URL
    public let root: URL
    public let includeCrontab: Bool

    public init(home: URL, root: URL, includeCrontab: Bool) {
        self.home = home
        self.root = root
        self.includeCrontab = includeCrontab
    }

    public static var system: PersistenceLocations {
        PersistenceLocations(home: AppPaths.home, root: URL(fileURLWithPath: "/"), includeCrontab: true)
    }

    func system(_ relative: String) -> URL { root.appendingPathComponent(relative, isDirectory: true) }
    func user(_ relative: String) -> URL { home.appendingPathComponent(relative, isDirectory: true) }
}

public struct PersistenceInventory: Sendable {
    public var entries: [PersistenceEntry] = []
    /// One finding per startup item (engine `.persistence`), any severity.
    public var findings: [Finding] = []
    /// Files/folders (plists, shell files, plug-in bundles) to run through the scan engines.
    public var scanPaths: [String] = []
    /// Programs started by those items; scanned individually (plus their enclosing app's integrity).
    public var programPaths: [String] = []
    /// Paths already described by a persistence finding (no extra "No issues found" rows needed).
    public var coveredUnits: Set<String> = []
}

/// Lists everything set to start automatically (similar in spirit to Objective-See's KnockKnock) and
/// flags risky patterns: root items with untrusted code, missing programs, hidden locations, download/
/// decode commands, publisher impersonation. Read-only: nothing is disabled or removed.
public struct PersistenceScanner: Sendable {
    public let locations: PersistenceLocations

    public init(locations: PersistenceLocations = .system) {
        self.locations = locations
    }

    static let shellFiles = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".bash_profile", ".bashrc", ".profile"]
    static let interpreters: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "python", "python3", "perl", "ruby", "osascript", "node", "env"]
    /// Hidden folders that are common, legitimate tool homes.
    static let benignHiddenFolders: Set<String> = [".local", ".cargo", ".nvm", ".orbstack", ".docker", ".volta", ".bun", ".deno", ".rbenv", ".pyenv", ".sdkman"]
    /// Package managers build locally and ad-hoc sign by design.
    public static let packageManagerPrefixes = ["/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/", "/opt/local/"]
    static let packageManagerLabels = ["homebrew.mxcl.", "org.macports."]

    /// Reason used for launch items whose program no longer exists (these can be removed from the results).
    public static let missingProgramReason = "Startup item points to a missing program"

    public static func isPackageManagerPath(_ path: String) -> Bool {
        packageManagerPrefixes.contains { path.hasPrefix($0) }
    }

    static let unusualPrefixes = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/", "/private/var/folders/", "/var/folders/"]

    /// Commands typical of droppers / backdoors.
    static let suspiciousPatterns: [(regex: NSRegularExpression, label: String)] = [
        (#"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(/bin/)?(ba|z)?sh"#, "downloads and runs a script"),
        (#"base64\s+(-d|-D|--decode)"#, "decodes a base64 payload"),
        (#"/dev/tcp/"#, "opens a raw network connection"),
        (#"\bnc\b[^\n]*\s-e\s"#, "netcat with command execution"),
        (#"osascript\s+-e"#, "runs inline AppleScript"),
        (#"python3?\s+-c\s+[^\n]*(base64|exec|socket)"#, "runs inline Python code"),
        (#"xattr\s+-(d|c|cr|rc)\b[^\n]*quarantine|xattr\s+-c"#, "removes the quarantine attribute"),
    ].compactMap { pattern, label in
        (try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])).map { ($0, label) }
    }

    static func suspiciousReasons(in text: String) -> [String] {
        let range = NSRange(text.startIndex..., in: text)
        return suspiciousPatterns.filter { $0.regex.firstMatch(in: text, range: range) != nil }.map(\.label)
    }

    // MARK: - Collect

    public func collect() throws -> PersistenceInventory {
        var inv = PersistenceInventory()
        var referenced = Set<String>()
        let fm = FileManager.default

        // LaunchAgents / LaunchDaemons
        let launchDirs: [(URL, PersistenceKind)] = [
            (locations.user("Library/LaunchAgents"), .userLaunchAgent),
            (locations.system("Library/LaunchAgents"), .launchAgent),
            (locations.system("Library/LaunchDaemons"), .launchDaemon),
        ]
        for (dir, kind) in launchDirs {
            for name in (try? fm.contentsOfDirectory(atPath: dir.path))?.sorted() ?? [] where name.hasSuffix(".plist") {
                try Task.checkCancellation()
                let plistURL = dir.appendingPathComponent(name)
                inv.scanPaths.append(plistURL.path)
                inv.coveredUnits.insert(plistURL.path)
                guard let data = try? Data(contentsOf: plistURL),
                      let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
                else {
                    inv.findings.append(Finding(
                        path: plistURL.path, severity: .warning, engine: .persistence,
                        reason: "Startup item can't be read",
                        detail: "\(kind.headline)\nThe property list is unreadable or malformed, so MacScan can't tell what it starts.",
                        unitPath: plistURL.path))
                    continue
                }
                let args = plist["ProgramArguments"] as? [String] ?? []
                let program = (plist["Program"] as? String) ?? args.first
                let entry = PersistenceEntry(
                    kind: kind,
                    source: plistURL.path,
                    label: plist["Label"] as? String,
                    program: program,
                    arguments: args,
                    runAtLoad: plist["RunAtLoad"] as? Bool ?? false,
                    keepAlive: (plist["KeepAlive"] as? Bool) ?? (plist["KeepAlive"] is [String: Any]),
                    disabled: plist["Disabled"] as? Bool ?? false,
                    bundleProgram: plist["BundleProgram"] as? String
                )
                inv.entries.append(entry)
                inv.findings.append(analyze(entry))
                if let program {
                    referenced.insert(program)
                    addProgram(program, to: &inv)
                }
                // Script files passed as arguments (e.g. /bin/bash /path/to/script.sh).
                for arg in args.dropFirst() where arg.hasPrefix("/") && isRegularFile(arg) {
                    addProgram(arg, to: &inv)
                }
            }
        }

        // Privileged helper tools not started by any LaunchDaemon plist we saw.
        let helpers = locations.system("Library/PrivilegedHelperTools")
        for name in (try? fm.contentsOfDirectory(atPath: helpers.path))?.sorted() ?? [] where !name.hasPrefix(".") {
            let path = helpers.appendingPathComponent(name).path
            addProgram(path, to: &inv)
            guard !referenced.contains(path) else { continue }
            let entry = PersistenceEntry(kind: .privilegedHelper, source: path, label: name, program: path)
            inv.entries.append(entry)
            inv.findings.append(analyze(entry, note: "Not started by any LaunchDaemon plist, often left behind by an uninstalled app."))
        }

        // Shell startup files.
        for name in Self.shellFiles {
            let url = locations.home.appendingPathComponent(name)
            guard isRegularFile(url.path) else { continue }
            inv.scanPaths.append(url.path)
            inv.coveredUnits.insert(url.path)
            let entry = PersistenceEntry(kind: .shellStartup, source: url.path, label: name)
            inv.entries.append(entry)
            inv.findings.append(analyzeShellFile(url))
        }

        // Plug-ins that macOS loads automatically.
        let pluginDirs: [(URL, String, Set<String>)] = [
            (locations.system("Library/QuickLook"), "Quick Look plug-in", ["qlgenerator"]),
            (locations.user("Library/QuickLook"), "Quick Look plug-in", ["qlgenerator"]),
            (locations.system("Library/Spotlight"), "Spotlight importer", ["mdimporter"]),
            (locations.user("Library/Spotlight"), "Spotlight importer", ["mdimporter"]),
            (locations.system("Library/ScriptingAdditions"), "Scripting addition", ["osax"]),
            (locations.system("Library/Security/SecurityAgentPlugins"), "Authorization plug-in", ["bundle"]),
            (locations.system("Library/InputManagers"), "Input manager", []),
            (locations.user("Library/InputManagers"), "Input manager", []),
            (locations.system("Library/Extensions"), "Kernel extension", ["kext"]),
        ]
        for (dir, type, extensions) in pluginDirs {
            for name in (try? fm.contentsOfDirectory(atPath: dir.path))?.sorted() ?? [] where !name.hasPrefix(".") {
                // Only real plug-in bundles (input managers accept any bundle, they're legacy anyway).
                if !extensions.isEmpty, !extensions.contains((name as NSString).pathExtension.lowercased()) { continue }
                let url = dir.appendingPathComponent(name)
                inv.scanPaths.append(url.path)
                inv.coveredUnits.insert(url.path)
                let entry = PersistenceEntry(kind: .plugin, source: url.path, label: type)
                inv.entries.append(entry)
                inv.findings.append(analyzePlugin(url, type: type))
            }
        }

        // The user's crontab.
        if locations.includeCrontab, let crontab = Self.readUserCrontab() {
            let source = "/usr/lib/cron/tabs/\(AppPaths.userName)"
            let jobs = crontab.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            for job in jobs {
                let entry = PersistenceEntry(kind: .cronJob, source: source, label: job)
                inv.entries.append(entry)
                let reasons = Self.suspiciousReasons(in: job)
                inv.findings.append(Finding(
                    path: source,
                    severity: reasons.isEmpty ? .clean : .warning,
                    engine: .persistence,
                    reason: reasons.isEmpty ? PersistenceKind.cronJob.headline : "Scheduled job " + reasons.joined(separator: ", "),
                    detail: "\(PersistenceKind.cronJob.headline)\nJob: \(job)\nEdit with `crontab -e` in Terminal.",
                    unitPath: source + "#" + job))
            }
        }

        return inv
    }

    private func addProgram(_ path: String, to inv: inout PersistenceInventory) {
        guard FileManager.default.fileExists(atPath: path), !inv.programPaths.contains(path) else { return }
        inv.programPaths.append(path)
        inv.coveredUnits.insert(path)
        if let app = Self.enclosingApp(of: path) { inv.coveredUnits.insert(app.path) }
    }

    public static func enclosingApp(of path: String) -> URL? {
        var url = URL(fileURLWithPath: "/")
        for component in URL(fileURLWithPath: path).pathComponents.dropFirst() {
            url.appendPathComponent(component)
            if component.lowercased().hasSuffix(".app") { return url }
        }
        return nil
    }

    private func isRegularFile(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && !isDir.boolValue
    }

    static func readUserCrontab() -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/crontab")
        // As root (elevated scan), read the scanning user's crontab, not root's.
        p.arguments = getuid() == 0 && AppPaths.userName != "root" ? ["-l", "-u", AppPaths.userName] : ["-l"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: - Analysis

    static func isUnusualLocation(_ path: String) -> Bool {
        if unusualPrefixes.contains(where: { path.hasPrefix($0) }) { return true }
        return URL(fileURLWithPath: path).pathComponents.contains { $0.hasPrefix(".") && $0 != "." && $0 != ".." && !benignHiddenFolders.contains($0) }
    }

    func analyze(_ entry: PersistenceEntry, note: String? = nil) -> Finding {
        var problems: [(Severity, String)] = []
        var notes = [entry.kind.headline]
        if let note { notes.append(note) }
        if let label = entry.label { notes.append("Label: \(label)") }
        if let program = entry.program { notes.append("Program: \(program)") }
        if entry.arguments.count > 1 {
            let joined = entry.arguments.dropFirst().joined(separator: " ")
            notes.append("Arguments: " + (joined.count > 400 ? String(joined.prefix(400)) + "…" : joined))
        }
        var flags: [String] = []
        if entry.runAtLoad { flags.append("runs at load") }
        if entry.keepAlive { flags.append("restarted if it quits") }
        if entry.disabled { flags.append("disabled in its plist") }
        if !flags.isEmpty { notes.append("Behaviour: " + flags.joined(separator: ", ")) }

        if let program = entry.program {
            if !FileManager.default.fileExists(atPath: program) {
                problems.append((.warning, Self.missingProgramReason))
                notes.append("The program no longer exists — usually left over from an uninstalled app.")
            } else {
                if Self.isUnusualLocation(program) {
                    problems.append((.warning, "Startup program is in a temporary, shared or hidden location"))
                }
                let name = (program as NSString).lastPathComponent
                if Self.interpreters.contains(name) {
                    let command = entry.arguments.dropFirst().joined(separator: " ")
                    let reasons = Self.suspiciousReasons(in: command)
                    if !reasons.isEmpty {
                        problems.append((.warning, "Startup item " + reasons.joined(separator: ", ")))
                    }
                } else {
                    switch MachO.inspect(path: program) {
                    case .executableCode:
                        let status = CodeSigning.status(of: URL(fileURLWithPath: program))
                        notes.append("Signature: \(status.description)")
                        if let team = status.teamID { notes.append("Team ID: \(team)") }
                        let packaged = Self.isPackageManagerPath(program)
                            && Self.packageManagerLabels.contains { (entry.label ?? "").hasPrefix($0) }
                        if packaged, case .adhoc = status {
                            notes.append("Homebrew/MacPorts service: package-manager builds are ad-hoc signed by design.")
                        } else {
                            problems += Self.signingProblems(status: status, kind: entry.kind)
                        }
                        if let label = entry.label,
                           let impersonation = AppIntegrityEngine.impersonationProblem(bundleID: label, status: status) {
                            problems.append((impersonation.0, impersonation.1))
                            notes.append(impersonation.2)
                        }
                    case .notMachO:
                        notes.append("Program is a script (scripts can't carry a code signature); its contents are checked by YARA.")
                    default:
                        break
                    }
                }
            }
        } else if entry.kind != .plugin && entry.kind != .shellStartup {
            if let bundleProgram = entry.bundleProgram {
                notes.append("Program inside its app bundle: \(bundleProgram) (registered with SMAppService)")
            } else {
                notes.append("This item names no program, so launchd has nothing to start. Apps sometimes leave such placeholders behind when they retire a helper.")
                return Finding(path: entry.source, severity: .clean, engine: .persistence,
                               reason: "Inactive startup item (starts nothing)", detail: notes.joined(separator: "\n"), unitPath: entry.source)
            }
        }

        let worst = problems.max { $0.0 < $1.0 }
        return Finding(
            path: entry.source,
            severity: worst?.0 ?? .clean,
            engine: .persistence,
            reason: worst.map { problems.count > 1 ? "\($0.1) (+\(problems.count - 1) more)" : $0.1 } ?? entry.kind.headline,
            detail: (problems.count > 1 ? problems.map { "• \($0.1)" } + [""] : []).joined(separator: "\n") + notes.joined(separator: "\n"),
            unitPath: entry.source
        )
    }

    static func signingProblems(status: SigningStatus, kind: PersistenceKind) -> [(Severity, String)] {
        switch (status, kind.runsAsRoot) {
        case (.unsigned, true), (.selfSigned, true):
            return [(.threat, "Runs as root, but its program isn't signed by a trusted developer")]
        case (.adhoc, true):
            return [(.warning, "Runs as root with an ad-hoc signed program")]
        case (.unsigned, false), (.selfSigned, false):
            return [(.warning, "Starts automatically with a program not signed by a trusted developer")]
        default:
            // Ad-hoc user agents are common for Homebrew services; noted in details only.
            return []
        }
    }

    func analyzeShellFile(_ url: URL) -> Finding {
        let headline = PersistenceKind.shellStartup.headline
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            return Finding(path: url.path, severity: .clean, engine: .persistence, reason: headline, detail: "\(headline)\nCould not read the file.", unitPath: url.path)
        }
        var hits: [String] = []
        var reasons = Set<String>()
        for line in text.prefix(512 * 1024).split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("#") else { continue }
            let found = Self.suspiciousReasons(in: trimmed)
            if !found.isEmpty {
                reasons.formUnion(found)
                if hits.count < 5 { hits.append(trimmed.count > 200 ? String(trimmed.prefix(200)) + "…" : trimmed) }
            }
        }
        if reasons.isEmpty {
            return Finding(path: url.path, severity: .clean, engine: .persistence, reason: headline, detail: headline, unitPath: url.path)
        }
        return Finding(
            path: url.path, severity: .warning, engine: .persistence,
            reason: "Shell startup file " + reasons.sorted().joined(separator: ", "),
            detail: "\(headline)\nSuspicious lines:\n" + hits.map { "  \($0)" }.joined(separator: "\n"),
            unitPath: url.path)
    }

    func analyzePlugin(_ url: URL, type: String) -> Finding {
        var notes = ["Loaded automatically by macOS: \(type)"]
        var severity = Severity.clean
        var reason = "Loaded automatically by macOS (\(type))"
        if type == "Input manager" {
            severity = .warning
            reason = "Legacy input manager (code injected into apps)"
            notes.append("Input managers are an obsolete mechanism that injects code into applications. Modern software doesn't use them.")
        }
        let status = CodeSigning.status(of: url)
        notes.append("Signature: \(status.description)")
        if status.isUntrusted, type == "Authorization plug-in" || type == "Kernel extension" {
            severity = .threat
            reason = "\(type) isn't signed by a trusted developer"
        }
        return Finding(path: url.path, severity: severity, engine: .persistence, reason: reason, detail: notes.joined(separator: "\n"), unitPath: url.path)
    }
}
