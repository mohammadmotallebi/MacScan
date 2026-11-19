import Foundation

public struct EnumerationResult: Sendable {
    public var items: [ScanItem] = []
    /// Files skipped because they exceed the size limit.
    public var skippedCount = 0
    public var issues: [ScanIssue] = []
    /// Findings from the startup-items inventory (engine `.persistence`).
    public var persistenceFindings: [Finding] = []
    /// Units already described by a persistence finding (no generic "No issues found" row).
    public var coveredUnits: Set<String> = []
    /// Startup items collected by a Startup Items target (nil when there was none).
    public var startupSnapshot: StartupSnapshot?
    /// Findings and snapshot from the browser-extension inventory (engine `.extensions`).
    public var extensionFindings: [Finding] = []
    public var extensionSnapshot: [String: BrowserExtensionState]?
    /// Findings from the running-process inventory (engine `.processes`).
    public var processFindings: [Finding] = []
    /// Executables of running programs; their signature verdict comes from the process finding.
    public var processExecutables: Set<String> = []
    /// Notes for the session (for example how many system processes were not listed).
    public var notes: [String] = []
    /// Which target first claimed each unit. A unit walked by Applications stays an Applications unit
    /// even if a later target (startup items, running processes) points into it.
    public var unitAreas: [String: ScanArea] = [:]

    public var fileCount: Int { items.lazy.filter { $0.kind == .file }.count }
    public var bundleCount: Int { items.lazy.filter { $0.kind == .appBundle }.count }
}

/// Walks scan targets and produces the list of `ScanItem`s.
///
/// - .app bundles produce one `.appBundle` item (for integrity checks) plus items for the files inside.
/// - Excluded paths, oversized files and (optionally) symlinks are skipped.
/// - Directories that macOS refuses to open are recorded as permission issues instead of failing the scan.
public struct FileEnumerator: Sendable {
    public let settings: ScanSettings
    public let persistenceLocations: PersistenceLocations
    public let processLister: any ProcessListing
    public let browserLocations: BrowserLocations

    /// Script-like extensions considered "executable content" in Applications scans.
    static let scriptExtensions: Set<String> = [
        "sh", "bash", "zsh", "command", "tool", "py", "rb", "pl", "php", "js", "jxa",
        "scpt", "applescript", "scptd", "jar", "dylib", "so", "pkg", "dmg", "workflow",
    ]

    public init(settings: ScanSettings, persistenceLocations: PersistenceLocations = .system,
                processLister: any ProcessListing = SystemProcessList(),
                browserLocations: BrowserLocations = .system) {
        self.browserLocations = browserLocations
        self.settings = settings
        self.persistenceLocations = persistenceLocations
        self.processLister = processLister
    }

    public static var applicationFolders: [URL] {
        [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            AppPaths.home.appendingPathComponent("Applications", isDirectory: true),
        ]
    }

    /// Enumerates synchronously; throws `CancellationError` if the current Task is cancelled.
    public func enumerate(_ targets: [ScanTarget]) throws -> EnumerationResult {
        var walker = Walker(settings: settings)
        for target in targets {
            walker.area = target.area
            switch target {
            case .applications:
                for folder in Self.applicationFolders where FileManager.default.fileExists(atPath: folder.path) {
                    try walker.walk(folder, applicationsMode: true)
                }
            case .path(let url):
                try walker.walk(url, applicationsMode: false)
            case .startupItems:
                let inventory = try PersistenceScanner(locations: persistenceLocations).collect()
                walker.result.persistenceFindings += inventory.findings
                walker.result.startupSnapshot = inventory.snapshot
                walker.result.coveredUnits.formUnion(inventory.coveredUnits)
                for path in inventory.scanPaths {
                    try walker.walk(URL(fileURLWithPath: path), applicationsMode: false)
                }
                for path in inventory.programPaths {
                    walker.addProgram(URL(fileURLWithPath: path))
                }
            case .browserExtensions:
                let inventory = try BrowserExtensionScanner(locations: browserLocations).collect()
                walker.result.extensionFindings += inventory.findings
                walker.result.extensionSnapshot = inventory.snapshot
                walker.result.coveredUnits.formUnion(inventory.coveredUnits)
                walker.result.notes += inventory.notes
                for path in inventory.scanPaths {
                    // Each extension is one unit: its hundreds of script files don't get a row each.
                    try walker.walk(URL(fileURLWithPath: path), applicationsMode: false, unit: URL(fileURLWithPath: path))
                }
            case .runningProcesses:
                let inventory = try ProcessScanner(lister: processLister).collect()
                walker.result.processFindings += inventory.findings
                walker.result.coveredUnits.formUnion(inventory.coveredUnits)
                walker.result.notes += inventory.notes
                for path in inventory.programPaths {
                    let url = URL(fileURLWithPath: path)
                    walker.result.processExecutables.formUnion([path, Paths.canonical(url).path])
                    walker.addProgram(url)
                }
            }
        }
        return walker.result
    }

    /// Walks a single root with explicit mode (used for tests and for scanning one app folder).
    func enumerate(root: URL, applicationsMode: Bool) throws -> EnumerationResult {
        var walker = Walker(settings: settings)
        try walker.walk(root, applicationsMode: applicationsMode)
        return walker.result
    }

    // MARK: - Walker

    private struct Walker {
        let settings: ScanSettings
        var result = EnumerationResult()
        var seen = Set<String>()
        var counter = 0
        /// The area of the target being walked.
        var area = ScanArea.files

        static let keys: [URLResourceKey] = [
            .isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey, .isExecutableKey,
        ]

        let excluder: PathExcluder

        init(settings: ScanSettings) {
            self.settings = settings
            // Quarantined items are locked and already dealt with: never scan them or report them as unreadable.
            self.excluder = PathExcluder(settings.excludedPaths + [AppPaths.quarantinePath])
        }

        /// `unit` makes every file below `root` belong to that one result unit (as files in an app do).
        mutating func walk(_ root: URL, applicationsMode: Bool, unit: URL? = nil) throws {
            // The user explicitly chose this root, so a symlinked root is resolved.
            let root = Paths.canonical(root)
            let rootPath = root.path
            guard !excluder.contains(rootPath) else { return }

            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: rootPath, isDirectory: &isDir) else {
                result.issues.append(ScanIssue(path: rootPath, message: "Does not exist", isPermissionDenied: false))
                return
            }

            if !isDir.boolValue {
                let values = try? root.resourceValues(forKeys: Set(Self.keys))
                addFile(root, values: values, bundle: unit, applicationsMode: applicationsMode)
                return
            }

            // Detect unreadable roots up front so the user gets a clear Full Disk Access message.
            do {
                _ = try FileManager.default.contentsOfDirectory(atPath: rootPath)
            } catch {
                recordIssue(path: rootPath, error: error)
                return
            }

            var currentBundle: URL? = unit
            if unit == nil, isAppBundle(root) {
                addBundle(root)
                currentBundle = root
            }

            let collector = ErrorCollector()
            guard let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: Self.keys,
                options: [],
                errorHandler: { url, error in
                    collector.errors.append((url.path, error))
                    return true
                }
            ) else { return }

            while let url = enumerator.nextObject() as? URL {
                counter += 1
                if counter % 256 == 0 { try Task.checkCancellation() }

                let path = url.path
                if unit == nil, let b = currentBundle, !path.hasPrefix(b.path + "/") {
                    currentBundle = nil
                }
                let values = try? url.resourceValues(forKeys: Set(Self.keys))

                if excluder.contains(path) {
                    if values?.isDirectory == true { enumerator.skipDescendants() }
                    continue
                }

                if values?.isSymbolicLink == true {
                    // Symlinks are structural in bundles (Versions/Current…); skipping them isn't counted.
                    if settings.skipSymlinks { continue }
                    let target = Paths.canonical(url)
                    let tValues = try? target.resourceValues(forKeys: Set(Self.keys))
                    // Only file symlinks are followed; directory symlinks could create loops.
                    if tValues?.isRegularFile == true, !excluder.contains(target.path) {
                        addFile(target, values: tValues, bundle: currentBundle, applicationsMode: applicationsMode)
                    }
                    continue
                }

                if values?.isDirectory == true {
                    if unit == nil, currentBundle == nil, isAppBundle(url) {
                        addBundle(url)
                        currentBundle = url
                    }
                    continue
                }

                if values?.isRegularFile == true {
                    addFile(url, values: values, bundle: currentBundle, applicationsMode: applicationsMode)
                }
            }

            for (path, error) in collector.errors {
                recordIssue(path: path, error: error)
            }
        }

        func isAppBundle(_ url: URL) -> Bool {
            url.pathExtension.lowercased() == "app"
        }

        /// Adds a single program; if it lives inside an .app, the app is added for integrity checks too.
        mutating func addProgram(_ url: URL) {
            let url = Paths.canonical(url)
            guard !excluder.contains(url.path) else { return }
            let values = try? url.resourceValues(forKeys: Set(Self.keys))
            guard values?.isRegularFile == true else { return }
            let app = PersistenceScanner.enclosingApp(of: url.path)
            if let app { addBundle(app) }
            addFile(url, values: values, bundle: app, applicationsMode: false)
        }

        mutating func addBundle(_ url: URL) {
            guard seen.insert("bundle:" + url.path).inserted else { return }
            result.items.append(ScanItem(url: url, kind: .appBundle, bundleURL: url))
            claim(url.path)
        }

        mutating func addFile(_ url: URL, values: URLResourceValues?, bundle: URL?, applicationsMode: Bool) {
            let path = url.path
            guard !seen.contains(path) else { return }

            let size = Int64(values?.fileSize ?? 0)
            if size > settings.maxFileSizeBytes {
                seen.insert(path)
                result.skippedCount += 1
                return
            }

            let inspection = MachO.inspect(path: path)
            if case .unreadable(let err) = inspection {
                seen.insert(path)
                let denied = err == EPERM || err == EACCES
                result.issues.append(ScanIssue(
                    path: path,
                    message: String(cString: strerror(err)),
                    isPermissionDenied: denied
                ))
                return
            }
            let isMachO = inspection == .executableCode

            if applicationsMode, settings.appScanExecutablesOnly {
                let ext = url.pathExtension.lowercased()
                let interesting = isMachO
                    || values?.isExecutable == true
                    || FileEnumerator.scriptExtensions.contains(ext)
                guard interesting else { return }
            }

            seen.insert(path)
            result.items.append(ScanItem(url: url, kind: .file, size: size, isMachO: isMachO, bundleURL: bundle))
            claim(bundle?.path ?? path)
        }

        private mutating func claim(_ unit: String) {
            if result.unitAreas[unit] == nil { result.unitAreas[unit] = area }
        }

        mutating func recordIssue(path: String, error: Error) {
            result.issues.append(ScanIssue(
                path: path,
                message: error.localizedDescription,
                isPermissionDenied: PermissionErrors.isPermissionDenied(error)
            ))
        }
    }
}

/// Collects enumerator errors (the error handler closure can't mutate the walker directly).
private final class ErrorCollector {
    var errors: [(String, Error)] = []
}

public enum PermissionErrors {
    /// True for EPERM/EACCES and Cocoa "no permission" errors, including wrapped underlying errors.
    public static func isPermissionDenied(_ error: Error) -> Bool {
        let ns = error as NSError
        if ns.domain == NSCocoaErrorDomain,
           ns.code == NSFileReadNoPermissionError || ns.code == NSFileWriteNoPermissionError {
            return true
        }
        if ns.domain == NSPOSIXErrorDomain, ns.code == Int(EPERM) || ns.code == Int(EACCES) {
            return true
        }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? Error {
            return isPermissionDenied(underlying)
        }
        return false
    }
}

public enum Paths {
    /// Fully resolved absolute path via realpath(3) (e.g. /var/... -> /private/var/...).
    /// Falls back to the standardized path if the file doesn't exist.
    public static func canonical(_ url: URL) -> URL {
        let path = url.standardizedFileURL.path
        guard let resolved = realpath(path, nil) else { return url.standardizedFileURL }
        defer { free(resolved) }
        return URL(fileURLWithPath: String(cString: resolved))
    }
}

/// Matches exclusion prefixes both as typed and in canonical (symlink-resolved) form.
struct PathExcluder: Sendable {
    let prefixes: [String]

    init(_ raw: [String]) {
        var set = Set<String>()
        for entry in raw {
            let expanded = (entry as NSString).expandingTildeInPath
            guard !expanded.isEmpty else { continue }
            let trimmed = expanded.count > 1 && expanded.hasSuffix("/") ? String(expanded.dropLast()) : expanded
            set.insert(trimmed)
            set.insert(Paths.canonical(URL(fileURLWithPath: trimmed)).path)
        }
        prefixes = Array(set)
    }

    func contains(_ path: String) -> Bool {
        prefixes.contains { path == $0 || path.hasPrefix($0 + "/") }
    }
}
