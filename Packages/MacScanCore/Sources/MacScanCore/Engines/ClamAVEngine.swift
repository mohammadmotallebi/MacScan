import Foundation

public enum ClamAVDatabase {
    static let homebrewDirectories = ["/opt/homebrew/var/lib/clamav", "/usr/local/var/lib/clamav"]
    static let databaseExtensions: Set<String> = [
        "cvd", "cld", "cud", "ndb", "hdb", "hsb", "ldb", "mdb", "msb", "ndu", "ldu", "idb", "cdb", "fp", "sfp", "ign2", "yar", "yara", "pdb", "wdb", "cbc",
    ]

    /// Where "Update virus database" writes: the explicit setting or MacScan's own directory.
    public static func updateDirectory(override: String?) -> URL {
        if let override, !override.isEmpty { return URL(fileURLWithPath: (override as NSString).expandingTildeInPath) }
        return AppPaths.clamDatabase
    }

    /// Where scans read from: explicit setting → MacScan's dir (if populated) → Homebrew's dir (if populated) → MacScan's dir.
    public static func resolve(override: String?) -> URL {
        if let override, !override.isEmpty { return URL(fileURLWithPath: (override as NSString).expandingTildeInPath) }
        if hasDatabase(AppPaths.clamDatabase) { return AppPaths.clamDatabase }
        for dir in homebrewDirectories {
            let url = URL(fileURLWithPath: dir)
            if hasDatabase(url) { return url }
        }
        return AppPaths.clamDatabase
    }

    public static func hasDatabase(_ dir: URL) -> Bool {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else { return false }
        return files.contains { databaseExtensions.contains(($0 as NSString).pathExtension.lowercased()) }
    }

    /// Modification date of the newest database file (≈ last successful update).
    public static func lastUpdated(_ dir: URL) -> Date? {
        guard let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey]) else { return nil }
        return files
            .filter { databaseExtensions.contains($0.pathExtension.lowercased()) }
            .compactMap { try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate }
            .max()
    }
}

/// ClamAV via the `clamscan` CLI. One clamscan process scans the whole item list (`--file-list`),
/// because loading the signature database takes several seconds each time clamscan starts.
public struct ClamAVEngine: ScanEngine {
    public let id = EngineID.clamav
    public let displayName = "ClamAV"

    public static let installInstructions = """
    ClamAV is not installed. Install it with Homebrew:

        brew install clamav

    Then click “Update virus database” in MacScan to download the signatures. \
    If clamscan is installed somewhere else, set its path in Settings › Engines.
    """

    let clamscanURL: URL?
    let freshclamURL: URL?
    let databaseDirectory: URL
    let updateDirectory: URL
    let maxFileSizeMB: Int

    public init(settings: ScanSettings) {
        clamscanURL = ToolLocator.locate(.clamscan, override: settings.clamscanPath)
        freshclamURL = ToolLocator.locate(.freshclam, override: settings.freshclamPath)
        databaseDirectory = ClamAVDatabase.resolve(override: settings.clamDatabasePath)
        updateDirectory = ClamAVDatabase.updateDirectory(override: settings.clamDatabasePath)
        maxFileSizeMB = settings.maxFileSizeMB
    }

    /// Explicit initializer (tests, custom setups).
    public init(clamscanURL: URL?, freshclamURL: URL? = nil, databaseDirectory: URL, maxFileSizeMB: Int = 100) {
        self.clamscanURL = clamscanURL
        self.freshclamURL = freshclamURL
        self.databaseDirectory = databaseDirectory
        self.updateDirectory = databaseDirectory
        self.maxFileSizeMB = maxFileSizeMB
    }

    public func availability() async -> EngineAvailability {
        guard clamscanURL != nil else { return .notInstalled(instructions: Self.installInstructions) }
        guard ClamAVDatabase.hasDatabase(databaseDirectory) else {
            return .needsSetup("No virus database yet. Click “Update virus database” to download it (≈300 MB).")
        }
        if let date = ClamAVDatabase.lastUpdated(databaseDirectory) {
            return .available(detail: "Signatures from \(date.formatted(date: .abbreviated, time: .shortened))")
        }
        return .available(detail: "Database at \(databaseDirectory.path)")
    }

    public func handles(_ item: ScanItem) -> Bool { item.kind == .file }

    public func scan(_ items: [ScanItem], context: ScanContext, events: @escaping EngineEventSink) async throws {
        guard let clamscan = clamscanURL else { throw EngineError.unavailable(Self.installInstructions) }
        guard !items.isEmpty else { return }

        // clamscan reads one path per line, so paths containing newlines can't go in the list.
        let (listable, odd) = items.reduce(into: ([ScanItem](), [ScanItem]())) { acc, item in
            if item.path.contains("\n") { acc.1.append(item) } else { acc.0.append(item) }
        }
        if !odd.isEmpty {
            await events(.note("ClamAV skipped \(odd.count) file(s) whose names contain line breaks."))
        }

        let tmp = try AppPaths.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let listURL = tmp.appendingPathComponent("files.txt")
        try listable.map(\.path).joined(separator: "\n").write(to: listURL, atomically: true, encoding: .utf8)

        let byPath = Dictionary(listable.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        let mb = max(1, maxFileSizeMB)
        let args = [
            "--database=\(databaseDirectory.path)",
            "--file-list=\(listURL.path)",
            "--no-summary",
            "--max-filesize=\(mb)M",
            "--max-scansize=\(mb * 4)M",
        ]

        await events(.note("ClamAV: loading signature database…"))
        context.logger.info("clamscan \(args.joined(separator: " ")) (\(listable.count) files)")

        let result = try await ProcessRunner.run(clamscan, args, collectStdout: false) { line in
            guard let parsed = Self.parseLine(line) else { return }
            guard let item = byPath[parsed.path] else { return }
            await events(.itemStarted(parsed.path))
            if let signature = parsed.signature {
                await events(.finding(Self.finding(for: item, signature: signature)))
            }
            await events(.itemFinished(parsed.path))
        }

        // clamscan: 0 = clean, 1 = virus found, 2 = some error(s) occurred.
        switch result.exitCode {
        case 0, 1:
            break
        default:
            let stderr = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            context.logger.warning("clamscan exit \(result.exitCode): \(stderr)")
            if Self.isFatal(stderr) {
                throw EngineError.failed("ClamAV could not run: " + (stderr.split(separator: "\n").last.map(String.init) ?? "exit code \(result.exitCode)"))
            }
            let errorCount = stderr.split(separator: "\n").filter { $0.contains("ERROR") }.count
            if errorCount > 0 {
                await events(.note("ClamAV reported \(errorCount) file error(s); see ~/Library/Logs/MacScan/MacScan.log."))
            }
        }
    }

    // MARK: - Parsing

    struct ParsedLine: Equatable {
        let path: String
        /// nil when the file is clean (OK / Empty file / Excluded…).
        let signature: String?
    }

    /// Parses "/path/to/file: OK" or "/path/to/file: Some.Signature-Name FOUND".
    static func parseLine(_ line: String) -> ParsedLine? {
        guard let sep = line.range(of: ": ", options: .backwards) else { return nil }
        let path = String(line[..<sep.lowerBound])
        let verdict = String(line[sep.upperBound...]).trimmingCharacters(in: .whitespaces)
        guard path.hasPrefix("/") else { return nil }
        if verdict.hasSuffix(" FOUND") {
            return ParsedLine(path: path, signature: String(verdict.dropLast(" FOUND".count)))
        }
        return ParsedLine(path: path, signature: nil)
    }

    static func finding(for item: ScanItem, signature: String) -> Finding {
        // PUA (potentially unwanted) and heuristic hits are warnings; real signatures are threats.
        let lower = signature.lowercased()
        let isSoft = lower.hasPrefix("pua.") || lower.hasPrefix("heuristics.") || lower.contains(".pua.")
        return Finding(
            path: item.path,
            severity: isSoft ? .warning : .threat,
            engine: .clamav,
            reason: "ClamAV: \(signature)",
            detail: isSoft
                ? "Potentially unwanted or heuristic detection. Review before acting."
                : "Matched ClamAV signature \(signature).",
            unitPath: item.unitPath
        )
    }

    static func isFatal(_ stderr: String) -> Bool {
        let markers = ["cl_load", "No supported database files found", "Can't open file or directory", "Malformed database", "cli_loaddb"]
        return markers.contains { stderr.contains($0) }
    }

    // MARK: - Database update

    /// Runs `freshclam` (only when the user clicks “Update virus database”).
    /// Uses MacScan's own config + data directory so Homebrew's config is never touched.
    public func updateDatabase(onLine: @escaping @Sendable (String) async -> Void) async throws {
        guard let freshclam = freshclamURL else {
            throw EngineError.unavailable(Self.installInstructions)
        }
        let dir = updateDirectory
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let config = AppPaths.applicationSupport.appendingPathComponent("freshclam.conf")
        let configText = """
        # Generated by MacScan. Used only when you click “Update virus database”.
        DatabaseMirror database.clamav.net
        """
        try configText.write(to: config, atomically: true, encoding: .utf8)

        let args = ["--config-file=\(config.path)", "--datadir=\(dir.path)", "--stdout", "--no-warnings"]
        FileLogger.shared.info("freshclam \(args.joined(separator: " "))")
        let result = try await ProcessRunner.run(freshclam, args) { line in
            await onLine(line)
        }
        if !result.stderr.isEmpty {
            for line in result.stderr.split(separator: "\n") { await onLine(String(line)) }
        }
        guard result.exitCode == 0 else {
            FileLogger.shared.error("freshclam failed (\(result.exitCode)): \(result.stderr)")
            throw EngineError.failed("freshclam exited with code \(result.exitCode). See the log above for details.")
        }
        FileLogger.shared.info("freshclam finished successfully")
    }
}
