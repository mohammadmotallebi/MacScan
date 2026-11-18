import Foundation

/// YARA via the `yara` CLI. Rules from the chosen folder are compiled once per scan with `yarac`
/// (if available), then files are scanned in chunks with `--scan-list` so progress updates regularly.
public struct YaraEngine: ScanEngine {
    public let id = EngineID.yara
    public let displayName = "YARA"

    public static let installInstructions = """
    YARA is not installed. Install it with Homebrew:

        brew install yara

    If yara is installed somewhere else, set its path in Settings › Engines.
    """

    /// The sample rules that ship with MacScan.
    public static var bundledRulesFolder: URL? {
        Bundle.module.url(forResource: "SampleRules", withExtension: nil)
    }

    /// Apple's XProtect YARA rules, updated by macOS itself.
    public static let xprotectRulesURL = URL(fileURLWithPath: "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara")
    static let xprotectNamespace = "xprotect"

    let yaraURL: URL?
    let yaracURL: URL?
    let rulesFolder: URL?
    /// Extra rule files compiled into their own namespace (e.g. XProtect).
    let extraRules: [(namespace: String, url: URL)]
    let chunkSize: Int
    let perFileTimeoutSeconds: Int

    public init(settings: ScanSettings) {
        yaraURL = ToolLocator.locate(.yara, override: settings.yaraPath)
        yaracURL = ToolLocator.locate(.yarac, override: settings.yaracPath)
        if let folder = settings.yaraRulesFolder, !folder.isEmpty {
            rulesFolder = URL(fileURLWithPath: (folder as NSString).expandingTildeInPath)
        } else {
            rulesFolder = Self.bundledRulesFolder
        }
        if settings.useXProtectRules, FileManager.default.isReadableFile(atPath: Self.xprotectRulesURL.path) {
            extraRules = [(Self.xprotectNamespace, Self.xprotectRulesURL)]
        } else {
            extraRules = []
        }
        chunkSize = 400
        perFileTimeoutSeconds = 60
    }

    public init(yaraURL: URL?, yaracURL: URL?, rulesFolder: URL?, extraRules: [(namespace: String, url: URL)] = [], chunkSize: Int = 400) {
        self.yaraURL = yaraURL
        self.yaracURL = yaracURL
        self.rulesFolder = rulesFolder
        self.extraRules = extraRules
        self.chunkSize = max(1, chunkSize)
        self.perFileTimeoutSeconds = 60
    }

    /// Number of `rule` declarations in Apple's XProtect file (for display).
    public static func xprotectRuleCount() -> Int? {
        guard let text = try? String(contentsOf: xprotectRulesURL, encoding: .utf8) else { return nil }
        return text.split(separator: "\n").lazy.filter { $0.hasPrefix("rule ") }.count
    }

    /// All rule sources: folder files (default namespace) plus extra files in their own namespace.
    func ruleSourceArguments() -> [String] {
        ruleFiles().map(\.path) + extraRules.map { "\($0.namespace):\($0.url.path)" }
    }

    public func availability() async -> EngineAvailability {
        guard yaraURL != nil else { return .notInstalled(instructions: Self.installInstructions) }
        let files = ruleFiles()
        guard !files.isEmpty || !extraRules.isEmpty else {
            if let rulesFolder { return .needsSetup("No .yar/.yara files found in \(rulesFolder.path).") }
            return .needsSetup("Choose a YARA rules folder in Settings › Engines.")
        }
        var parts: [String] = []
        if !files.isEmpty {
            parts.append(rulesFolder == Self.bundledRulesFolder ? "sample rules" : "\(files.count) file(s) in \(rulesFolder?.lastPathComponent ?? "folder")")
        }
        if extraRules.contains(where: { $0.namespace == Self.xprotectNamespace }) {
            parts.append("Apple XProtect" + (Self.xprotectRuleCount().map { " (\($0) rules)" } ?? ""))
        }
        return .available(detail: parts.joined(separator: " + "))
    }

    public func handles(_ item: ScanItem) -> Bool { item.kind == .file }

    public func ruleFiles() -> [URL] {
        guard let rulesFolder,
              let e = FileManager.default.enumerator(at: rulesFolder, includingPropertiesForKeys: [.isRegularFileKey])
        else { return [] }
        var files: [URL] = []
        for case let url as URL in e where ["yar", "yara"].contains(url.pathExtension.lowercased()) {
            files.append(url)
        }
        return files.sorted { $0.path < $1.path }
    }

    /// Compiles rules. Returns the arguments that select the rules for `yara` (compiled file or sources).
    func prepareRules(in tmp: URL) async throws -> [String] {
        let sources = ruleSourceArguments()
        guard !sources.isEmpty else { throw EngineError.unavailable("No YARA rule files found.") }

        if let yarac = yaracURL {
            let compiled = tmp.appendingPathComponent("rules.yarc")
            let r = try await ProcessRunner.run(yarac, ["-w"] + sources + [compiled.path])
            guard r.exitCode == 0 else {
                throw EngineError.failed("YARA rules failed to compile:\n" + r.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            return ["-C", compiled.path]
        }
        return sources
    }

    public func scan(_ items: [ScanItem], context: ScanContext, events: @escaping EngineEventSink) async throws {
        guard let yara = yaraURL else { throw EngineError.unavailable(Self.installInstructions) }
        guard !items.isEmpty else { return }

        let tmp = try AppPaths.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let ruleArgs = try await prepareRules(in: tmp)

        let usable = items.filter { !$0.path.contains("\n") }
        let byPath = Dictionary(usable.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        var errorCount = 0

        for start in stride(from: 0, to: usable.count, by: chunkSize) {
            try Task.checkCancellation()
            let chunk = Array(usable[start..<min(start + chunkSize, usable.count)])
            if let first = chunk.first { await events(.itemStarted(first.path)) }

            let list = tmp.appendingPathComponent("chunk.txt")
            try chunk.map(\.path).joined(separator: "\n").write(to: list, atomically: true, encoding: .utf8)

            let args = ["-w", "-m", "-e", "-a", String(perFileTimeoutSeconds)] + ruleArgs + ["--scan-list", list.path]
            let r = try await ProcessRunner.run(yara, args) { line in
                guard let match = Self.parseMatch(line), let item = byPath[match.path] else { return }
                await events(.finding(Self.finding(for: item, match: match)))
            }
            if r.exitCode != 0 || !r.stderr.isEmpty {
                let lines = r.stderr.split(separator: "\n")
                errorCount += max(lines.count, r.exitCode != 0 ? 1 : 0)
                context.logger.warning("yara exit \(r.exitCode): \(r.stderr.prefix(2000))")
            }
            for item in chunk { await events(.itemFinished(item.path)) }
        }

        if errorCount > 0 {
            await events(.note("YARA reported \(errorCount) error(s) (usually unreadable files); see ~/Library/Logs/MacScan/MacScan.log."))
        }
    }

    // MARK: - Parsing

    struct Match: Equatable {
        let rule: String
        let meta: [String: String]
        let path: String
        var namespace: String? = nil
    }

    /// Parses `yara -m` output: `RuleName [key="value",n=1] /path/to/file` or `RuleName /path`.
    static func parseMatch(_ line: String) -> Match? {
        guard let space = line.firstIndex(of: " ") else { return nil }
        let rule = String(line[..<space])
        guard !rule.isEmpty, rule.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == ":" }) else { return nil }
        var rest = line[line.index(after: space)...]
        var meta: [String: String] = [:]

        if rest.first == "[" {
            // Find the closing bracket that is not inside a quoted string.
            var inQuotes = false
            var escaped = false
            var end: Substring.Index?
            var i = rest.index(after: rest.startIndex)
            while i < rest.endIndex {
                let c = rest[i]
                if escaped { escaped = false }
                else if c == "\\" { escaped = true }
                else if c == "\"" { inQuotes.toggle() }
                else if c == "]", !inQuotes { end = i; break }
                i = rest.index(after: i)
            }
            guard let end else { return nil }
            meta = parseMeta(String(rest[rest.index(after: rest.startIndex)..<end]))
            rest = rest[rest.index(after: end)...]
            guard rest.first == " " else { return nil }
            rest = rest.dropFirst()
        }
        let path = String(rest)
        guard path.hasPrefix("/") else { return nil }
        // With `-e`, yara prints "namespace:Rule".
        if let colon = rule.firstIndex(of: ":") {
            let ns = String(rule[..<colon])
            let name = String(rule[rule.index(after: colon)...])
            return Match(rule: name, meta: meta, path: path, namespace: ns == "default" ? nil : ns)
        }
        return Match(rule: rule, meta: meta, path: path)
    }

    static func parseMeta(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        var key = ""
        var value = ""
        var readingKey = true
        var inQuotes = false
        var escaped = false
        func commit() {
            let k = key.trimmingCharacters(in: .whitespaces)
            if !k.isEmpty { result[k] = value }
            key = ""; value = ""; readingKey = true
        }
        for c in text {
            if readingKey {
                if c == "=" { readingKey = false } else if c != "," { key.append(c) }
                continue
            }
            if escaped { value.append(c); escaped = false; continue }
            if inQuotes {
                if c == "\\" { escaped = true }
                else if c == "\"" { inQuotes = false }
                else { value.append(c) }
                continue
            }
            if c == "\"" { inQuotes = true }
            else if c == "," { commit() }
            else { value.append(c) }
        }
        if !key.isEmpty { commit() }
        return result
    }

    static func finding(for item: ScanItem, match: Match) -> Finding {
        if match.namespace == xprotectNamespace {
            let family = match.meta["description"] ?? match.rule
            return Finding(
                path: item.path,
                severity: .threat,
                engine: .yara,
                reason: "Apple XProtect: \(family)",
                detail: "Matched Apple's built-in XProtect malware signature \(match.rule) (\(family)). Apple ships this rule with macOS to detect known Mac malware, so this is a high-confidence detection.\nRule source: \(xprotectRulesURL.path)",
                unitPath: item.unitPath
            )
        }
        let sev: Severity
        switch match.meta["severity"]?.lowercased() {
        case "threat", "high", "critical", "malicious": sev = .threat
        default: sev = .warning
        }
        let description = match.meta["description"]
        var details = ["Rule: \(match.rule)"]
        for (k, v) in match.meta.sorted(by: { $0.key < $1.key }) where k != "description" {
            details.append("\(k): \(v)")
        }
        return Finding(
            path: item.path,
            severity: sev,
            engine: .yara,
            reason: description.map { "YARA \(match.rule): \($0)" } ?? "YARA rule \(match.rule) matched",
            detail: details.joined(separator: "\n"),
            unitPath: item.unitPath
        )
    }
}
