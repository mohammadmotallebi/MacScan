import Foundation

/// How a result differs from the previous scan of the same kind.
public enum FindingChange: String, Codable, Sendable {
    case new
    case changed

    public var title: String {
        switch self {
        case .new: "New"
        case .changed: "Changed"
        }
    }
}

/// What one startup item does, reduced to the parts whose change matters: what it starts, with which
/// arguments, who signed that program, and (for scripts and shell files) the file's contents.
/// An app update that replaces a program with one from the same signer is deliberately not a change.
public struct StartupItemState: Codable, Hashable, Sendable {
    /// Display name (launchd label, file name or cron job).
    public var name: String
    public var program: String?
    public var arguments: [String]
    public var signer: String?
    public var contentHash: String?

    public init(name: String, program: String? = nil, arguments: [String] = [], signer: String? = nil, contentHash: String? = nil) {
        self.name = name
        self.program = program
        self.arguments = arguments
        self.signer = signer
        self.contentHash = contentHash
    }

    /// Plain-language differences from an earlier state of the same item; empty when nothing relevant changed.
    public func differences(from old: StartupItemState) -> [String] {
        var result: [String] = []
        if program != old.program {
            result.append("Program changed: \(old.program ?? "none") → \(program ?? "none")")
        }
        if arguments != old.arguments {
            let before = old.arguments.dropFirst().joined(separator: " ")
            result.append("Arguments changed" + (before.isEmpty ? "" : " (were: \(before.count > 200 ? String(before.prefix(200)) + "…" : before))"))
        }
        if signer != old.signer {
            result.append("Signer changed: \(old.signer ?? "unknown") → \(signer ?? "unknown")")
        }
        if contentHash != old.contentHash {
            result.append("File contents changed")
        }
        return result
    }

    static func signerSummary(_ status: SigningStatus) -> String? {
        switch status {
        case .unsigned: "unsigned"
        case .adhoc: "ad-hoc"
        case .selfSigned(_, let authority): "self-signed (\(authority ?? "unknown"))"
        case .signed(_, let team, let authority): team.map { "Team \($0)" } ?? authority ?? "Apple-issued certificate"
        case .unreadable: nil   // transient read errors must not look like a change
        }
    }

    /// Key and state for one inventory entry.
    static func make(_ entry: PersistenceEntry) -> (key: String, state: StartupItemState) {
        let fileName = (entry.source as NSString).lastPathComponent
        var state = StartupItemState(name: entry.label ?? fileName, program: entry.program ?? entry.bundleProgram, arguments: entry.arguments)
        var key = entry.source
        switch entry.kind {
        case .cronJob:
            key += "#" + (entry.label ?? "")
            state.name = entry.label.map { $0.count > 60 ? String($0.prefix(60)) + "…" : $0 } ?? fileName
        case .shellStartup:
            state.contentHash = FileHasher.fingerprint(for: entry.source)
        case .plugin:
            state.name = fileName
            state.signer = signerSummary(CodeSigning.status(of: URL(fileURLWithPath: entry.source)))
        case .userLaunchAgent, .launchAgent, .launchDaemon, .privilegedHelper:
            guard let program = entry.program else { break }
            switch MachO.inspect(path: program) {
            case .executableCode: state.signer = signerSummary(CodeSigning.status(of: URL(fileURLWithPath: program)))
            case .notMachO: state.contentHash = FileHasher.fingerprint(for: program)   // a script: its text is its behaviour
            default: break
            }
        }
        return (key, state)
    }
}

public typealias StartupSnapshot = [String: StartupItemState]

/// What changed between the saved baseline and a scan. Names are display names.
public struct StartupChangeSummary: Codable, Hashable, Sendable {
    public var since: Date
    public var added: [String] = []
    public var changed: [String] = []
    public var removed: [String] = []

    public var isEmpty: Bool { added.isEmpty && changed.isEmpty && removed.isEmpty }

    public var text: String {
        func part(_ names: [String], _ word: String) -> String? {
            guard !names.isEmpty else { return nil }
            let shown = names.prefix(5).joined(separator: ", ") + (names.count > 5 ? " and \(names.count - 5) more" : "")
            return "\(names.count) \(word) (\(shown))"
        }
        let date = since.formatted(date: .abbreviated, time: .shortened)
        let parts = [part(added, "new"), part(changed, "changed"), part(removed, "removed")].compactMap { $0 }
        return parts.isEmpty
            ? "Startup items: nothing added, changed or removed since the scan on \(date)."
            : "Startup items since the scan on \(date): " + parts.joined(separator: "; ") + "."
    }
}

/// Remembers the startup items of the last scan and marks what is new or changed in the next one.
/// The only file it writes is its own baseline; startup items themselves are never touched.
public struct StartupChangeTracker: Sendable {
    struct Baseline: Codable {
        var savedAt: Date
        var items: StartupSnapshot
    }

    public let file: URL

    public init(file: URL = AppPaths.startupBaselineFile) {
        self.file = file
    }

    func load() -> Baseline? {
        guard let data = try? Data(contentsOf: file) else { return nil }
        return try? JSONDecoder.macScan.decode(Baseline.self, from: data)
    }

    public func forget() {
        try? FileManager.default.removeItem(at: file)
    }

    /// Compares the session's startup snapshot with the baseline, marks new and changed results, adds
    /// a summary note, and saves the snapshot as the new baseline. Does nothing for a scan that didn't
    /// include Startup Items. Run it as the user (never in the root worker), so the baseline stays theirs.
    public func apply(to session: inout ScanSession) {
        guard let snapshot = session.startupSnapshot else { return }
        session.startupSnapshot = nil   // the baseline file holds it from here on
        defer {
            do {
                try JSONEncoder.macScan.encode(Baseline(savedAt: session.startedAt, items: snapshot)).write(to: file, options: .atomic)
            } catch {
                session.notes.append("Could not save the startup item baseline: \(error.localizedDescription)")
            }
        }
        guard let baseline = load() else {
            session.notes.append("Startup items: baseline saved (\(snapshot.count) items). Later scans report what was added, changed or removed.")
            return
        }

        var summary = StartupChangeSummary(since: baseline.savedAt)
        let date = baseline.savedAt.formatted(date: .abbreviated, time: .shortened)
        for key in snapshot.keys.sorted() {
            let state = snapshot[key]!
            var change: FindingChange?
            var lead = ""
            if let old = baseline.items[key] {
                let differences = state.differences(from: old)
                guard !differences.isEmpty else { continue }
                change = .changed
                summary.changed.append(state.name)
                lead = "Changed since the scan on \(date):\n" + differences.map { "• \($0)" }.joined(separator: "\n")
            } else {
                change = .new
                summary.added.append(state.name)
                lead = "New since the scan on \(date)."
            }
            for index in session.findings.indices where session.findings[index].engine == .persistence && session.findings[index].unitPath == key {
                session.findings[index].change = change
                session.findings[index].detail = lead + "\n\n" + (session.findings[index].detail ?? "")
            }
        }
        summary.removed = baseline.items.filter { snapshot[$0.key] == nil }.map(\.value.name).sorted()
        session.startupChanges = summary
        session.notes.append(summary.text)
    }
}
