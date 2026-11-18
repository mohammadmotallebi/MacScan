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
/// The tracked facts about one inventory item (a startup item, a browser extension).
public protocol TrackedItemState: Codable, Hashable, Sendable {
    /// Display name.
    var name: String { get }
    /// Plain-language differences from an earlier state of the same item; empty when nothing relevant changed.
    func differences(from old: Self) -> [String]
}

public struct StartupItemState: TrackedItemState {
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

    public var text: String { text(subject: "Startup items") }

    public func text(subject: String) -> String {
        func part(_ names: [String], _ word: String) -> String? {
            guard !names.isEmpty else { return nil }
            let shown = names.prefix(5).joined(separator: ", ") + (names.count > 5 ? " and \(names.count - 5) more" : "")
            return "\(names.count) \(word) (\(shown))"
        }
        let date = since.formatted(date: .abbreviated, time: .shortened)
        let parts = [part(added, "new"), part(changed, "changed"), part(removed, "removed")].compactMap { $0 }
        return parts.isEmpty
            ? "\(subject): nothing added, changed or removed since the scan on \(date)."
            : "\(subject) since the scan on \(date): " + parts.joined(separator: "; ") + "."
    }
}

/// Shared comparison of an inventory with its saved baseline file.
enum ChangeTracking {
    struct Baseline<State: TrackedItemState>: Codable {
        var savedAt: Date
        var items: [String: State]
    }

    /// Marks new and changed results of `engine` in the session, adds a summary note, saves `snapshot`
    /// as the new baseline, and returns the summary (nil for the first scan).
    static func apply<State: TrackedItemState>(
        snapshot: [String: State], file: URL, engine: EngineID, subject: String, session: inout ScanSession
    ) -> StartupChangeSummary? {
        defer {
            do {
                try JSONEncoder.macScan.encode(Baseline(savedAt: session.startedAt, items: snapshot)).write(to: file, options: .atomic)
            } catch {
                session.notes.append("Could not save the baseline for \(subject.lowercased()): \(error.localizedDescription)")
            }
        }
        guard let data = try? Data(contentsOf: file),
              let baseline = try? JSONDecoder.macScan.decode(Baseline<State>.self, from: data) else {
            session.notes.append("\(subject): baseline saved (\(snapshot.count) items). Later scans report what was added, changed or removed.")
            return nil
        }

        var summary = StartupChangeSummary(since: baseline.savedAt)
        let date = baseline.savedAt.formatted(date: .abbreviated, time: .shortened)
        for key in snapshot.keys.sorted() {
            let state = snapshot[key]!
            let change: FindingChange
            let lead: String
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
            for index in session.findings.indices where session.findings[index].engine == engine && session.findings[index].changeKey(default: session.findings[index].unitPath) == key {
                session.findings[index].change = change
                session.findings[index].detail = lead + "\n\n" + (session.findings[index].detail ?? "")
            }
        }
        summary.removed = baseline.items.filter { snapshot[$0.key] == nil }.map(\.value.name).sorted()
        session.notes.append(summary.text(subject: subject))
        return summary
    }
}

extension Finding {
    func changeKey(default fallback: String) -> String { trackingKey ?? fallback }
}

/// Remembers the startup items of the last scan and marks what is new or changed in the next one.
/// The only file it writes is its own baseline; startup items themselves are never touched.
public struct StartupChangeTracker: Sendable {
    public let file: URL

    public init(file: URL = AppPaths.startupBaselineFile) {
        self.file = file
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
        session.startupChanges = ChangeTracking.apply(snapshot: snapshot, file: file, engine: .persistence, subject: "Startup items", session: &session)
    }
}

/// The same for browser extensions: what was installed, or gained permissions, since the last scan.
public struct ExtensionChangeTracker: Sendable {
    public let file: URL

    public init(file: URL = AppPaths.extensionBaselineFile) {
        self.file = file
    }

    public func apply(to session: inout ScanSession) {
        guard let snapshot = session.extensionSnapshot else { return }
        session.extensionSnapshot = nil
        session.extensionChanges = ChangeTracking.apply(snapshot: snapshot, file: file, engine: .extensions, subject: "Browser extensions", session: &session)
    }
}
