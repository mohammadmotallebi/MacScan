import Foundation

/// Whether an engine can run right now, and why not.
public enum EngineAvailability: Sendable, Equatable {
    case available(detail: String)
    /// The tool is missing. The string contains install instructions.
    case notInstalled(instructions: String)
    /// Installed but needs a one-time setup step (e.g. download the virus database, add an API key).
    case needsSetup(String)
    /// Turned off in Settings.
    case disabled

    public var isAvailable: Bool {
        if case .available = self { return true }
        return false
    }

    public var summary: String {
        switch self {
        case .available(let d): d
        case .notInstalled(let i): i
        case .needsSetup(let s): s
        case .disabled: "Disabled in Settings"
        }
    }
}

/// Events an engine reports while scanning.
public enum EngineEvent: Sendable {
    /// The engine is now looking at this path (drives the "current file" label).
    case itemStarted(String)
    /// The engine is done with this path (drives "files scanned").
    case itemFinished(String)
    /// Something worth reporting (any severity).
    case finding(Finding)
    /// A non-fatal note for the scan log/session (e.g. "3 files could not be opened").
    case note(String)
}

public typealias EngineEventSink = @Sendable (EngineEvent) async -> Void

public struct ScanContext: Sendable {
    public let settings: ScanSettings
    public let logger: FileLogger

    public init(settings: ScanSettings, logger: FileLogger = .shared) {
        self.settings = settings
        self.logger = logger
    }
}

public enum EngineError: Error, LocalizedError, Equatable {
    case unavailable(String)
    case failed(String)

    public var errorDescription: String? {
        switch self {
        case .unavailable(let s): s
        case .failed(let s): s
        }
    }
}

/// A detection engine. Add a new engine by conforming to this protocol and registering it in `EngineFactory`.
///
/// The coordinator hands each engine *all* items it `handles(_:)` in one call, so engines with a
/// slow start-up (ClamAV loads its database once) can process them in a single run or in batches.
/// Engines must:
///  - emit `.itemFinished` for items as they complete (anything not reported is marked done when `scan` returns),
///  - check for Task cancellation and throw `CancellationError` promptly,
///  - never modify, move, or delete files.
public protocol ScanEngine: Sendable {
    var id: EngineID { get }
    var displayName: String { get }
    func availability() async -> EngineAvailability
    func handles(_ item: ScanItem) -> Bool
    func scan(_ items: [ScanItem], context: ScanContext, events: @escaping EngineEventSink) async throws
}
