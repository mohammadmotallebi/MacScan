import Foundation
import os

// Elevated scans: after asking for an administrator password once, the app runs a copy of its own
// executable as root in a headless "worker" mode (`ElevatedScanWorker`). The worker runs the normal
// `ScanCoordinator` and streams events as JSON lines into a file in a per-scan directory that the app
// tails (`ElevatedScanLauncher`). The worker exits when the scan ends, so nothing stays running as root.
//
// Root can read files owned by other users and the system. It does NOT bypass privacy protection (TCC)
// or SIP: Mail, Safari, Messages, etc. still need Full Disk Access granted to MacScan.

/// What the app hands the root worker. It travels base64-encoded on the worker's command line, not
/// through a file, so other processes can't change it between the password prompt and the scan.
public struct ElevatedScanRequest: Codable, Sendable, Equatable {
    public var targets: [ScanTarget]
    public var settings: ScanSettings
    public var ignoreList: IgnoreList
    public var userHome: String
    public var userName: String
    /// The app's process ID. The worker stops if the app goes away.
    public var appPID: Int32

    public init(targets: [ScanTarget], settings: ScanSettings, ignoreList: IgnoreList, userHome: String, userName: String, appPID: Int32) {
        self.targets = targets
        self.settings = settings
        self.ignoreList = ignoreList
        self.userHome = userHome
        self.userName = userName
        self.appPID = appPID
    }

    /// Builds a request for the current user. Everything that depends on the home folder (tool paths,
    /// the ClamAV database, the rules folder, `~` in exclusions) is resolved here, because as root
    /// `~` would mean /var/root and MacScan must not create root-owned folders in the user's Library.
    public static func make(targets: [ScanTarget], settings: ScanSettings, ignoreList: IgnoreList) -> ElevatedScanRequest {
        func expand(_ path: String?) -> String? {
            guard let path, !path.isEmpty else { return path }
            return (path as NSString).expandingTildeInPath
        }
        var s = settings
        s.clamscanPath = ToolLocator.locate(.clamscan, override: s.clamscanPath)?.path ?? expand(s.clamscanPath)
        s.yaraPath = ToolLocator.locate(.yara, override: s.yaraPath)?.path ?? expand(s.yaraPath)
        s.yaracPath = ToolLocator.locate(.yarac, override: s.yaracPath)?.path ?? expand(s.yaracPath)
        s.clamDatabasePath = ClamAVDatabase.resolve(override: s.clamDatabasePath).path
        s.yaraRulesFolder = expand(s.yaraRulesFolder)
        s.excludedPaths = s.excludedPaths.map { ($0 as NSString).expandingTildeInPath }
        return ElevatedScanRequest(
            targets: targets,
            settings: s,
            ignoreList: ignoreList,
            userHome: AppPaths.home.path,
            userName: AppPaths.userName,
            appPID: getpid()
        )
    }

    /// Upper bound for the encoded request. macOS limits a command line (plus environment) to 1 MB;
    /// staying well below that avoids an obscure "argument list too long" from the password step.
    static let maxEncodedLength = 512 * 1024

    public func encoded() throws -> String {
        let text = try ElevatedScanCoding.encoder.encode(self).base64EncodedString()
        guard text.utf8.count <= Self.maxEncodedLength else {
            throw ElevatedScanError.failed("The scan settings are too large to hand to the administrator scan (\(ignoreList.entries.count) ignored results). Remove some entries in Settings › Ignored, or scan without administrator rights.")
        }
        return text
    }

    public static func decode(_ base64: String) throws -> ElevatedScanRequest {
        guard let data = Data(base64Encoded: base64) else { throw ElevatedScanError.failed("Malformed scan request") }
        return try ElevatedScanCoding.decoder.decode(ElevatedScanRequest.self, from: data)
    }
}

/// One line of the worker's event stream.
public enum ElevatedScanEvent: Codable, Sendable, Equatable {
    case progress(ScanProgress)
    case log(FileLogger.Level, String)
    case finished(ScanSession)
}

public enum ElevatedScanError: Error, LocalizedError, Equatable {
    case passwordCancelled
    case failed(String)

    public var errorDescription: String? {
        switch self {
        case .passwordCancelled: "The administrator password prompt was cancelled, so the scan did not run."
        case .failed(let message): "The administrator scan failed: \(message)"
        }
    }
}

enum ElevatedScanCoding {
    static let eventsFileName = "events.jsonl"
    static let cancelFileName = "cancel"

    static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.withoutEscapingSlashes]   // one event per line: never pretty-print
        return e
    }

    static var decoder: JSONDecoder { JSONDecoder.macScan }
}

// MARK: - Worker (runs as root)

public enum ElevatedScanWorker {
    /// First argument that switches the MacScan executable into worker mode.
    public static let flag = "--macscan-elevated-scan"

    /// Arguments after `flag`: `<base64 request> <scan directory>`. Returns the process exit code.
    public static func main(arguments: [String]) -> Int32 {
        guard arguments.count == 2, let request = try? ElevatedScanRequest.decode(arguments[0]) else { return 64 }
        let directory = URL(fileURLWithPath: arguments[1], isDirectory: true)

        // O_EXCL | O_NOFOLLOW: never follow or overwrite something planted at this path.
        let path = directory.appendingPathComponent(ElevatedScanCoding.eventsFileName).path
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard fd >= 0 else { return 73 }
        let writer = EventWriter(fd: fd)
        defer { writer.close() }

        AppPaths.setTargetUser(home: URL(fileURLWithPath: request.userHome, isDirectory: true), name: request.userName)

        let done = DispatchSemaphore(value: 0)
        Task.detached {
            await run(request, directory: directory, writer: writer)
            done.signal()
        }
        done.wait()
        return 0
    }

    static func run(_ request: ElevatedScanRequest, directory: URL, writer: EventWriter) async {
        let logger = FileLogger(forwardingTo: { level, message in writer.send(.log(level, message)) })
        logger.info("Administrator scan running as uid \(getuid()) for \(request.userName)")
        let coordinator = ScanCoordinator(
            engines: EngineFactory.makeEngines(settings: request.settings),
            lookupEngine: nil,
            settings: request.settings,
            ignoreList: request.ignoreList,
            logger: logger
        )
        let scan = Task {
            await coordinator.run(targets: request.targets) { writer.send(.progress($0)) }
        }
        let cancelPath = directory.appendingPathComponent(ElevatedScanCoding.cancelFileName).path
        let watcher = Task {
            while !Task.isCancelled {
                if FileManager.default.fileExists(atPath: cancelPath) || !isAlive(request.appPID) {
                    scan.cancel()
                    return
                }
                try? await Task.sleep(for: .milliseconds(300))
            }
        }
        let session = await scan.value
        watcher.cancel()
        writer.send(.finished(session))
    }

    static func isAlive(_ pid: Int32) -> Bool {
        pid <= 0 || kill(pid, 0) == 0 || errno == EPERM
    }
}

/// Writes events as JSON lines to a file descriptor, from any thread.
final class EventWriter: Sendable {
    private let fd: OSAllocatedUnfairLock<Int32>

    init(fd: Int32) { self.fd = OSAllocatedUnfairLock(initialState: fd) }

    func send(_ event: ElevatedScanEvent) {
        guard var encoded = try? ElevatedScanCoding.encoder.encode(event) else { return }
        encoded.append(0x0A)
        let data = encoded
        fd.withLock { fd in
            guard fd >= 0 else { return }
            data.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                    if n <= 0 { if errno == EINTR { continue }; return }
                    offset += n
                }
            }
        }
    }

    func close() {
        fd.withLock { fd in
            if fd >= 0 { Darwin.close(fd) }
            fd = -1
        }
    }
}

// MARK: - Launcher (runs in the app)

/// Starts the root worker behind one administrator password prompt and relays its events.
public struct ElevatedScanLauncher: Sendable {
    let executable: URL
    let admin: any AdminRunner

    public init(executable: URL, admin: any AdminRunner = OsascriptAdminRunner()) {
        self.executable = executable
        self.admin = admin
    }

    static let prompt = "MacScan wants to scan as administrator so it can read files owned by other users and the system."

    /// Runs the scan and returns the worker's session. Task cancellation asks the worker to stop and
    /// still returns its partial session. Throws `ElevatedScanError`.
    public func run(
        _ request: ElevatedScanRequest,
        logger: FileLogger = .shared,
        onProgress: @escaping @Sendable (ScanProgress) -> Void
    ) async throws -> ScanSession {
        let directory = try AppPaths.makeTemporaryDirectory()
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        defer { try? FileManager.default.removeItem(at: directory) }

        let script = [
            Uninstaller.shellQuote(executable.path),
            ElevatedScanWorker.flag,
            Uninstaller.shellQuote(try request.encoded()),
            Uninstaller.shellQuote(directory.path),
            ">/dev/null 2>&1",
        ].joined(separator: " ")

        // Detached on purpose: cancelling the scan must not kill osascript. That would orphan the root
        // worker and lose its partial results. Cancellation goes through the cancel file instead.
        let admin = admin
        let outcome = OSAllocatedUnfairLock<Result<String, Error>?>(initialState: nil)
        Task.detached {
            let result: Result<String, Error>
            do { result = .success(try await admin.run(script: script, prompt: Self.prompt)) } catch { result = .failure(error) }
            outcome.withLock { $0 = result }
        }

        let cancelURL = directory.appendingPathComponent(ElevatedScanCoding.cancelFileName)
        let tail = EventTail(url: directory.appendingPathComponent(ElevatedScanCoding.eventsFileName))
        var session: ScanSession?
        let result: Result<String, Error> = await withTaskCancellationHandler {
            while true {
                let finished = outcome.withLock { $0 }
                for event in tail.readNew() {
                    switch event {
                    case .progress(let p): onProgress(p)
                    case .log(let level, let message): logger.log(level, "[admin scan] " + message)
                    case .finished(let s): session = s
                    }
                }
                if let finished { return finished }
                await Self.pause(milliseconds: 150)
            }
        } onCancel: {
            FileManager.default.createFile(atPath: cancelURL.path, contents: nil)
        }

        if let session { return session }
        switch result {
        case .failure(UninstallError.adminCancelled):
            throw ElevatedScanError.passwordCancelled
        case .failure(UninstallError.adminFailed(let message)):
            throw ElevatedScanError.failed(message.isEmpty ? "unknown error" : message)
        case .failure(let error):
            throw ElevatedScanError.failed(error.localizedDescription)
        case .success:
            throw ElevatedScanError.failed("The scan stopped without reporting results.")
        }
    }

    /// A sleep that ignores Task cancellation (the loop must keep draining after a cancel).
    static func pause(milliseconds: Int) async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(milliseconds)) { c.resume() }
        }
    }
}

/// Reads complete JSON lines appended to a file since the last call.
final class EventTail {
    private let url: URL
    private var handle: FileHandle?
    private var buffer = Data()

    init(url: URL) { self.url = url }

    deinit { try? handle?.close() }

    func readNew() -> [ElevatedScanEvent] {
        if handle == nil { handle = try? FileHandle(forReadingFrom: url) }
        guard let handle, let data = try? handle.readToEnd(), !data.isEmpty else { return [] }
        buffer.append(data)
        var events: [ElevatedScanEvent] = []
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer[buffer.startIndex..<newline]
            buffer.removeSubrange(buffer.startIndex...newline)
            if let event = try? ElevatedScanCoding.decoder.decode(ElevatedScanEvent.self, from: Data(line)) {
                events.append(event)
            }
        }
        return events
    }
}
