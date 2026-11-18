import Foundation
import Testing
@testable import MacScanCore

/// Stands in for the password prompt: runs the launcher's shell command (whose executable is a stub
/// that records its arguments), then runs the real worker in-process with those arguments, as the
/// current user. No password, no root.
final class InProcessWorkerRunner: AdminRunner, @unchecked Sendable {
    let argsFile: URL
    var cancel = false

    init(argsFile: URL) { self.argsFile = argsFile }

    func run(script: String, prompt: String) async throws -> String {
        if cancel { throw UninstallError.adminCancelled }
        _ = try await ProcessRunner.run(URL(fileURLWithPath: "/bin/sh"), ["-c", script])
        let lines = try String(contentsOf: argsFile, encoding: .utf8).split(separator: "\n").map(String.init)
        guard lines.first == ElevatedScanWorker.flag else { throw UninstallError.adminFailed("worker flag missing") }
        let args = Array(lines.dropFirst())
        let status = await withCheckedContinuation { (c: CheckedContinuation<Int32, Never>) in
            Thread.detachNewThread { c.resume(returning: ElevatedScanWorker.main(arguments: args)) }
        }
        if status != 0 { throw UninstallError.adminFailed("worker exit \(status)") }
        return ""
    }
}

@Suite struct ElevatedScanTests {
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))

    /// A stub "executable" that writes each argument on its own line.
    func makeStub(in dir: TempDir) throws -> (exe: URL, argsFile: URL) {
        let argsFile = dir.url.appendingPathComponent("args.txt")
        let exe = try dir.write("stub.sh", "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '\(argsFile.path)'; done\n")
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: exe.path)
        return (exe, argsFile)
    }

    @Test func requestRoundTripsAndResolvesHomePaths() throws {
        var settings = ScanSettings()
        settings.excludedPaths = ["~/Library/Caches"]
        settings.yaraRulesFolder = "~/Rules"
        let request = ElevatedScanRequest.make(targets: [.startupItems, .path(URL(fileURLWithPath: "/tmp/x"))], settings: settings, ignoreList: IgnoreList())

        let home = FileManager.default.homeDirectoryForCurrentUser.path
        #expect(request.settings.excludedPaths == [home + "/Library/Caches"])
        #expect(request.settings.yaraRulesFolder == home + "/Rules")
        #expect(request.settings.clamDatabasePath?.isEmpty == false)
        #expect(request.userHome == AppPaths.home.path)
        #expect(request.appPID == getpid())
        #expect(try ElevatedScanRequest.decode(request.encoded()) == request)
    }

    @Test func eventsRoundTripThroughTheFile() throws {
        let dir = try TempDir()
        let url = dir.url.appendingPathComponent("events.jsonl")
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL, 0o644)
        let writer = EventWriter(fd: fd)
        let tail = EventTail(url: url)
        let progress = ScanProgress(phase: .scanning, itemsDone: 3, itemsTotal: 9, currentFile: "/a\nb")
        writer.send(.progress(progress))
        writer.send(.log(.warning, "hello"))
        #expect(tail.readNew() == [.progress(progress), .log(.warning, "hello")])
        #expect(tail.readNew().isEmpty)
        var session = ScanSession(targets: ["T"])
        session.findings = [Finding(path: "/x", severity: .threat, engine: .clamav, reason: "r", unitPath: "/x")]
        writer.send(.finished(session))
        writer.close()
        guard case .finished(let decoded) = tail.readNew().first else { Issue.record("no finished event"); return }
        #expect(decoded.findings.map(\.id) == session.findings.map(\.id))  // dates lose sub-second precision (ISO 8601), as in history
        #expect(decoded.id == session.id)
    }

    @Test func workerRefusesAPlantedEventsFile() throws {
        let dir = try TempDir()
        try FileManager.default.createSymbolicLink(atPath: dir.url.appendingPathComponent("events.jsonl").path, withDestinationPath: "/tmp/should-not-be-written")
        let request = ElevatedScanRequest.make(targets: [], settings: ScanSettings(), ignoreList: IgnoreList())
        #expect(ElevatedScanWorker.main(arguments: [try request.encoded(), dir.url.path]) == 73)
        #expect(ElevatedScanWorker.main(arguments: ["not base64!", dir.url.path]) == 64)
    }

    @Test func cancelledPasswordPromptThrows() async throws {
        let dir = try TempDir()
        let stub = try makeStub(in: dir)
        let runner = InProcessWorkerRunner(argsFile: stub.argsFile)
        runner.cancel = true
        let request = ElevatedScanRequest.make(targets: [.path(dir.url)], settings: ScanSettings(), ignoreList: IgnoreList())
        await #expect(throws: ElevatedScanError.passwordCancelled) {
            _ = try await ElevatedScanLauncher(executable: stub.exe, admin: runner).run(request, logger: logger) { _ in }
        }
    }

    @Test func launcherRunsTheWorkerAndReturnsItsSession() async throws {
        let dir = try TempDir()
        let stub = try makeStub(in: dir)
        let target = try TempDir()
        try target.makeApp("Demo")

        var settings = ScanSettings()
        settings.enableClamAV = false
        settings.enableYara = false
        settings.enableIntegrity = true
        let request = ElevatedScanRequest.make(targets: [.path(target.url)], settings: settings, ignoreList: IgnoreList())

        let progress = ProgressLog()
        let session = try await ElevatedScanLauncher(executable: stub.exe, admin: InProcessWorkerRunner(argsFile: stub.argsFile))
            .run(request, logger: logger) { progress.append($0) }

        #expect(session.status == .completed)
        #expect(session.enginesUsed.contains(.integrity))
        #expect(session.itemsTotal > 0)
        #expect(session.findings.contains { $0.unitPath.hasSuffix("Demo.app") })
        #expect(!progress.values.isEmpty)
    }

    /// Mach-O files so the integrity engine has real per-file work (a scan that takes a moment).
    func makeSlowTarget() throws -> TempDir {
        let target = try TempDir()
        for i in 0..<150 { _ = try target.copy("/usr/bin/true", to: "bin/tool\(i)") }
        return target
    }

    func integrityOnly() -> ScanSettings {
        var settings = ScanSettings()
        settings.enableClamAV = false
        settings.enableYara = false
        settings.enableIntegrity = true
        return settings
    }

    /// Runs the worker on its own thread and returns the session from its `finished` event.
    func runWorker(_ request: ElevatedScanRequest, in dir: TempDir) async throws -> ScanSession {
        let args = [try request.encoded(), dir.url.path]
        let status = await withCheckedContinuation { (c: CheckedContinuation<Int32, Never>) in
            Thread.detachNewThread { c.resume(returning: ElevatedScanWorker.main(arguments: args)) }
        }
        #expect(status == 0)
        let events = EventTail(url: dir.url.appendingPathComponent(ElevatedScanCoding.eventsFileName)).readNew()
        for case .finished(let session) in events { return session }
        throw ElevatedScanError.failed("no finished event")
    }

    @Test func workerStopsWhenCancelFileAppears() async throws {
        let target = try makeSlowTarget()
        let dir = try TempDir()
        // The app cancelled while the password prompt was still open.
        FileManager.default.createFile(atPath: dir.url.appendingPathComponent(ElevatedScanCoding.cancelFileName).path, contents: nil)
        let request = ElevatedScanRequest.make(targets: [.path(target.url)], settings: integrityOnly(), ignoreList: IgnoreList())
        let session = try await runWorker(request, in: dir)
        #expect(session.status == .cancelled)
        #expect(session.itemsScanned < session.itemsTotal, "stopped early, partial counts kept")
    }

    @Test func workerStopsWhenTheAppIsGone() async throws {
        let target = try makeSlowTarget()
        let dir = try TempDir()
        // A process that has already exited stands in for an app that quit or crashed.
        let gone = Process()
        gone.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try gone.run()
        gone.waitUntilExit()
        var request = ElevatedScanRequest.make(targets: [.path(target.url)], settings: integrityOnly(), ignoreList: IgnoreList())
        request.appPID = gone.processIdentifier
        let session = try await runWorker(request, in: dir)
        #expect(session.status == .cancelled)
    }

    @Test func oversizedRequestFailsClearly() throws {
        let finding = Finding(path: String(repeating: "/very/long/path", count: 40), severity: .warning, engine: .integrity, reason: "r", unitPath: "/x")
        let request = ElevatedScanRequest.make(targets: [], settings: ScanSettings(),
                                               ignoreList: IgnoreList(entries: Array(repeating: IgnoreEntry(finding: finding), count: 1_000)))
        #expect(throws: ElevatedScanError.self) { try request.encoded() }
        let small = ElevatedScanRequest.make(targets: [], settings: ScanSettings(), ignoreList: IgnoreList(entries: [IgnoreEntry(finding: finding)]))
        #expect(try small.encoded().count < ElevatedScanRequest.maxEncodedLength)
    }
}
