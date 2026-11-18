import Foundation
import Testing
@testable import MacScanCore

struct FakeProcessList: ProcessListing {
    var processes: [LiveProcess]
    func runningProcesses() -> [LiveProcess] { processes }
}

@Suite struct ProcessScanTests {
    let scanner = ProcessScanner(lister: FakeProcessList(processes: []), home: URL(fileURLWithPath: "/Users/me"))
    let signed = SigningStatus.signed(identifier: "com.example.x", teamID: "ABCDE12345", authority: "Developer ID Application: Example")

    func reasons(_ path: String, _ status: SigningStatus, root: Bool = false) -> [String] {
        scanner.problems(path: path, status: status, runsAsRoot: root).map { "\($0.0.rawValue): \($0.1)" }
    }

    @Test func signatureRules() {
        let app = "/Applications/X.app/Contents/MacOS/X"
        #expect(reasons(app, signed).isEmpty)
        #expect(reasons(app, signed, root: true).isEmpty)
        #expect(reasons(app, .unsigned) == ["warning: Running program isn't code signed"])
        #expect(reasons(app, .unsigned, root: true) == ["threat: Running as root, but isn't signed by a trusted developer"])
        #expect(reasons(app, .selfSigned(identifier: nil, authority: "x")).first?.hasPrefix("threat") == true)
        #expect(reasons(app, .selfSigned(identifier: nil, authority: "x"), root: true).first?.hasPrefix("threat") == true)
        // Ad-hoc: fine for the user's own tools, a warning as root, expected for Homebrew.
        #expect(reasons("/Users/me/project/target/debug/tool", .adhoc(identifier: nil)).isEmpty)
        #expect(reasons("/usr/local/bin/tool", .adhoc(identifier: nil), root: true) == ["warning: Running as root with an ad-hoc signed program"])
        #expect(reasons("/opt/homebrew/Cellar/redis/8.0/bin/redis-server", .adhoc(identifier: nil), root: true).isEmpty)
    }

    @Test func locationRules() {
        let adhoc = SigningStatus.adhoc(identifier: nil)
        #expect(reasons("/Users/me/Downloads/Tool.app/Contents/MacOS/Tool", adhoc) == ["warning: Untrusted program running from the Downloads folder"])
        #expect(reasons("/private/tmp/x", adhoc) == ["warning: Untrusted program running from a temporary or shared folder"])
        #expect(reasons("/Users/Shared/x", .unsigned).count == 2)
        #expect(reasons("/Users/me/.hidden/agent", adhoc) == ["warning: Untrusted program running from a hidden folder"])
        // Known tool homes are not "hidden" in the suspicious sense.
        #expect(reasons("/Users/me/.cargo/bin/tool", adhoc).isEmpty)
        #expect(reasons("/Users/me/.vscode/extensions/a/server", adhoc).isEmpty)
        // Signed programs are not flagged for where they run: macOS itself runs signed apps from temporary
        // folders (App Translocation, Chrome's code-sign clone, iPhone app wrappers).
        #expect(reasons("/Users/me/Downloads/Tool.app/Contents/MacOS/Tool", signed).isEmpty)
        #expect(reasons("/private/var/folders/ab/X/com.google.Chrome.code_sign_clone/c/Google Chrome.app.bundle/Contents/MacOS/Google Chrome", signed).isEmpty)
        #expect(reasons("/private/var/folders/ab/T/AppTranslocation/1234/d/Tool.app/Contents/MacOS/Tool", signed).isEmpty)
        let process = LiveProcess(pid: 9, uid: 501, name: "x", path: "/private/tmp/x")
        #expect(scanner.finding(path: "/private/tmp/x", processes: [process], status: signed, nameOf: [:]).detail?.contains("Location: runs from a temporary or shared folder") == true)
    }

    @Test func sealedSystemPaths() {
        #expect(ProcessScanner.isSealedSystemPath("/usr/libexec/trustd"))
        #expect(ProcessScanner.isSealedSystemPath("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"))
        #expect(!ProcessScanner.isSealedSystemPath("/usr/local/bin/tool"))
        #expect(!ProcessScanner.isSealedSystemPath("/System/Volumes/Data/Users/me/tool"))
        #expect(!ProcessScanner.isSealedSystemPath("/Library/Apple/usr/libexec/oah/x"))
    }

    @Test func impersonationBySigningIdentifier() {
        let process = LiveProcess(pid: 10, uid: 501, name: "Chrome", path: "/Applications/Fake.app/Contents/MacOS/Chrome")
        let finding = scanner.finding(path: process.path!, processes: [process], status: .adhoc(identifier: "com.google.Chrome"), nameOf: [:])
        #expect(finding.severity == .threat)
        #expect(finding.reason.contains("Claims to be Google software"))
        #expect(finding.engine == .processes)
    }

    @Test func inventoryGroupsListsAndSkipsSystemSoftware() throws {
        let dir = try TempDir()
        let unsigned = try dir.copy("/usr/bin/true", to: "bin/unsigned-tool")
        try shell("/usr/bin/codesign", ["--remove-signature", unsigned.path])
        let gone = dir.url.appendingPathComponent("bin/gone").path
        let uid = getuid()

        let list = FakeProcessList(processes: [
            LiveProcess(pid: 1, parentPID: 0, uid: 0, name: "launchd", path: "/sbin/launchd"),
            LiveProcess(pid: 50, uid: uid, name: "true", path: "/usr/bin/true"),
            LiveProcess(pid: 100, uid: 0, name: "unsigned-tool", path: unsigned.path),
            LiveProcess(pid: 101, parentPID: 100, uid: uid, name: "unsigned-tool", path: unsigned.path),
            LiveProcess(pid: 200, uid: uid, name: "ghost", path: nil, executableDeleted: true),
            LiveProcess(pid: 201, uid: uid, name: "gone", path: nil, executableDeleted: true, launchPath: gone),
            LiveProcess(pid: 202, uid: uid, name: "true", path: nil, executableDeleted: true, launchPath: "/usr/bin/true"),
            LiveProcess(pid: 300, uid: 0, name: "hidden", path: nil),
        ])
        let inv = try ProcessScanner(lister: list, home: dir.url).collect()
        func finding(_ path: String) -> Finding? { inv.findings.first { $0.path == path } }

        // System software on the sealed volume is counted, not listed.
        #expect(finding("/sbin/launchd") == nil)
        #expect(inv.notes.first?.contains("8 running, 4 programs listed") == true)
        #expect(inv.notes.first?.contains("The 2 that are Apple system software") == true)
        #expect(inv.notes.contains { $0.hasPrefix("1 process couldn't be inspected") })

        // Two processes of one program are one row; root + unsigned is a threat.
        let tool = try #require(finding(unsigned.path))
        #expect(tool.severity == .threat)
        #expect(tool.reason.hasPrefix("Running as root, but isn't signed by a trusted developer"))
        #expect(tool.detail?.contains("Running now: 2 processes (PID 100, 101)") == true)
        #expect(tool.detail?.contains("User: root") == true)
        #expect(tool.detail?.contains("Started by: launchd") == true)
        #expect(inv.programPaths == [unsigned.path, "/usr/bin/true"] || inv.programPaths == ["/usr/bin/true", unsigned.path])

        // Deleted program files.
        #expect(finding("ghost")?.reason == ProcessScanner.deletedReason)
        #expect(finding(gone)?.severity == .warning)
        #expect(finding(gone)?.detail?.contains("Started from: \(gone)") == true)
        let updated = try #require(finding("/usr/bin/true"))
        #expect(updated.severity == .clean)
        #expect(updated.reason == "Running an older copy (the app was updated while running)")
        #expect(inv.findings.allSatisfy { $0.engine == .processes })
    }

    @Test func systemListSeesARealProcessAndItsDeletedFile() async throws {
        let dir = try TempDir()
        let tool = try dir.copy("/bin/sleep", to: "sleeper")
        try shell("/usr/bin/codesign", ["--force", "--sign", "-", tool.path])
        let process = Process()
        process.executableURL = tool
        process.arguments = ["30"]
        try process.run()
        defer { process.terminate() }
        try await Task.sleep(for: .milliseconds(300))
        try #require(process.isRunning, "an ad-hoc signed copy of /bin/sleep should run")

        let running = try #require(SystemProcessList().runningProcesses().first { $0.pid == process.processIdentifier })
        #expect(running.path == tool.path)
        #expect(running.uid == getuid())
        #expect(running.parentPID == getpid())
        #expect(running.name == "sleeper")
        #expect(!running.executableDeleted)

        try FileManager.default.removeItem(at: tool)
        let after = try #require(SystemProcessList().runningProcesses().first { $0.pid == process.processIdentifier })
        #expect(after.path == nil)
        #expect(after.executableDeleted)
        // As passed to exec, so /var/… rather than /private/var/….
        #expect(after.launchPath?.hasSuffix("/" + dir.url.lastPathComponent + "/sleeper") == true)

        // The real table always has launchd, and never a path-less entry that isn't accounted for.
        #expect(SystemProcessList().runningProcesses().contains { $0.pid == 1 && $0.path == "/sbin/launchd" && $0.uid == 0 })
    }

    @Test func coordinatorIntegratesRunningProcesses() async throws {
        let dir = try TempDir()
        let unsigned = try dir.copy("/usr/bin/true", to: "bin/unsigned-tool")
        try shell("/usr/bin/codesign", ["--remove-signature", unsigned.path])
        let app = try dir.makeApp("Runner")
        let appBinary = app.appendingPathComponent("Contents/MacOS/Runner")
        let list = FakeProcessList(processes: [
            LiveProcess(pid: 50, uid: getuid(), name: "true", path: "/usr/bin/true"),
            LiveProcess(pid: 100, uid: getuid(), name: "unsigned-tool", path: unsigned.path),
            LiveProcess(pid: 101, uid: getuid(), name: "Runner", path: appBinary.path),
        ])
        var settings = ScanSettings()
        settings.enableClamAV = false
        settings.enableYara = false
        let coordinator = ScanCoordinator(
            engines: EngineFactory.makeEngines(settings: settings), settings: settings,
            logger: FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs")),
            processLister: list)
        let session = await coordinator.run(targets: [.runningProcesses]) { _ in }

        #expect(session.targets == ["Running Processes"])
        #expect(session.enginesUsed.contains(.processes))
        #expect(session.notes.contains { $0.hasPrefix("Running processes: 3 running, 2 programs listed") })
        let tool = session.findings.filter { $0.path == unsigned.path }
        // One row for the program: the integrity engine's "Unsigned executable" duplicate is dropped.
        #expect(tool.map(\.engine) == [.processes])
        #expect(tool.first?.severity == .warning)
        // The app a process belongs to still gets its bundle-level integrity check.
        #expect(session.findings.contains { $0.engine == .integrity && $0.path == app.path })
        #expect(session.findings.contains { $0.engine == .processes && $0.path == appBinary.path })
        #expect(!session.findings.contains { $0.engine == .scanner })
        #expect(session.itemsTotal == 3)   // two executables + the app bundle
    }
}
