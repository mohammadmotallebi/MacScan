import Foundation
import Testing
@testable import MacScanCore

@Suite struct AppIntegrityEngineTests {
    let engine = AppIntegrityEngine()
    let codesign = "/usr/bin/codesign"

    @Test func appleSignedBinaryIsSigned() {
        let status = CodeSigning.status(of: URL(fileURLWithPath: "/usr/bin/true"))
        guard case .signed = status else {
            Issue.record("Expected /usr/bin/true to be signed, got \(status)")
            return
        }
    }

    @Test func detectsAdhocAndUnsignedExecutables() async throws {
        let dir = try TempDir()
        let adhoc = try dir.copy("/usr/bin/true", to: "adhoc-tool")
        try shell(codesign, ["--force", "--sign", "-", adhoc.path])
        let unsigned = try dir.copy("/usr/bin/true", to: "unsigned-tool")
        try shell(codesign, ["--remove-signature", unsigned.path])

        #expect(CodeSigning.status(of: adhoc).isUnsignedOrAdhoc)
        #expect(CodeSigning.status(of: unsigned) == .unsigned)

        let items = [adhoc, unsigned].map { ScanItem(url: $0, kind: .file, isMachO: true) }
        let recorder = EventRecorder()
        try await engine.scan(items, context: .test, events: recorder.sink)

        let findings = await recorder.findings
        #expect(findings.count == 2)
        #expect(findings.first { $0.path == adhoc.path }?.reason == "Ad-hoc signed executable")
        #expect(findings.first { $0.path == unsigned.path }?.reason == "Unsigned executable")
        #expect(findings.allSatisfy { $0.severity == .warning && $0.engine == .integrity })
        #expect(Set(await recorder.finished) == Set(items.map(\.path)))
    }

    @Test func adhocBundleIsFlaggedOnceAtBundleLevel() async throws {
        let dir = try TempDir()
        let app = try dir.makeApp("AdhocDemo")
        try shell(codesign, ["--force", "--deep", "--sign", "-", app.path])

        let exe = app.appendingPathComponent("Contents/MacOS/AdhocDemo")
        let items = [
            ScanItem(url: app, kind: .appBundle, bundleURL: app),
            ScanItem(url: exe, kind: .file, isMachO: true, bundleURL: app),
        ]
        let recorder = EventRecorder()
        try await engine.scan(items, context: .test, events: recorder.sink)
        let findings = await recorder.findings

        // Bundle: ad-hoc + Gatekeeper rejection. No duplicate warning for the main executable.
        #expect(findings.allSatisfy { $0.path == app.path })
        #expect(findings.contains { $0.reason == "App is ad-hoc signed" })
        #expect(findings.contains { $0.reason == "Gatekeeper would block this app" })
        #expect(!findings.contains { $0.severity == .clean })
    }

    /// Builds an app shaped like the launcher a Chromium browser creates for an installed website.
    func makeShortcut(in dir: TempDir, name: String, bundleID: String, sign: Bool = true) throws -> URL {
        let app = dir.url.appendingPathComponent("\(name).app")
        let macos = app.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: macos.appendingPathComponent("app_mode_loader").path)
        let plist: [String: Any] = ["CFBundleExecutable": "app_mode_loader", "CFBundleIdentifier": bundleID, "CFBundleName": name, "CFBundlePackageType": "APPL"]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: app.appendingPathComponent("Contents/Info.plist"))
        if sign { try shell(codesign, ["--force", "--deep", "--sign", "-", app.path]) }
        return app
    }

    @Test func webAppShortcutBundleIDs() {
        let id = "agimnkijcaahngcdmfeangaknmldooml"
        #expect(WebAppShortcut.browser(forBundleID: "com.google.Chrome.app.\(id)") == "Chrome")
        #expect(WebAppShortcut.browser(forBundleID: "com.microsoft.edgemac.app.\(id)") == "Edge")
        #expect(WebAppShortcut.browser(forBundleID: "com.brave.Browser.app.\(id)") == "Brave")
        #expect(WebAppShortcut.browser(forBundleID: "com.google.Chrome") == nil)
        #expect(WebAppShortcut.browser(forBundleID: "com.google.Chrome.app.short") == nil)
        #expect(WebAppShortcut.browser(forBundleID: "com.google.Chrome.app.\(id.dropLast())z") == nil, "extension IDs use a to p only")
        #expect(WebAppShortcut.browser(forBundleID: "com.google.Chrome.helper.\(id)") == nil)
    }

    @Test func chromeWebAppShortcutIsCleanNotImpersonation() async throws {
        let dir = try TempDir()
        let bundleID = "com.google.Chrome.app.agimnkijcaahngcdmfeangaknmldooml"
        let app = try makeShortcut(in: dir, name: "YouTube", bundleID: bundleID)
        let findings = try await engine.checkBundle(app, context: .test)
        #expect(findings.count == 1)
        #expect(findings.first?.severity == .clean)
        #expect(findings.first?.reason == "Chrome web-app shortcut (signed on this Mac by Chrome)")
        #expect(findings.first?.detail?.contains(bundleID) == true)

        // A running shortcut isn't an impersonation threat either.
        let loader = app.appendingPathComponent("Contents/MacOS/app_mode_loader").path
        #expect(WebAppShortcut.browser(ofProgram: loader, status: CodeSigning.status(of: URL(fileURLWithPath: loader))) == "Chrome")
    }

    /// Everything that only looks like a shortcut keeps its Threat.
    @Test func lookalikeShortcutsAreStillThreats() async throws {
        let dir = try TempDir()
        let bundleID = "com.google.Chrome.app.agimnkijcaahngcdmfeangaknmldooml"
        let impersonation = "Claims to be Google software but isn't signed by Google"

        // A second program next to the loader.
        let extra = try makeShortcut(in: dir, name: "Extra", bundleID: bundleID, sign: false)
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: extra.appendingPathComponent("Contents/MacOS/payload").path)
        try shell(codesign, ["--force", "--deep", "--sign", "-", extra.path])
        #expect(try await engine.checkBundle(extra, context: .test).contains { $0.severity == .threat && $0.reason == impersonation })

        // Changed after it was signed.
        let tampered = try makeShortcut(in: dir, name: "Tampered", bundleID: bundleID)
        try "added".write(to: tampered.appendingPathComponent("Contents/Resources/extra.txt"), createDirs: true)
        let tamperedFindings = try await engine.checkBundle(tampered, context: .test)
        #expect(tamperedFindings.contains { $0.severity == .threat && $0.reason == impersonation })
        #expect(!tamperedFindings.contains { $0.severity == .clean })

        // Not signed at all.
        let unsigned = try makeShortcut(in: dir, name: "Unsigned", bundleID: bundleID, sign: false)
        try shell(codesign, ["--remove-signature", unsigned.appendingPathComponent("Contents/MacOS/app_mode_loader").path])
        #expect(try await engine.checkBundle(unsigned, context: .test).contains { $0.severity == .threat && $0.reason == impersonation })

        // The main Chrome ID, not a web-app ID.
        let fake = try makeShortcut(in: dir, name: "Fake", bundleID: "com.google.Chrome")
        #expect(try await engine.checkBundle(fake, context: .test).contains { $0.severity == .threat && $0.reason == impersonation })
    }

    @Test func tamperedBundleFailsVerification() async throws {
        let dir = try TempDir()
        let app = try dir.makeApp("Tampered")
        try shell(codesign, ["--force", "--deep", "--sign", "-", app.path])
        // Modify a sealed resource after signing.
        try "changed".write(to: app.appendingPathComponent("Contents/Resources/readme.txt"), atomically: true, encoding: .utf8)

        let findings = try await engine.checkBundle(app, context: .test)
        let invalid = try #require(findings.first { $0.reason.hasPrefix("Code signature invalid") })
        #expect(invalid.reason.contains("sealed resource"))
        #expect(invalid.detail?.contains("changed, added or removed") == true)
    }

    @Test func unsignedBundle() async throws {
        let dir = try TempDir()
        let app = try dir.makeApp("NoSig")
        try shell(codesign, ["--remove-signature", app.appendingPathComponent("Contents/MacOS/NoSig").path])
        let findings = try await engine.checkBundle(app, context: .test)
        #expect(findings.contains { $0.reason == "App is not code signed" })
    }

    @Test func systemAppIsClean() async throws {
        let calculator = URL(fileURLWithPath: "/System/Applications/Calculator.app")
        guard FileManager.default.fileExists(atPath: calculator.path) else { return }
        let findings = try await engine.checkBundle(calculator, context: .test)
        #expect(findings.count == 1)
        #expect(findings.first?.severity == .clean)
    }

    @Test func quarantineParsing() throws {
        let q = try #require(QuarantineInfo.parse("0083;65f1a2b3;Safari;1234-ABCD"))
        #expect(q.agent == "Safari")
        #expect(q.userApproved == false)
        #expect(q.date != nil)
        let approved = try #require(QuarantineInfo.parse("00c1;65f1a2b3;Chrome;"))
        #expect(approved.userApproved)
        #expect(QuarantineInfo.parse("garbage") == nil)
    }

    @Test func quarantineReadFromXattr() throws {
        let dir = try TempDir()
        let f = try dir.write("downloaded.zip", "x")
        try shell("/usr/bin/xattr", ["-w", "com.apple.quarantine", "0081;65f1a2b3;Firefox;", f.path])
        let q = try #require(QuarantineInfo.read(path: f.path))
        #expect(q.agent == "Firefox")
    }

    @Test func gatekeeperParsing() {
        let ok = GatekeeperAssessment.parse(exitCode: 0, output: "/Applications/A.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: X (ABC)\n")
        #expect(ok.accepted)
        #expect(ok.source == "Notarized Developer ID")
        let bad = GatekeeperAssessment.parse(exitCode: 3, output: "/tmp/B.app: rejected\nsource=no usable signature\n")
        #expect(!bad.accepted)
        #expect(bad.message == "rejected")
        #expect(bad.source == "no usable signature")
    }
}
