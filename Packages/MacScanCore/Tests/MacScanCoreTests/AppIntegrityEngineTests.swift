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
