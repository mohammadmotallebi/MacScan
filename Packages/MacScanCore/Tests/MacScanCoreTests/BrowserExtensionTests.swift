import Foundation
import Testing
@testable import MacScanCore

@Suite struct BrowserExtensionTests {
    let home: TempDir
    let other: TempDir
    let idNice = String(repeating: "a", count: 32)
    let idSpy = String(repeating: "b", count: 32)
    let idLocal = String(repeating: "c", count: 32)
    let idComponent = String(repeating: "d", count: 32)
    let idOff = String(repeating: "e", count: 32)
    let idPolicy = String(repeating: "f", count: 32)

    init() throws {
        home = try TempDir()
        other = try TempDir()
    }

    func json(_ object: Any) throws -> Data { try JSONSerialization.data(withJSONObject: object) }

    var chrome: String { "Library/Application Support/Google/Chrome" }

    func locations(safari: String? = nil) -> BrowserLocations {
        BrowserLocations(home: home.url, safariListing: { point in point == "com.apple.Safari.web-extension" ? safari : nil })
    }

    /// A Chrome profile with a store extension, a powerful one, an unpacked one, a component, a
    /// disabled one and a policy-installed one.
    func makeChrome(spyPermissions: [String] = ["cookies", "nativeMessaging"]) throws {
        try home.write("\(chrome)/Default/Extensions/\(idNice)/1.0_0/manifest.json",
                       json(["name": "__MSG_appName__", "default_locale": "en", "version": "1.0", "permissions": ["storage", "https://example.com/*"]]))
        try home.write("\(chrome)/Default/Extensions/\(idNice)/1.0_0/_locales/en/messages.json", json(["AppName": ["message": "Nice Tool"]]))
        try home.write("\(chrome)/Default/Extensions/\(idNice)/1.0_0/background.js", "console.log('hi')")
        try home.write("\(chrome)/Default/Extensions/\(idSpy)/2.0_0/manifest.json", json(["name": "Spy", "version": "2.0"]))
        try other.write("unpacked/manifest.json", json(["name": "Dev Build", "version": "0.1", "host_permissions": ["https://dev.example/*"]]))
        let powerful: [String: Any] = ["api": spyPermissions, "explicit_host": ["<all_urls>"], "scriptable_host": []]
        let settings: [String: Any] = [
            idNice: ["location": 1, "from_webstore": true, "path": "\(idNice)/1.0_0"],
            idSpy: ["location": 1, "from_webstore": true, "manifest": ["name": "Spy", "version": "2.0"], "active_permissions": powerful],
            idLocal: ["location": 4, "path": other.url.appendingPathComponent("unpacked").path],
            idComponent: ["location": 5, "manifest": ["name": "Built In"]],
            idOff: ["location": 1, "from_webstore": true, "disable_reasons": [1], "manifest": ["name": "Off"], "active_permissions": powerful],
            idPolicy: ["location": 9, "manifest": ["name": "Forced", "version": "3"]],
        ]
        try home.write("\(chrome)/Default/Secure Preferences", json(["extensions": ["settings": settings]]))
        try home.write("\(chrome)/Default/Preferences", json(["extensions": ["settings": [idNice: ["location": 1, "from_webstore": false]]]]))
    }

    @Test func chromiumExtensionsAreClassified() throws {
        try makeChrome()
        let inv = try BrowserExtensionScanner(locations: locations()).collect()
        func finding(_ name: String) -> Finding? { inv.findings.first { $0.reason.hasPrefix(name + ":") } }

        #expect(inv.extensions.count == 5, "the built-in component is not listed")
        let nice = try #require(finding("Nice Tool"))
        #expect(nice.severity == .clean)
        #expect(nice.reason == "Nice Tool: Chrome extension")
        #expect(nice.path.hasSuffix("/Extensions/\(idNice)"), "the id folder, which survives updates")
        #expect(nice.detail?.contains("Installed from: the browser's extension store") == true, "Secure Preferences wins over Preferences")
        #expect(nice.detail?.contains("Website access: https://example.com/*") == true)
        #expect(nice.detail?.contains("Permissions: storage") == true)

        let spy = try #require(finding("Spy"))
        #expect(spy.severity == .warning)
        #expect(spy.reason == "Spy: can read and change all websites and read cookies (your logins), talk to programs on this Mac")
        #expect(finding("Off")?.severity == .clean)
        #expect(finding("Off")?.reason == "Off: Chrome extension (disabled)")
        #expect(finding("Dev Build")?.reason == "Dev Build: loaded from a local folder, not installed from the store")
        #expect(finding("Dev Build")?.path == other.url.appendingPathComponent("unpacked").path)
        #expect(finding("Forced")?.reason == "Forced: force-installed by a management policy")
        #expect(inv.findings.allSatisfy { $0.engine == .extensions })
        #expect(inv.notes.first?.hasPrefix("Browser extensions: 5 extensions in Chrome.") == true)
        // Only what exists on disk is scanned.
        #expect(inv.scanPaths.count == 3)
    }

    @Test func profilesAreNamedWhenThereAreSeveral() throws {
        try makeChrome()
        try home.write("\(chrome)/Profile 1/Preferences", json(["extensions": ["settings": [idNice: ["location": 1, "from_webstore": true, "manifest": ["name": "Work Tool"]]]]]))
        let inv = try BrowserExtensionScanner(locations: locations()).collect()
        let work = try #require(inv.extensions.first { $0.name == "Work Tool" })
        #expect(work.profile == "Profile 1")
        #expect(inv.findings.first { $0.reason.hasPrefix("Work Tool") }?.detail?.contains("Browser: Chrome (profile Profile 1)") == true)
        // Same id in two profiles is two extensions.
        #expect(inv.snapshot.count == 6)
    }

    @Test func permissionListsAreSplitIntoAPIsAndSites() {
        let manifest: [String: Any] = [
            "permissions": ["tabs", "<all_urls>", "*://*.example.com/*"],
            "host_permissions": ["https://a.test/*"],
            "content_scripts": [["matches": ["https://b.test/*"]]],
        ]
        let (permissions, sites) = BrowserExtensionScanner.permissionsAndSites(manifest: manifest)
        #expect(permissions == ["tabs"])
        #expect(sites == ["<all_urls>", "*://*.example.com/*", "https://a.test/*", "https://b.test/*"])
        #expect(BrowserExtensionScanner.chromiumEnabled(["state": 0]) == false)
        #expect(BrowserExtensionScanner.chromiumEnabled(["disable_reasons": 0]) == true)
        #expect(BrowserExtensionScanner.chromiumEnabled([:]) == true)
        #expect(BrowserExtensionScanner.chromiumSource(["from_webstore": false], location: 1) == .notFromStore)
        #expect(BrowserExtensionScanner.chromiumSource(["was_installed_by_default": true], location: 1) == .installedByDefault)
        #expect(BrowserExtensionScanner.chromiumSource([:], location: 3) == .otherProgram)
    }

    @Test func firefoxAddOns() throws {
        let addons: [[String: Any]] = [
            ["id": "good@example", "type": "extension", "location": "app-profile", "signedState": 2, "active": true, "version": "1",
             "defaultLocale": ["name": "Good Fox"], "userPermissions": ["permissions": ["storage"], "origins": ["https://example.com/*"]]],
            ["id": "raw@example", "type": "extension", "location": "app-profile", "signedState": 0, "active": true,
             "defaultLocale": ["name": "Raw Fox"], "userPermissions": ["permissions": ["cookies"], "origins": ["<all_urls>"]]],
            ["id": "builtin@mozilla.org", "type": "extension", "location": "app-builtin", "defaultLocale": ["name": "Built In"]],
            ["id": "theme@example", "type": "theme", "location": "app-profile"],
        ]
        try home.write("Library/Application Support/Firefox/Profiles/abc.default/extensions.json", json(["addons": addons]))
        let inv = try BrowserExtensionScanner(locations: locations()).collect()
        #expect(inv.extensions.map(\.name) == ["Good Fox", "Raw Fox"])
        #expect(inv.findings.first { $0.reason.hasPrefix("Good Fox") }?.severity == .clean)
        let raw = try #require(inv.findings.first { $0.reason.hasPrefix("Raw Fox") })
        #expect(raw.severity == .warning)
        #expect(raw.reason.contains("not signed by the browser's add-on store (+1 more)"))
        #expect(raw.detail?.contains("• can read and change all websites and read cookies (your logins)") == true)
    }

    @Test func safariListingIsParsed() throws {
        let appex = try home.write("Apps/Blocker.app/Contents/PlugIns/Ext.appex/Contents/Resources/manifest.json",
                                   json(["name": "x", "permissions": ["nativeMessaging", "<all_urls>"]]))
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let listing = """
        +    com.example.blocker.ext(2.2.22)
        \t            Path = \(appex.path)
        \t            UUID = C69CCD56-2398-405C-8BB1-8F8C201C92D6
        \t             SDK = com.apple.Safari.web-extension
        \t   Parent Bundle = \(home.url.path)/Apps/Blocker.app
        \t    Display Name = Blocker Panel

        -    com.example.other(1.0)
        \t            Path = /nonexistent/Other.appex
        \t    Display Name = $(PRODUCT_NAME)
        \t   Parent Bundle = /nonexistent/Other Thing.app
        """
        let found = BrowserExtensionScanner.parseSafariListing(listing)
        #expect(found.map(\.id) == ["com.example.blocker.ext", "com.example.other"])
        #expect(found[0].name == "Blocker Panel")
        #expect(found[0].version == "2.2.22")
        #expect(found[0].enabled)
        #expect(found[0].permissions == ["nativeMessaging"])
        #expect(found[0].canAccessAllSites)
        #expect(!found[1].enabled)
        #expect(found[1].name == "Other Thing", "an unexpanded build variable falls back to the app's name")

        let inv = try BrowserExtensionScanner(locations: locations(safari: listing)).collect()
        #expect(inv.notes.first?.contains("in Safari.") == true)
        let blocker = try #require(inv.findings.first { $0.reason.hasPrefix("Blocker Panel") })
        #expect(blocker.reason.contains("can read and change all websites and talk to programs on this Mac"))
        #expect(blocker.detail?.contains("Website access: all websites (may ask; you choose the sites in Safari)") == true)
    }

    @Test func noBrowsersIsNotAnError() throws {
        let inv = try BrowserExtensionScanner(locations: locations()).collect()
        #expect(inv.findings.isEmpty)
        #expect(inv.notes == ["Browser extensions: no supported browser data was found."])
    }

    func scan() async -> ScanSession {
        var settings = ScanSettings()
        settings.enableClamAV = false
        settings.enableYara = false
        let coordinator = ScanCoordinator(
            engines: [FilesOnlyEngine()], settings: settings,
            logger: FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs")),
            browserLocations: locations())
        return await coordinator.run(targets: [.browserExtensions]) { _ in }
    }

    @Test func coordinatorScansExtensionFilesAsOneUnitAndTracksChanges() async throws {
        try makeChrome()
        let tracker = ExtensionChangeTracker(file: other.url.appendingPathComponent("baseline.json"))

        var first = await scan()
        #expect(first.targets == ["Browser Extensions"])
        #expect(first.enginesUsed.contains(.extensions))
        #expect(first.itemsTotal == 5, "manifest, messages and script of one extension, manifests of two more")
        #expect(first.findings.count == 5, "one row per extension, none per file")
        #expect(!first.findings.contains { $0.engine == .scanner })
        tracker.apply(to: &first)
        #expect(first.extensionSnapshot == nil)
        #expect(first.extensionChanges == nil)
        #expect(first.notes.contains { $0.hasPrefix("Browser extensions: baseline saved (5 items)") })

        // The powerful extension gains a permission; a new one appears.
        try makeChrome(spyPermissions: ["cookies", "history", "nativeMessaging"])
        try home.write("\(chrome)/Profile 1/Preferences", json(["extensions": ["settings": [idNice: ["location": 1, "from_webstore": true, "manifest": ["name": "Newcomer"]]]]]))
        var second = await scan()
        tracker.apply(to: &second)
        let changes = try #require(second.extensionChanges)
        // "Off" has the same permission set in this fixture, so it changed too.
        #expect(changes.changed.sorted() == ["Off (Chrome)", "Spy (Chrome)"])
        #expect(changes.added.contains("Newcomer (Chrome)"))
        let spy = try #require(second.findings.first { $0.reason.hasPrefix("Spy:") })
        #expect(spy.change == .changed)
        #expect(spy.detail?.contains("• Permissions added: history") == true)
        #expect(second.findings.first { $0.reason.hasPrefix("Newcomer") }?.change == .new)
        #expect(second.notes.contains { $0.hasPrefix("Browser extensions since the scan on") })
    }

    @Test func engineFindingsInsideAnExtensionBelongToItsRow() async throws {
        try makeChrome()
        try home.write("\(chrome)/Default/Extensions/\(idNice)/1.0_0/evil.js", "MALWARE-MARKER")
        let session = await scan()
        let hit = try #require(session.findings.first { $0.engine == .yara })
        #expect(hit.path.hasSuffix("evil.js"))
        #expect(hit.unitPath.hasSuffix("/Extensions/\(idNice)"))
    }
}

/// Flags files containing a marker; lets coordinator tests run without ClamAV or YARA.
private struct FilesOnlyEngine: ScanEngine {
    let id = EngineID.yara
    let displayName = "Marker"
    func availability() async -> EngineAvailability { .available(detail: "test") }
    func handles(_ item: ScanItem) -> Bool { item.kind == .file }
    func scan(_ items: [ScanItem], context: ScanContext, events: @escaping EngineEventSink) async throws {
        for item in items {
            if (try? String(contentsOf: item.url, encoding: .utf8))?.contains("MALWARE-MARKER") == true {
                await events(.finding(Finding(path: item.path, severity: .threat, engine: .yara, reason: "marker", unitPath: item.unitPath)))
            }
            await events(.itemFinished(item.path))
        }
    }
}
