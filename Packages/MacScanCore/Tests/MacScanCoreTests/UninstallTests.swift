import Foundation
import Testing
@testable import MacScanCore

/// Moves "trashed" items into a test folder instead of the real Trash.
struct FolderTrasher: Trasher {
    let folder: URL
    func trash(_ url: URL) throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try FileManager.default.moveItem(at: url, to: folder.appendingPathComponent(url.lastPathComponent + "-\(UUID().uuidString.prefix(4))"))
    }
}

/// Runs the "admin" script as the current user with /bin/sh (no password, no root) and records it.
final class RecordingAdminRunner: AdminRunner, @unchecked Sendable {
    var scripts: [String] = []
    var cancel = false

    func run(script: String, prompt: String) async throws -> String {
        scripts.append(script)
        if cancel { throw UninstallError.adminCancelled }
        let r = try await ProcessRunner.run(URL(fileURLWithPath: "/bin/sh"), ["-c", script])
        return r.stdout
    }
}

@Suite struct LeftoverFinderTests {
    /// A fake system: a Demo.app with a nested helper, plus leftovers (and look-alikes that must NOT match).
    func makeFixture() throws -> (root: TempDir, home: TempDir, app: InstalledApp) {
        let root = try TempDir()
        let home = try TempDir()
        let appURL = try root.makeApp("Demo") // CFBundleIdentifier com.example.macscan.test.Demo
        // Nested login item with its own bundle ID.
        let helper = appURL.appendingPathComponent("Contents/Library/LoginItems/DemoHelper.app")
        try FileManager.default.createDirectory(at: helper.appendingPathComponent("Contents"), withIntermediateDirectories: true)
        let helperPlist = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "com.example.macscan.test.Demo.LoginHelper", "CFBundlePackageType": "APPL"], format: .xml, options: 0)
        try helperPlist.write(to: helper.appendingPathComponent("Contents/Info.plist"))

        let id = "com.example.macscan.test.Demo"
        // User leftovers.
        try home.write("Library/Application Support/\(id)/data.db", "x")
        try home.write("Library/Application Support/Demo/settings.json", "x")            // by name
        try home.write("Library/Caches/\(id)/cache", "x")
        try home.write("Library/Preferences/\(id).plist", "x")
        try home.write("Library/Preferences/ByHost/\(id).0A1B2C3D-0000.plist", "x")
        try home.write("Library/Containers/com.example.macscan.test.Demo.LoginHelper/x", "x") // nested ID
        try home.write("Library/Group Containers/ABCDE12345.\(id)/x", "x")                  // team prefix
        try home.write("Library/Saved Application State/\(id).savedState/x", "x")
        try home.write("Library/HTTPStorages/\(id).binarycookies", "x")
        try home.write("Library/Logs/Demo/log.txt", "x")
        // Look-alikes that must stay.
        try home.write("Library/Application Support/com.example.macscan.test.DemoPro/x", "x")
        try home.write("Library/Application Support/Demonstration/x", "x")
        try home.write("Library/Preferences/com.example.macscan.test.Other.plist", "x")

        // Launch items: one named after the ID, one named differently but launching the app, one unrelated.
        let agent = try PropertyListSerialization.data(fromPropertyList: ["Label": "\(id).agent", "ProgramArguments": ["/usr/bin/true"]], format: .xml, options: 0)
        try home.write("Library/LaunchAgents/\(id).agent.plist", agent)
        let helperTool = try root.copy("/usr/bin/true", to: "Library/PrivilegedHelperTools/com.vendor.updater")
        let daemon = try PropertyListSerialization.data(fromPropertyList: ["Label": "com.vendor.updater", "Program": helperTool.path, "AssociatedBundleIdentifiers": [id]], format: .xml, options: 0)
        try root.write("Library/LaunchDaemons/com.vendor.updater.plist", daemon)
        let unrelated = try PropertyListSerialization.data(fromPropertyList: ["Label": "com.other.thing", "ProgramArguments": ["/usr/bin/true"]], format: .xml, options: 0)
        try root.write("Library/LaunchDaemons/com.other.thing.plist", unrelated)
        try root.write("Library/Application Support/\(id)/shared.dat", "x")

        let app = try #require(InstalledApp.load(appURL))
        return (root, home, app)
    }

    @Test func findsEverythingAndNothingElse() throws {
        let (root, home, app) = try makeFixture()
        #expect(app.nestedBundleIDs.contains("com.example.macscan.test.Demo.LoginHelper"))
        let finder = LeftoverFinder(locations: UninstallLocations(home: home.url, root: root.url, isRealSystem: false))
        let plan = try finder.find(app)
        let found = Set(plan.leftovers.map { $0.path.replacingOccurrences(of: home.url.path, with: "~").replacingOccurrences(of: root.url.path, with: "") })

        let id = "com.example.macscan.test.Demo"
        let expected: Set<String> = [
            "/Demo.app",
            "~/Library/Application Support/\(id)",
            "~/Library/Application Support/Demo",
            "~/Library/Caches/\(id)",
            "~/Library/Preferences/\(id).plist",
            "~/Library/Preferences/ByHost/\(id).0A1B2C3D-0000.plist",
            "~/Library/Containers/com.example.macscan.test.Demo.LoginHelper",
            "~/Library/Group Containers/ABCDE12345.\(id)",
            "~/Library/Saved Application State/\(id).savedState",
            "~/Library/HTTPStorages/\(id).binarycookies",
            "~/Library/Logs/Demo",
            "~/Library/LaunchAgents/\(id).agent.plist",
            "/Library/LaunchDaemons/com.vendor.updater.plist",
            "/Library/PrivilegedHelperTools/com.vendor.updater",
            "/Library/Application Support/\(id)",
        ]
        #expect(found == expected, "missing: \(expected.subtracting(found)) extra: \(found.subtracting(expected))")

        let daemon = try #require(plan.leftovers.first { $0.path.hasSuffix("com.vendor.updater.plist") })
        #expect(daemon.category == .launchDaemon)
        #expect(daemon.launchDomain == .system)
        #expect(daemon.matchedBy == "Declares the app as its owner")
        #expect(plan.leftovers.first { $0.path.hasSuffix("Application Support/Demo") }?.matchedByNameOnly == true)
        #expect(plan.leftovers.first { $0.category == .application }?.size ?? 0 > 0)
    }

    @Test func identifierMatching() {
        let ids = ["com.x.app"]
        #expect(LeftoverFinder.matchesIdentifier("com.x.app", ids: ids))
        #expect(LeftoverFinder.matchesIdentifier("com.x.app.plist", ids: ids))
        #expect(LeftoverFinder.matchesIdentifier("com.x.App.helper.plist", ids: ids))
        #expect(LeftoverFinder.matchesIdentifier("group.com.x.app", ids: ids))
        #expect(LeftoverFinder.matchesIdentifier("S8EX82NJP6.com.x.app", ids: ids, teamID: "S8EX82NJP6"))
        #expect(!LeftoverFinder.matchesIdentifier("com.x.apppro", ids: ids))
        #expect(!LeftoverFinder.matchesIdentifier("com.x", ids: ids))
        #expect(!LeftoverFinder.matchesIdentifier("UBF8T346G9.Office", ids: ["com.microsoft.word"]))
    }

    @Test func protectedApps() throws {
        let calc = try #require(InstalledApp.load(URL(fileURLWithPath: "/System/Applications/Calculator.app")))
        #expect(calc.isProtected)
    }
}

@Suite(.serialized) struct UninstallerTests {
    @Test func uninstallsUserAndAdminItems() async throws {
        let dir = try TempDir()
        let appURL = try dir.makeApp("Gone")
        let app = try #require(InstalledApp.load(appURL))
        let support = try dir.write("home/Library/Application Support/com.example.macscan.test.Gone/x", "x").deletingLastPathComponent()
        let daemonPlist = try dir.write("root/Library/LaunchDaemons/it's \"odd\" $HOME.plist", "x")
        let helper = try dir.write("root/Library/PrivilegedHelperTools/com.example.helper", "x")
        let keep = try dir.write("home/Library/Caches/keep-me/x", "x").deletingLastPathComponent()

        func leftover(_ url: URL, _ cat: LeftoverCategory, admin: Bool = false, domain: LaunchDomain? = nil) -> Leftover {
            Leftover(url: url, category: cat, matchedBy: "test", matchedByNameOnly: false, requiresAdmin: admin, size: 1, launchLabel: nil, launchDomain: domain)
        }
        let plan = UninstallPlan(app: app, leftovers: [
            leftover(appURL, .application),
            leftover(support, .appSupport),
            leftover(daemonPlist, .launchDaemon, admin: true, domain: .system),
            leftover(helper, .privilegedHelper, admin: true),
            leftover(keep, .caches),
        ], processes: [], packageReceipts: [], notes: [])

        let trashed = dir.url.appendingPathComponent("FakeTrash")
        let admin = RecordingAdminRunner()
        let uninstaller = Uninstaller(trasher: FolderTrasher(folder: trashed), admin: admin,
                                      logger: FileLogger(directory: dir.url.appendingPathComponent("logs")),
                                      trashDirectory: trashed, manageProcesses: false)
        let selected = Set([appURL, support, daemonPlist, helper].map(\.path)) // not `keep`
        let report = try await uninstaller.uninstall(plan, selected: selected)

        #expect(report.movedCount == 4)
        #expect(report.failures.isEmpty)
        for url in [appURL, support, daemonPlist, helper] {
            #expect(!FileManager.default.fileExists(atPath: url.path), "\(url.lastPathComponent) should be gone")
        }
        #expect(FileManager.default.fileExists(atPath: keep.path), "unselected items must stay")
        #expect(FileManager.default.fileExists(atPath: trashed.appendingPathComponent("it's \"odd\" $HOME.plist").path))
        // One admin step, which also stops the daemon.
        #expect(admin.scripts.count == 1)
        #expect(admin.scripts[0].contains("launchctl bootout system"))
    }

    @Test func cancelledPasswordLeavesSystemItems() async throws {
        let dir = try TempDir()
        let appURL = try dir.makeApp("Stay")
        let app = try #require(InstalledApp.load(appURL))
        let helper = try dir.write("root/helper", "x")
        let plan = UninstallPlan(app: app, leftovers: [
            Leftover(url: helper, category: .privilegedHelper, matchedBy: "t", matchedByNameOnly: false, requiresAdmin: true, size: 1, launchLabel: nil, launchDomain: nil),
        ], processes: [], packageReceipts: [], notes: [])
        let admin = RecordingAdminRunner()
        admin.cancel = true
        let report = try await Uninstaller(trasher: FolderTrasher(folder: dir.url.appendingPathComponent("T")), admin: admin,
                                           logger: FileLogger(directory: dir.url.appendingPathComponent("logs")),
                                           trashDirectory: dir.url.appendingPathComponent("T"), manageProcesses: false)
            .uninstall(plan, selected: [helper.path])
        #expect(report.results.first?.outcome == .skipped("Password prompt cancelled"))
        #expect(FileManager.default.fileExists(atPath: helper.path))
    }

    @Test func refusesProtectedApps() async throws {
        let calc = try #require(InstalledApp.load(URL(fileURLWithPath: "/System/Applications/Calculator.app")))
        let plan = UninstallPlan(app: calc, leftovers: [], processes: [], packageReceipts: [], notes: [])
        await #expect(throws: UninstallError.self) {
            try await Uninstaller(trasher: FolderTrasher(folder: URL(fileURLWithPath: "/nonexistent")), manageProcesses: false)
                .uninstall(plan, selected: [calc.url.path])
        }
    }

    @Test func escapingSurvivesRealOsascript() async throws {
        let nasty = #"/tmp/a b/it's "quoted" $HOME `cmd` \back"#
        let shell = "printf '%s' \(Uninstaller.shellQuote(nasty))"
        let source = "do shell script \"\(Uninstaller.appleScriptEscape(shell))\""
        let r = try await ProcessRunner.run(URL(fileURLWithPath: "/usr/bin/osascript"), ["-e", source])
        #expect(r.exitCode == 0)
        #expect(r.stdout.trimmingCharacters(in: .newlines) == nasty)
    }

    @Test func adminOutputParsing() {
        let (ok, failed) = Uninstaller.parseAdminOutput("OK:0\rFAIL:1\nOK:2\ngarbage")
        #expect(ok == [0, 2])
        #expect(failed == [1])
    }
}

// MARK: - Background items (BTM) & permanent removal

@Suite struct BackgroundItemsTests {
    static let sample = """
    ========================
     Records for UID 501 : 11111111-2222-3333-4444-555555555555
    ========================

     Items:

     #1:
                     UUID: 08EC9D5A-E5B3-4C60-9700-EB6354446793
                     Name: ChatGPT
           Developer Name: OpenAI, L.L.C.
          Team Identifier: 2DC432GLL2
                     Type: app (0x2)
              Disposition: [disabled, allowed, not notified] (0x2)
               Identifier: 2.com.openai.chat
                      URL: /Users/\(getuid())/.Trash/ChatGPT.app
        Bundle Identifier: com.openai.chat
        Embedded Item Identifiers:
            #1: 8.com.openai.chat-helper

     #2:
                     Name: ChatGPTHelper
           Developer Name: (null)
          Team Identifier: 2DC432GLL2
                     Type: agent (0x8)
               Identifier: 8.com.openai.chat-helper
                      URL: Contents/Library/LaunchAgents/com.openai.chat-helper.plist
          Executable Path: Contents/Resources/ChatGPTHelper
        Parent Identifier: 2.com.openai.chat

     #3:
                     Name: steamclean
           Developer Name: Steam
          Team Identifier: MXGJJ98X76
                     Type: legacy agent (0x10008)
               Identifier: 8.com.valvesoftware.steamclean
                      URL: /Users/\(getuid())/Library/LaunchAgents/com.valvesoftware.steamclean.plist
          Executable Path: /Users/\(getuid())/Library/Application Support/Steam/SteamApps/steamclean
        Parent Identifier: Steam

     #4:
                     Name: OtherDaemon
           Developer Name: Steam
          Team Identifier: MXGJJ98X76
                     Type: legacy daemon (0x10010)
               Identifier: 16.com.valvesoftware.other
                      URL: /Library/LaunchDaemons/com.valvesoftware.other.plist
        Parent Identifier: Valve Corporation
    """

    @Test func parsesRecords() throws {
        let records = BackgroundItems.parse(Self.sample)
        #expect(records.count == 4)
        let app = try #require(records.first { $0.identifier == "2.com.openai.chat" })
        #expect(app.isApp)
        #expect(app.url == AppPaths.home.path + "/.Trash/ChatGPT.app")
        let helper = try #require(records.first { $0.name == "ChatGPTHelper" })
        #expect(helper.launchDomain == .gui)
        #expect(helper.label == "com.openai.chat-helper")
        #expect(helper.isEmbedded)
        #expect(helper.developerName == nil)
        let steam = try #require(records.first { $0.name == "steamclean" })
        #expect(steam.isLegacy)
        #expect(steam.launchDomain == .gui)
        #expect(steam.url == AppPaths.home.path + "/Library/LaunchAgents/com.valvesoftware.steamclean.plist")
        #expect(records.first { $0.name == "OtherDaemon" }?.launchDomain == .system)
        let loginItem = BTMRecord(identifier: "4.com.macpaw.CleanMyMac5.Menu", type: "login item (0x4)")
        #expect(loginItem.launchDomain == .gui)
        #expect(loginItem.label == "com.macpaw.CleanMyMac5.Menu")
    }

    @Test func findsAppsItemsIncludingDifferentlyNamedLegacyAgents() throws {
        let dir = try TempDir()
        let records = BackgroundItems.parse(Self.sample)

        // ChatGPT: embedded helper is owned via Parent Identifier.
        let chat = try #require(InstalledApp.load(try dir.makeApp("ChatGPT")))
        let chatLike = InstalledApp(url: chat.url, name: "ChatGPT", bundleID: "com.openai.chat", version: nil, teamID: "2DC432GLL2",
                                    nestedBundleIDs: [], names: ["ChatGPT"], protectionReason: nil)
        #expect(BackgroundItems.items(for: chatLike, in: records).owned.map(\.label) == ["com.openai.chat-helper"])

        // Steam: legacy agent grouped under the app's name is owned; another Valve item under a different
        // parent is only "same developer".
        let steam = InstalledApp(url: dir.url.appendingPathComponent("Steam.app"), name: "Steam", bundleID: "com.valvesoftware.steam",
                                 version: nil, teamID: "MXGJJ98X76", nestedBundleIDs: [], names: ["Steam"], protectionReason: nil)
        let (owned, same) = BackgroundItems.items(for: steam, in: records)
        #expect(owned.map(\.name) == ["steamclean"])
        #expect(same.map(\.name) == ["OtherDaemon"])
    }

    @Test func finderUsesBackgroundItemsAndSupportFolderPrograms() throws {
        let root = try TempDir()
        let home = try TempDir()
        let appURL = try root.makeApp("Gamey") // com.example.macscan.test.Gamey
        let id = "com.example.macscan.test.Gamey"
        // Support folder (name match) with a program that a differently named agent starts.
        let cleaner = try home.write("Library/Application Support/Gamey/bin/cleaner", "#!/bin/sh\n")
        let agent = try PropertyListSerialization.data(fromPropertyList: ["Label": "com.vendor.cleaner", "ProgramArguments": [cleaner.path]], format: .xml, options: 0)
        try home.write("Library/LaunchAgents/com.vendor.cleaner.plist", agent)
        // A same-developer item that must not be preselected.
        let shared = try root.write("Library/LaunchDaemons/com.vendor.sharedupdater.plist", "x")

        let app = try #require(InstalledApp.load(appURL))
        let records = [
            BTMRecord(identifier: "2.\(id)", name: "Gamey", type: "app (0x2)", url: appURL.path, bundleID: id, teamID: "TEAM123456"),
            BTMRecord(identifier: "8.\(id)-helper", name: "GameyHelper", type: "agent (0x8)", url: "Contents/Library/LaunchAgents/\(id)-helper.plist",
                      parentIdentifier: "2.\(id)", teamID: "TEAM123456"),
            BTMRecord(identifier: "16.com.vendor.sharedupdater", name: "Updater", type: "legacy daemon (0x10010)", url: shared.path,
                      parentIdentifier: "Vendor Inc", teamID: "TEAM123456", developerName: "Vendor Inc"),
        ]
        let appWithTeam = InstalledApp(url: app.url, name: app.name, bundleID: app.bundleID, version: nil, teamID: "TEAM123456",
                                       nestedBundleIDs: app.nestedBundleIDs, names: app.names, protectionReason: nil)
        let plan = try LeftoverFinder(locations: UninstallLocations(home: home.url, root: root.url, isRealSystem: false), backgroundItems: records)
            .find(appWithTeam)

        #expect(plan.launchJobs.contains(LaunchJob(label: "\(id)-helper", domain: .gui)), "embedded SMAppService helper is unregistered")
        #expect(plan.launchJobs.contains(LaunchJob(label: "com.vendor.cleaner", domain: .gui)))
        let cleanerAgent = try #require(plan.leftovers.first { $0.path.hasSuffix("com.vendor.cleaner.plist") })
        #expect(cleanerAgent.matchedBy.contains("support files"))
        let sharedItem = try #require(plan.leftovers.first { $0.path == shared.path })
        #expect(sharedItem.selectedByDefault == false)
    }

    @Test func hyphenatedLabelsMatch() {
        #expect(LeftoverFinder.matchesIdentifier("com.openai.chat-helper", ids: ["com.openai.chat"]))
        #expect(LeftoverFinder.matchesIdentifier("com.openai.chat-helper.plist", ids: ["com.openai.chat"]))
    }
}

@Suite struct PermanentRemovalTests {
    func leftover(_ url: URL, _ cat: LeftoverCategory = .appSupport, admin: Bool = false) -> Leftover {
        Leftover(url: url, category: cat, matchedBy: "t", matchedByNameOnly: false, requiresAdmin: admin, size: 1, launchLabel: nil, launchDomain: nil)
    }

    @Test func permanentAndAlreadyTrashedItemsAreDeleted() async throws {
        let dir = try TempDir()
        let trash = dir.url.appendingPathComponent("Trash")
        try FileManager.default.createDirectory(at: trash, withIntermediateDirectories: true)
        let appInTrash = trash.appendingPathComponent("Old.app")
        try FileManager.default.moveItem(at: try dir.makeApp("Old"), to: appInTrash)
        let app = try #require(InstalledApp.load(appInTrash))
        let support = try dir.write("home/support/x", "x").deletingLastPathComponent()
        let adminOwned = try dir.write("root/helper", "x")
        let plan = UninstallPlan(app: app, leftovers: [leftover(appInTrash, .application), leftover(support), leftover(adminOwned, .privilegedHelper, admin: true)],
                                 processes: [], packageReceipts: [], notes: [])
        let fakeTrash = dir.url.appendingPathComponent("FakeTrash")
        let admin = RecordingAdminRunner()
        let report = try await Uninstaller(trasher: FolderTrasher(folder: fakeTrash), admin: admin,
                                           logger: FileLogger(directory: dir.url.appendingPathComponent("logs")),
                                           trashDirectory: trash, manageProcesses: false)
            .uninstall(plan, selected: Set(plan.leftovers.map(\.path)), permanently: true)

        #expect(report.deletedCount == 3)
        #expect(!FileManager.default.fileExists(atPath: appInTrash.path))
        #expect(!FileManager.default.fileExists(atPath: support.path))
        #expect(!FileManager.default.fileExists(atPath: adminOwned.path))
        #expect(!FileManager.default.fileExists(atPath: fakeTrash.path), "nothing went to the Trash")
        #expect(admin.scripts.first?.contains("/bin/rm -rf") == true)
    }

    @Test func alreadyTrashedAppIsDeletedEvenWithoutPermanentFlag() async throws {
        let dir = try TempDir()
        let trash = dir.url.appendingPathComponent("Trash")
        try FileManager.default.createDirectory(at: trash, withIntermediateDirectories: true)
        let appInTrash = trash.appendingPathComponent("Old2.app")
        try FileManager.default.moveItem(at: try dir.makeApp("Old2"), to: appInTrash)
        let app = try #require(InstalledApp.load(appInTrash))
        let plan = UninstallPlan(app: app, leftovers: [leftover(appInTrash, .application)], processes: [], packageReceipts: [], notes: [])
        let report = try await Uninstaller(trasher: FolderTrasher(folder: dir.url.appendingPathComponent("FakeTrash")),
                                           admin: RecordingAdminRunner(), logger: FileLogger(directory: dir.url.appendingPathComponent("logs")),
                                           trashDirectory: trash, manageProcesses: false)
            .uninstall(plan, selected: [appInTrash.path])
        #expect(report.results.first?.outcome == .deleted)
    }

    @Test func safetyGuard() {
        let home = AppPaths.home.path
        for bad in ["/", "/Applications", "/Library", "/Library/LaunchDaemons", home, home + "/Library", home + "/Library/Application Support",
                    "/System/Applications/Calculator.app", "/usr/bin/true", "/private/var/db/receipts/x", "/etc/hosts"] {
            #expect(!Uninstaller.isSafeToRemove(bad), "\(bad) must be refused")
        }
        for ok in ["/Applications/Foo.app", home + "/Library/Caches/com.x.y", "/Library/LaunchDaemons/com.x.plist", home + "/.Trash/Foo.app"] {
            #expect(Uninstaller.isSafeToRemove(ok), "\(ok) should be allowed")
        }
    }

    @Test func adminScriptStopsSystemJobsByLabel() {
        let s = Uninstaller.adminScript(items: [], rootPIDs: [], systemJobs: ["com.x.daemon"], receipts: [], trashDirectory: URL(fileURLWithPath: "/tmp"), owner: 501)
        #expect(s.text.contains("/bin/launchctl bootout 'system/com.x.daemon'"))
    }
}

/// Leftovers that apps like CleanMyMac leave under helper names, crash caches and older-version IDs.
@Suite struct HelperAndVersionLeftoverTests {
    /// Writes a bundle with the given executable name and bundle ID.
    func makeBundle(_ url: URL, executable: String, id: String) throws {
        let macos = url.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: macos.appendingPathComponent(executable).path)
        let plist: [String: Any] = ["CFBundleExecutable": executable, "CFBundleIdentifier": id, "CFBundleName": executable, "CFBundlePackageType": "APPL"]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: url.appendingPathComponent("Contents/Info.plist"))
    }

    @Test func findsHelperNamedCrashAndOlderVersionLeftovers() throws {
        let root = try TempDir()
        let home = try TempDir()
        let appURL = root.url.appendingPathComponent("Cleaner_5.app")
        try makeBundle(appURL, executable: "Cleaner_5", id: "com.example.Cleaner5")
        try makeBundle(appURL.appendingPathComponent("Contents/Library/LoginItems/Cleaner_5_Monitor.app"),
                       executable: "Cleaner_5_Monitor", id: "com.example.Cleaner5.Monitor")
        // A generic helper name that must not be used for matching.
        try makeBundle(appURL.appendingPathComponent("Contents/XPCServices/Downloader.xpc"),
                       executable: "Downloader", id: "com.example.Cleaner5.Downloader")
        let app = try #require(InstalledApp.load(appURL))
        #expect(app.helperNames == ["Cleaner_5_Monitor"])

        // Should be found.
        try home.write("Library/Application Support/Cleaner_5_Monitor/state", "x")
        try home.write("Library/Caches/SentryCrash/Cleaner_5/report", "x")
        try home.write("Library/Caches/SentryCrash/Cleaner_5_Monitor/report", "x")
        try home.write("Library/Logs/DiagnosticReports/Cleaner_5_Monitor_2026-11-17-115729_MacBook-Pro.diag", "x")
        try home.write("Library/Group Containers/ABCDE12345.com.example.Cleaner4/x", "x")
        try home.write("Library/Application Scripts/ABCDE12345.com.example.Cleaner4/x", "x")
        try root.write("Library/Logs/DiagnosticReports/Cleaner_5_2026-11-17-120000_MacBook-Pro.ips", "x")
        // Look-alikes that must stay.
        try home.write("Library/Caches/SentryCrash/OtherApp/report", "x")
        try home.write("Library/Application Support/Downloader/x", "x")
        try home.write("Library/Logs/DiagnosticReports/Cleaner_50_2026-11-17.diag", "x")
        try home.write("Library/Logs/DiagnosticReports/OtherApp_2026-11-17.diag", "x")
        try home.write("Library/Group Containers/ABCDE12345.com.example.CleanerPro/x", "x")
        try home.write("Library/Group Containers/ABCDE12345.com.example.Cleaner45x/x", "x")

        let finder = LeftoverFinder(locations: UninstallLocations(home: home.url, root: root.url, isRealSystem: false), backgroundItems: [])
        let plan = try finder.find(app)
        func rel(_ l: Leftover) -> String {
            l.path.replacingOccurrences(of: home.url.path, with: "~").replacingOccurrences(of: root.url.path, with: "")
        }
        let found = Set(plan.leftovers.map(rel))
        let expected: Set<String> = [
            "/Cleaner_5.app",
            "~/Library/Application Support/Cleaner_5_Monitor",
            "~/Library/Caches/SentryCrash/Cleaner_5",
            "~/Library/Caches/SentryCrash/Cleaner_5_Monitor",
            "~/Library/Logs/DiagnosticReports/Cleaner_5_Monitor_2026-11-17-115729_MacBook-Pro.diag",
            "~/Library/Group Containers/ABCDE12345.com.example.Cleaner4",
            "~/Library/Application Scripts/ABCDE12345.com.example.Cleaner4",
            "/Library/Logs/DiagnosticReports/Cleaner_5_2026-11-17-120000_MacBook-Pro.ips",
        ]
        #expect(found == expected, "missing: \(expected.subtracting(found)) extra: \(found.subtracting(expected))")

        let report = try #require(plan.leftovers.first { $0.path.hasSuffix("Cleaner_5_Monitor_2026-11-17-115729_MacBook-Pro.diag") })
        #expect(report.matchedBy == "Crash report from Cleaner_5_Monitor")

        // Other-version items are shown but not ticked; everything else is ticked.
        for item in plan.leftovers {
            #expect(item.selectedByDefault == !rel(item).contains("Cleaner4"), "\(rel(item))")
        }
    }

    @Test func otherVersionIdentifierRules() {
        let ids = ["com.macpaw.cleanmymac5"]
        #expect(LeftoverFinder.otherVersionIdentifier("S8EX82NJP6.com.macpaw.CleanMyMac4", ids: ids) == "com.macpaw.cleanmymac4")
        #expect(LeftoverFinder.otherVersionIdentifier("com.macpaw.CleanMyMac4.plist", ids: ids) == "com.macpaw.cleanmymac4")
        #expect(LeftoverFinder.otherVersionIdentifier("com.macpaw.CleanMyMac3.Helper", ids: ids) == "com.macpaw.cleanmymac3")
        #expect(LeftoverFinder.otherVersionIdentifier("com.macpaw.CleanMyMac5", ids: ids) == nil)        // same version
        #expect(LeftoverFinder.otherVersionIdentifier("com.macpaw.CleanMyMacX", ids: ids) == nil)
        #expect(LeftoverFinder.otherVersionIdentifier("com.macpaw.CleanMyMac4Pro", ids: ids) == nil)
        #expect(LeftoverFinder.otherVersionIdentifier("com.macpaw.Gemini2", ids: ids) == nil)
        // IDs without a trailing version, or a non-letter before it, never produce matches.
        #expect(LeftoverFinder.otherVersionIdentifier("com.x.app2", ids: ["com.x.app"]) == nil)
        #expect(LeftoverFinder.otherVersionIdentifier("com.x.app_2", ids: ["com.x.app_1"]) == nil)
        #expect(LeftoverFinder.otherVersionIdentifier("x2", ids: ["x1"]) == nil)
    }
}
