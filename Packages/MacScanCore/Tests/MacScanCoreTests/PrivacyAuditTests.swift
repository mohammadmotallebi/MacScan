import Foundation
import SQLite3
import Testing
@testable import MacScanCore

@Suite struct PrivacyAuditTests {
    /// Creates a small SQLite file by running the given statements.
    func makeDatabase(_ dir: TempDir, name: String = "TCC.db", _ sql: [String]) throws -> URL {
        let url = dir.url.appendingPathComponent(name)
        var db: OpaquePointer?
        #expect(sqlite3_open(url.path, &db) == SQLITE_OK)
        defer { sqlite3_close(db) }
        for statement in sql {
            #expect(sqlite3_exec(db, statement, nil, nil, nil) == SQLITE_OK, "\(statement)")
        }
        return url
    }

    static let schema = """
        CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, \
        auth_reason INTEGER NOT NULL DEFAULT 0, csreq BLOB, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', last_modified INTEGER NOT NULL DEFAULT 0)
        """

    func insert(_ service: String, _ client: String, type: Int = 0, auth: Int = 2, target: String = "UNUSED", modified: Int = 0) -> String {
        "INSERT INTO access (service, client, client_type, auth_value, indirect_object_identifier, last_modified) VALUES ('\(service)', '\(client)', \(type), \(auth), '\(target)', \(modified))"
    }

    /// An audit over made-up apps: every bundle ID in `apps` is "installed" at /Apps/<name>.app with the given signature.
    func audit(user: URL, system: URL, home: URL = URL(fileURLWithPath: "/Users/test"), apps: [String: (String, SigningStatus)]) -> PrivacyAudit {
        let paths = apps.mapValues { $0.0 }
        let statuses = Dictionary(uniqueKeysWithValues: apps.values.map { ($0.0, $0.1) })
        return PrivacyAudit(userDatabase: user, systemDatabase: system, home: home,
                            resolveApp: { paths[$0].map { URL(fileURLWithPath: $0) } },
                            signing: { statuses[$0.path] ?? .unsigned })
    }

    static let good = SigningStatus.signed(identifier: "x", teamID: "TEAM123456", authority: "Developer ID Application: Good")

    @Test func serviceNames() {
        #expect(PrivacyPermission.parse(service: "kTCCServiceCamera")?.permission == .camera)
        #expect(PrivacyPermission.parse(service: "kTCCServicePostEvent")?.permission == .accessibility)
        #expect(PrivacyPermission.parse(service: "kTCCServiceSystemPolicyDownloadsFolder")?.part == "Downloads")
        #expect(PrivacyPermission.parse(service: "kTCCServiceLiverpool") == nil)
        for permission in PrivacyPermission.allCases { #expect(permission.settingsURL != nil) }
    }

    @Test func readsRecords() throws {
        let dir = try TempDir()
        let db = try makeDatabase(dir, [
            Self.schema,
            insert("kTCCServiceCamera", "com.example.cam", modified: 1_700_000_000),
            insert("kTCCServiceAppleEvents", "com.example.script", target: "com.apple.finder"),
            insert("kTCCServiceAccessibility", "/usr/local/bin/tool", type: 1, auth: 0),
        ])
        let records = try TCCDatabase.read(db).get()
        #expect(records.count == 3)
        #expect(records[0] == TCCRecord(service: "kTCCServiceCamera", client: "com.example.cam", modified: Date(timeIntervalSince1970: 1_700_000_000)))
        #expect(records[1].target == "com.apple.finder")
        #expect(records[2].clientIsPath && records[2].authValue == 0)
        // Only the private copy was opened: nothing new next to the original.
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.url.path) == ["TCC.db"])
    }

    @Test func oldSchemaAndBadFiles() throws {
        let dir = try TempDir()
        let old = try makeDatabase(dir, name: "old.db", [
            "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, allowed INTEGER)",
            "INSERT INTO access VALUES ('kTCCServiceMicrophone', 'com.example.mic', 0, 1)",
            "INSERT INTO access VALUES ('kTCCServiceCamera', 'com.example.mic', 0, 0)",
        ])
        #expect(try TCCDatabase.read(old).get().map(\.authValue) == [2, 0])

        #expect(TCCDatabase.read(dir.url.appendingPathComponent("none.db")) == .failure(.missing))
        let other = try makeDatabase(dir, name: "other.db", ["CREATE TABLE things (a TEXT)"])
        #expect(TCCDatabase.read(other) == .failure(.failed("not a permission database")))
        let junk = try dir.write("junk.db", "not a database at all")
        if case .failure(.failed) = TCCDatabase.read(junk) {} else { Issue.record("junk should fail") }
    }

    @Test func groupsAndFlags() throws {
        let dir = try TempDir()
        let user = try makeDatabase(dir, name: "user.db", [
            Self.schema,
            insert("kTCCServiceCamera", "com.good.app"),
            insert("kTCCServiceCamera", "com.bad.app"),
            insert("kTCCServiceCamera", "com.denied.app", auth: 0),
            insert("kTCCServiceCamera", "com.undecided.app", auth: 1),
            insert("kTCCServiceMicrophone", "com.gone.app"),
            insert("kTCCServiceMicrophone", "com.apple.gone"),
            insert("kTCCServiceSystemPolicyDesktopFolder", "com.good.app"),
            insert("kTCCServiceSystemPolicyDownloadsFolder", "com.good.app"),
            insert("kTCCServiceSystemPolicyDocumentsFolder", "com.good.app", auth: 0),
            insert("kTCCServiceAppleEvents", "com.good.app", target: "com.apple.finder"),
            insert("kTCCServiceAppleEvents", "com.good.app", target: "com.other.thing"),
            insert("kTCCServicePhotos", "com.good.app", auth: 3),
            insert("kTCCServiceLiverpool", "com.good.app"),
        ])
        let system = try makeDatabase(dir, name: "system.db", [
            Self.schema,
            insert("kTCCServiceScreenCapture", "com.good.app"),
            insert("kTCCServiceAccessibility", "com.good.app"),
            insert("kTCCServicePostEvent", "com.good.app"),
            insert("kTCCServiceSystemPolicyAllFiles", "com.downloads.app"),
            insert("kTCCServiceSystemPolicyAllFiles", "com.brew.tool"),
        ])
        let report = audit(user: user, system: system, apps: [
            "com.good.app": ("/Apps/Good.app", Self.good),
            "com.bad.app": ("/Apps/Bad.app", .selfSigned(identifier: "com.bad.app", authority: "Me")),
            "com.denied.app": ("/Apps/Denied.app", .unsigned),
            "com.downloads.app": ("/Users/test/Downloads/Thing.app", .adhoc(identifier: "thing")),
            "com.brew.tool": ("/opt/homebrew/bin/tool", .adhoc(identifier: "tool")),
            "com.apple.finder": ("/System/Library/CoreServices/Finder.app", Self.good),
        ]).run()

        #expect(report.user == .read(13))
        #expect(report.system == .read(5))
        #expect(!report.needsFullDiskAccess)
        func grant(_ permission: PrivacyPermission, _ client: String) -> PrivacyGrant? {
            report.grants.first { $0.permission == permission && $0.client == client }
        }

        // Camera: flagged first, undecided left out, denied never flagged.
        #expect(report.grants(for: .camera).map(\.client) == ["com.bad.app", "com.denied.app", "com.good.app"])
        #expect(grant(.camera, "com.bad.app")?.risk == .warning)
        #expect(grant(.camera, "com.bad.app")?.reasons == ["It is signed with a certificate Apple didn't issue."])
        #expect(grant(.camera, "com.denied.app")?.decision == .denied)
        #expect(grant(.camera, "com.denied.app")?.risk == PrivacyRisk.none)
        let good = try #require(grant(.camera, "com.good.app"))
        #expect(good.name == "Good" && good.path == "/Apps/Good.app" && good.risk == .none)

        // An app that isn't installed is worth a look; macOS's own helpers are not.
        #expect(grant(.microphone, "com.gone.app")?.risk == .review)
        #expect(grant(.microphone, "com.gone.app")?.name == "com.gone.app")
        #expect(grant(.microphone, "com.apple.gone")?.risk == PrivacyRisk.none)

        // Several folders and several controlled apps become one row each.
        #expect(grant(.filesAndFolders, "com.good.app")?.detail == "Desktop, Downloads")
        #expect(grant(.automation, "com.good.app")?.detail == "Controls Finder, com.other.thing")
        #expect(grant(.photos, "com.good.app")?.decision == .limited)
        #expect(report.grants(for: .accessibility).count == 1)

        // Seeing the screen and controlling the Mac together is pointed out once, on Screen Recording.
        #expect(grant(.screenRecording, "com.good.app")?.risk == .review)
        #expect(grant(.accessibility, "com.good.app")?.risk == PrivacyRisk.none)

        // Location adds to an untrusted signature; Homebrew's ad-hoc builds are fine.
        #expect(grant(.fullDiskAccess, "com.downloads.app")?.reasons.count == 2)
        #expect(grant(.fullDiskAccess, "com.brew.tool")?.risk == PrivacyRisk.none)
        #expect(report.count(.warning) == 2)
    }

    @Test func pathClientsAndMissingDatabases() throws {
        let dir = try TempDir()
        let app = try dir.makeApp("Tool")
        let binary = app.appendingPathComponent("Contents/MacOS/Tool").path
        let user = try makeDatabase(dir, [
            Self.schema,
            insert("kTCCServiceCamera", binary, type: 1),
            insert("kTCCServiceCamera", "/nowhere/gone-tool", type: 1),
        ])
        let appPath = app.path
        let audit = PrivacyAudit(userDatabase: user, systemDatabase: dir.url.appendingPathComponent("none.db"), home: dir.url,
                                 resolveApp: { _ in nil }, signing: { $0.path == appPath ? Self.good : .unsigned })
        let report = audit.run()
        #expect(report.system == .missing)
        let tool = try #require(report.grants.first { $0.client == binary })
        #expect(tool.name == "Tool" && tool.path == app.path && tool.risk == .none)
        let gone = try #require(report.grants.first { $0.client == "/nowhere/gone-tool" })
        #expect(gone.name == "gone-tool" && gone.path == nil && gone.risk == .review)
    }

    // MARK: - Removing leftovers

    actor Calls {
        var list: [[String]] = []
        var standInID: String?
        func add(_ call: [String], standInID: String?) {
            list.append(call)
            if let standInID { self.standInID = standInID }
        }
    }

    func leftover(_ client: String = "com.gone.app", services: [String] = ["kTCCServiceAccessibility", "kTCCServicePostEvent"], isPath: Bool = false) -> PrivacyGrant {
        PrivacyGrant(permission: .accessibility, client: client, name: client, path: nil, decision: .allowed, detail: nil, signer: nil,
                     risk: .review, reasons: [], modified: nil, services: services, clientIsPath: isPath, appMissing: true)
    }

    func remover(_ dir: TempDir, calls: Calls, tccutilExit: Int32 = 0, installed: [String: String] = [:]) -> PrivacyLeftoverRemover {
        let work = dir.url.appendingPathComponent("work")
        return PrivacyLeftoverRemover(workFolder: work, run: { tool, arguments in
            var id: String?
            if tool == "/usr/bin/tccutil", let folder = try? FileManager.default.contentsOfDirectory(atPath: work.path).first {
                let plist = work.appendingPathComponent("\(folder)/Removed App.app/Contents/Info.plist")
                id = NSDictionary(contentsOf: plist)?["CFBundleIdentifier"] as? String
            }
            await calls.add([(tool as NSString).lastPathComponent] + arguments.prefix(3), standInID: id)
            return PostureCommandOutput(exitCode: tool == "/usr/bin/tccutil" ? tccutilExit : 0, text: tccutilExit == 0 ? "ok" : "tccutil: nope")
        }, resolveApp: { installed[$0].map { URL(fileURLWithPath: $0) } })
    }

    @Test func removesLeftoverThroughStandIn() async throws {
        let dir = try TempDir()
        let calls = Calls()
        try await remover(dir, calls: calls).remove(leftover())
        let list = await calls.list
        #expect(list.map(\.first) == ["codesign", "lsregister", "tccutil", "tccutil", "lsregister"])
        #expect(list[1][1] == "-f" && list[4][1] == "-u")
        #expect(list[2] == ["tccutil", "reset", "Accessibility", "com.gone.app"])
        #expect(list[3] == ["tccutil", "reset", "PostEvent", "com.gone.app"])
        // The stand-in carried the app's ID while tccutil ran, and is gone afterwards.
        #expect(await calls.standInID == "com.gone.app")
        #expect(!FileManager.default.fileExists(atPath: dir.url.appendingPathComponent("work").path))
    }

    @Test func refusesAnythingThatIsNotALeftover() async throws {
        let dir = try TempDir()
        let calls = Calls()
        var present = leftover()
        present.appMissing = false
        for grant in [present, leftover("/usr/local/bin/tool", isPath: true), leftover("com.apple.something"), leftover("-rf"), leftover("a b"), leftover(services: [])] {
            await #expect(throws: PrivacyLeftoverRemover.RemoveError.notALeftover) { try await remover(dir, calls: calls).remove(grant) }
        }
        // Installed since the list was read: left alone.
        await #expect(throws: PrivacyLeftoverRemover.RemoveError.appIsInstalled("/Apps/Back.app")) {
            try await remover(dir, calls: calls, installed: ["com.gone.app": "/Apps/Back.app"]).remove(leftover())
        }
        #expect(await calls.list.isEmpty)
        #expect(leftover().canRemove)
    }

    @Test func failedResetIsReportedAndCleanedUp() async throws {
        let dir = try TempDir()
        let calls = Calls()
        await #expect(throws: PrivacyLeftoverRemover.RemoveError.failed("tccutil: nope")) {
            try await remover(dir, calls: calls, tccutilExit: 64).remove(leftover(services: ["kTCCServiceCamera"]))
        }
        // One retry, then the stand-in is still unregistered and deleted.
        #expect(await calls.list.map(\.first) == ["codesign", "lsregister", "tccutil", "tccutil", "lsregister"])
        #expect(!FileManager.default.fileExists(atPath: dir.url.appendingPathComponent("work").path))
    }
}
