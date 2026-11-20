import Foundation
import Testing
@testable import MacScanCore

@Suite struct FullCheckTests {
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))

    @Test func targetsAndTitle() {
        #expect(FullCheck.targets == [.applications, .startupItems, .runningProcesses, .browserExtensions])
        #expect(FullCheck.areas == [.applications, .startupItems, .runningProcesses, .browserExtensions])
        #expect(ScanTarget.path(URL(fileURLWithPath: "/tmp")).area == .files)

        var session = ScanSession(targets: FullCheck.targets.map(\.displayName))
        #expect(session.title == "Applications, Startup Items, Running Processes, Browser Extensions")
        session.fullCheck = FullCheckInfo()
        #expect(session.title == "Full Check")
    }

    @Test func areaSummaryCountsBySeverity() {
        var session = ScanSession()
        func finding(_ severity: Severity, _ area: ScanArea?) -> Finding {
            var f = Finding(path: "/x/\(UUID().uuidString)", severity: severity, engine: .yara, reason: "r")
            f.area = area
            return f
        }
        session.findings = [
            finding(.threat, .applications), finding(.warning, .applications), finding(.warning, .applications),
            finding(.clean, .applications), finding(.clean, .startupItems), finding(.threat, nil),
        ]
        let apps = session.summary(of: .applications)
        #expect(apps == AreaSummary(area: .applications, threats: 1, warnings: 2, clean: 1))
        #expect(apps.worst == .threat)
        #expect(session.summary(of: .startupItems).worst == .clean)
        #expect(session.summary(of: .browserExtensions).isEmpty)
    }

    @Test func postureSummaryListsWhatDidNotPass() {
        let summary = PostureSummary(checks: [
            PostureCheck(id: .sip, title: "System Integrity Protection", status: .pass, summary: "On"),
            PostureCheck(id: .firewall, title: "Firewall", status: .warning, summary: "Off"),
            PostureCheck(id: .updates, title: "Software updates", status: .unknown, summary: "?"),
        ])
        #expect(summary == PostureSummary(passed: 1, total: 3, problems: ["Firewall", "Software updates"]))
    }

    @Test func privacySummaryCounts() {
        func grant(_ client: String, _ decision: PrivacyDecision, _ risk: PrivacyRisk, missing: Bool = false) -> PrivacyGrant {
            PrivacyGrant(permission: .camera, client: client, name: client, path: nil, decision: decision, detail: nil, signer: nil,
                         risk: risk, reasons: [], modified: nil, services: ["kTCCServiceCamera"], appMissing: missing)
        }
        let grants = [
            grant("com.a", .allowed, .none), grant("com.b", .allowed, .warning), grant("com.gone", .allowed, .review, missing: true),
            grant("com.c", .denied, .none),
        ]
        let full = PrivacySummary(report: PrivacyReport(grants: grants, user: .read(3), system: .read(1)))
        #expect(full == PrivacySummary(apps: 3, warnings: 1, review: 1, leftovers: 1))

        let partial = PrivacySummary(report: PrivacyReport(grants: grants, user: .read(3), system: .noAccess))
        #expect(partial.readable && partial.partial)

        let none = PrivacySummary(report: PrivacyReport(grants: [], user: .noAccess, system: .noAccess))
        #expect(!none.readable && !none.partial)
        // Both lists simply absent (a fresh Mac): nothing to read is not a problem worth a Full Disk Access hint.
        let empty = PrivacySummary(report: PrivacyReport(grants: [], user: .read(0), system: .missing))
        #expect(empty.readable && empty.apps == 0)
    }

    @Test func oldHistoryWithoutAreasStillDecodes() throws {
        var session = ScanSession(targets: ["Applications"])
        session.findings = [Finding(path: "/a", severity: .warning, engine: .yara, reason: "r")]
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(session)) as? [String: Any])
        object["fullCheck"] = nil
        var findings = try #require(object["findings"] as? [[String: Any]])
        findings[0]["area"] = nil
        object["findings"] = findings
        let decoded = try JSONDecoder().decode(ScanSession.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(decoded.fullCheck == nil)

        // A Full Check saved before privacy was added has no privacy summary.
        let oldInfo = try JSONDecoder().decode(FullCheckInfo.self, from: Data(#"{"security":{"passed":1,"total":1,"problems":[]}}"#.utf8))
        #expect(oldInfo.privacy == nil && oldInfo.security?.passed == 1)
        #expect(decoded.findings.first?.area == nil)

        session.fullCheck = FullCheckInfo(security: PostureSummary(passed: 12, total: 13, problems: ["Firewall"]),
                                          privacy: PrivacySummary(apps: 13, warnings: 0, review: 7, leftovers: 6))
        session.findings[0].area = .applications
        let again = try JSONDecoder().decode(ScanSession.self, from: JSONEncoder().encode(session))
        #expect(again.fullCheck?.security?.problems == ["Firewall"])
        #expect(again.fullCheck?.privacy?.leftovers == 6)
        #expect(again.findings.first?.area == .applications)
    }

    /// A folder, the startup items and the running processes in one scan: each result lands in its area,
    /// and an app that was scanned in full keeps its own row although it is also running and starts at login.
    @Test func combinedScanAssignsAreas() async throws {
        let dir = try TempDir()
        let home = try TempDir()
        let root = try TempDir()
        let app = try dir.makeApp("Combined")
        let appBinary = app.appendingPathComponent("Contents/MacOS/Combined")
        let bad = try dir.write("bad.txt", "x")
        let agent: [String: Any] = ["Label": "com.example.combined", "ProgramArguments": [appBinary.path]]
        try home.write("Library/LaunchAgents/com.example.combined.plist",
                       PropertyListSerialization.data(fromPropertyList: agent, format: .xml, options: 0))
        let list = FakeProcessList(processes: [
            LiveProcess(pid: 100, uid: getuid(), name: "Combined", path: appBinary.path),
        ])

        let coordinator = ScanCoordinator(
            engines: [FakeEngine()], settings: ScanSettings(), logger: logger,
            persistenceLocations: PersistenceLocations(home: home.url, root: root.url, includeCrontab: false),
            processLister: list,
            browserLocations: BrowserLocations(home: home.url, safariListing: { _ in nil }))
        let targets: [ScanTarget] = [.path(dir.url), .startupItems, .runningProcesses, .browserExtensions]
        let session = await coordinator.run(targets: targets) { _ in }

        #expect(session.status == .completed)
        #expect(!session.findings.contains { $0.area == nil })
        #expect(session.findings.first { $0.path == Paths.canonical(bad).path }?.area == .files)
        #expect(session.findings.contains { $0.engine == .persistence && $0.area == .startupItems })
        #expect(session.findings.contains { $0.engine == .processes && $0.area == .runningProcesses })
        // The app was walked in full by the folder target, so it has its own clean row there.
        let appRow = try #require(session.findings.first { $0.path == Paths.canonical(app).path && $0.engine == .scanner })
        #expect(appRow.severity == .clean)
        #expect(appRow.area == .files)
        #expect(session.summary(of: .files).threats == 1)
        #expect(session.summary(of: .browserExtensions).isEmpty)
    }

    /// Unchanged behaviour for a single-target scan: the enclosing app of a running program gets no generic row.
    @Test func singleTargetScanStillHidesCoveredApp() async throws {
        let dir = try TempDir()
        let app = try dir.makeApp("Solo")
        let list = FakeProcessList(processes: [
            LiveProcess(pid: 100, uid: getuid(), name: "Solo", path: app.appendingPathComponent("Contents/MacOS/Solo").path),
        ])
        let coordinator = ScanCoordinator(engines: [FakeEngine()], settings: ScanSettings(), logger: logger, processLister: list)
        let session = await coordinator.run(targets: [.runningProcesses]) { _ in }
        #expect(!session.findings.contains { $0.engine == .scanner })
        #expect(session.findings.allSatisfy { $0.area == .runningProcesses })
    }
}
