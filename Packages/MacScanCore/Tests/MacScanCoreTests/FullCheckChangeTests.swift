import Foundation
import Testing
@testable import MacScanCore

@Suite struct FullCheckChangeTests {
    func app(_ name: String, _ severity: Severity = .clean) -> Finding {
        var f = Finding(path: "/Applications/\(name).app", severity: severity, engine: .scanner, reason: "r")
        f.area = .applications
        return f
    }

    func session(_ apps: [Finding], status: ScanStatus = .completed, at date: Date = Date()) -> ScanSession {
        var s = ScanSession(startedAt: date, targets: ["Applications"])
        s.findings = apps
        s.status = status
        s.fullCheck = FullCheckInfo()
        return s
    }

    func grant(_ client: String, _ permission: PrivacyPermission, decision: PrivacyDecision = .allowed) -> PrivacyGrant {
        PrivacyGrant(permission: permission, client: client, name: client, path: "/Applications/\(client).app", decision: decision, detail: nil,
                     signer: nil, risk: .none, reasons: [], modified: nil, services: [])
    }

    func report(_ grants: [PrivacyGrant], readable: Bool = true) -> PrivacyReport {
        PrivacyReport(grants: grants, user: readable ? .read(1) : .noAccess, system: readable ? .read(1) : .noAccess)
    }

    func check(_ id: PostureCheckID, _ status: PostureStatus, _ summary: String = "s") -> PostureCheck {
        PostureCheck(id: id, title: id.rawValue, status: status, summary: summary)
    }

    @Test func firstThenChanges() throws {
        let dir = try TempDir()
        let tracker = FullCheckChangeTracker(file: dir.url.appendingPathComponent("baseline.json"))

        var first = session([app("Old")], at: Date(timeIntervalSince1970: 1_000))
        tracker.apply(to: &first, checks: [check(.firewall, .pass), check(.webProxy, .pass), check(.dnsServers, .warning, "a")],
                      privacy: report([grant("Zoom", .camera)]))
        #expect(first.fullCheck?.changes == nil && first.fullCheck?.comparedWith == nil && first.fullCheck?.tracked == true)

        var second = session([app("Old"), app("New", .warning)])
        tracker.apply(to: &second, checks: [
            check(.firewall, .warning, "Off."), check(.webProxy, .pass), check(.dnsServers, .warning, "b"),
        ], privacy: report([grant("Zoom", .camera), grant("Zoom", .screenRecording), grant("Notes", .contacts), grant("Spy", .microphone, decision: .denied)]))
        let info = try #require(second.fullCheck)
        #expect(info.comparedWith == Date(timeIntervalSince1970: 1_000))
        let changes = try #require(info.changes)
        #expect(changes.map(\.kind) == [.settingChanged, .settingChanged, .newPermission, .newApp])
        #expect(changes[0].title == "firewall" && changes[0].detail == "Off.")
        #expect(changes[1].title == "dnsServers" && changes[1].detail == "b")
        #expect(changes[2].title == "Zoom" && changes[2].detail == "Can now use Screen Recording.")
        #expect(changes[3] == FullCheckChange(kind: .newApp, title: "New", detail: "Installed since the last check, with warnings.", path: "/Applications/New.app"))

        // Nothing changed the third time; the firewall fixed the fourth.
        var third = session([app("Old"), app("New", .warning)])
        tracker.apply(to: &third, checks: [check(.firewall, .warning, "Off."), check(.dnsServers, .warning, "b")],
                      privacy: report([grant("Zoom", .camera), grant("Zoom", .screenRecording)]))
        #expect(third.fullCheck?.changes == [])
        var fourth = session([app("Old")])
        tracker.apply(to: &fourth, checks: [check(.firewall, .pass, "On.")], privacy: report([]))
        #expect(fourth.fullCheck?.changes == [FullCheckChange(kind: .settingFixed, title: "firewall", detail: "On.")])
        #expect(fourth.fullCheck?.changes?.first?.needsAttention == false)
    }

    @Test func incompleteScansAndUnreadablePermissions() throws {
        let dir = try TempDir()
        let file = dir.url.appendingPathComponent("baseline.json")
        let tracker = FullCheckChangeTracker(file: file)

        // A cancelled check neither compares nor saves.
        var cancelled = session([app("A")], status: .cancelled)
        tracker.apply(to: &cancelled, checks: [], privacy: nil)
        #expect(!FileManager.default.fileExists(atPath: file.path))
        #expect(cancelled.fullCheck?.tracked == nil)

        var first = session([app("A")])
        tracker.apply(to: &first, checks: [check(.firewall, .pass)], privacy: report([grant("Zoom", .camera)]))

        // Permissions unreadable: not compared, and the old ones are kept. An unknown check is skipped too.
        var blind = session([app("A")])
        tracker.apply(to: &blind, checks: [check(.firewall, .unknown)], privacy: report([], readable: false))
        #expect(blind.fullCheck?.changes == [])

        // Readable again: Zoom's camera is still known, only the new one shows.
        var again = session([app("A")])
        tracker.apply(to: &again, checks: [check(.firewall, .pass)], privacy: report([grant("Zoom", .camera), grant("Zoom", .microphone)]))
        #expect(again.fullCheck?.changes?.map(\.detail) == ["Can now use Microphone."])

        tracker.forget()
        #expect(!FileManager.default.fileExists(atPath: file.path))
    }

    @Test func olderBaselineWithoutPermissionsDoesNotFlood() throws {
        let dir = try TempDir()
        let file = dir.url.appendingPathComponent("baseline.json")
        try Data(#"{"date":"2026-11-01T00:00:00Z","apps":["/Applications/A.app"],"checks":{}}"#.utf8).write(to: file)
        var s = session([app("A")])
        FullCheckChangeTracker(file: file).apply(to: &s, checks: [check(.firewall, .pass)], privacy: report([grant("Zoom", .camera)]))
        #expect(s.fullCheck?.changes == [])
    }

    @Test func oldHistoryDecodes() throws {
        let info = try JSONDecoder().decode(FullCheckInfo.self, from: Data(#"{"security":{"passed":1,"total":1,"problems":[]}}"#.utf8))
        #expect(info.changes == nil && info.comparedWith == nil && info.tracked == nil)
        var withChanges = FullCheckInfo()
        withChanges.changes = [FullCheckChange(kind: .newApp, title: "X", detail: "d", path: "/Applications/X.app")]
        withChanges.comparedWith = Date(timeIntervalSince1970: 5)
        #expect(try JSONDecoder().decode(FullCheckInfo.self, from: JSONEncoder().encode(withChanges)) == withChanges)
    }
}
