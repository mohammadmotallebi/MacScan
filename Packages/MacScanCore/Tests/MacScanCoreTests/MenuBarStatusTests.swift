import Foundation
import Testing
@testable import MacScanCore

@Suite struct MenuBarStatusTests {
    let now = Date(timeIntervalSince1970: 1_000_000)

    func finding(_ severity: Severity) -> Finding {
        Finding(path: "/Applications/A.app", severity: severity, engine: .integrity, reason: "x")
    }

    func fullCheck(minutesAgo: Double, findings: [Finding] = [], info: FullCheckInfo = FullCheckInfo(),
                   status: ScanStatus = .completed) -> ScanSession {
        var session = ScanSession(startedAt: now.addingTimeInterval(-minutesAgo * 60 - 120), targets: ["Applications"])
        session.finishedAt = now.addingTimeInterval(-minutesAgo * 60)
        session.findings = findings
        session.fullCheck = info
        session.status = status
        return session
    }

    @Test func noFullCheckYet() {
        let plain = ScanSession(startedAt: now)   // not a Full Check
        let status = MenuBarStatus(history: [plain], isScanning: false, now: now)
        #expect(status.level == .unknown && status.badgeSymbol == nil)
        #expect(status.title == "No Full Check yet" && status.sessionID == nil)
        #expect(MenuBarStatus(history: [], isScanning: true, now: now).level == .scanning)
    }

    @Test func clearResult() {
        let session = fullCheck(minutesAgo: 130, findings: [finding(.clean)],
                                info: FullCheckInfo(security: PostureSummary(passed: 19, total: 19, problems: [])))
        let status = MenuBarStatus(history: [session], isScanning: false, now: now)
        #expect(status.level == .clear && status.badgeSymbol == nil)
        #expect(status.title == "Last Full Check: 2 hours ago")
        #expect(status.detail == "Nothing needs attention.")
        #expect(status.sessionID == session.id)
        #expect(status.tooltip == "MacScan\nLast Full Check: 2 hours ago\nNothing needs attention.")
    }

    @Test func attentionAndThreats() {
        var info = FullCheckInfo(security: PostureSummary(passed: 17, total: 19, problems: ["Firewall", "FileVault"]))
        info.privacy = PrivacySummary(apps: 5, warnings: 1, review: 2, leftovers: 0, readable: true, partial: false)
        info.changes = [FullCheckChange(kind: .newApp, title: "Zoom", detail: "x"),
                        FullCheckChange(kind: .settingFixed, title: "Guest", detail: "y")]
        let warn = fullCheck(minutesAgo: 5, findings: [finding(.warning), finding(.warning)], info: info)
        let status = MenuBarStatus(history: [warn], isScanning: false, now: now)
        #expect(status.level == .attention && status.badgeSymbol == "exclamationmark.circle")
        #expect(status.detail == "2 warnings · 2 settings off · 1 risky permission · 1 change")
        #expect(status.title == "Last Full Check: 5 minutes ago")

        let bad = fullCheck(minutesAgo: 0.2, findings: [finding(.threat), finding(.warning)])
        let threat = MenuBarStatus(history: [bad], isScanning: false, now: now)
        #expect(threat.level == .threat && threat.badgeSymbol == "exclamationmark.circle.fill" && threat.detail == "1 threat · 1 warning")
        #expect(threat.title == "Last Full Check: just now")
    }

    @Test func skipsUnfinishedAndShowsScanning() {
        let old = fullCheck(minutesAgo: 60 * 30, findings: [finding(.threat)])
        let cancelled = fullCheck(minutesAgo: 1, status: .cancelled)
        let status = MenuBarStatus(history: [cancelled, old], isScanning: false, now: now)
        #expect(status.sessionID == old.id && status.title == "Last Full Check: yesterday")

        let busy = MenuBarStatus(history: [cancelled, old], isScanning: true, now: now)
        #expect(busy.level == .scanning && busy.title == "Scanning…" && busy.detail == "1 threat")
    }

    @Test func ages() {
        #expect(MenuBarStatus.ago(now.addingTimeInterval(-61), now: now) == "1 minute ago")
        #expect(MenuBarStatus.ago(now.addingTimeInterval(-3600), now: now) == "1 hour ago")
        #expect(MenuBarStatus.ago(now.addingTimeInterval(-86400 * 4), now: now) == "4 days ago")
        #expect(MenuBarStatus.ago(now.addingTimeInterval(60), now: now) == "just now")
    }

    @Test func settingDefaultsOn() throws {
        #expect(ScanSettings().showInMenuBar == true)
        let old = try JSONDecoder().decode(ScanSettings.self, from: Data("{}".utf8))
        #expect(old.showInMenuBar == true)
    }
}
