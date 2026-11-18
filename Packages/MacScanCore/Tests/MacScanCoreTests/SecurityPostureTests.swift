import Foundation
import Testing
@testable import MacScanCore

@Suite struct SecurityPostureTests {
    func out(_ text: String) -> PostureCommandOutput { PostureCommandOutput(text: text) }

    @Test func sipGatekeeperFileVaultFirewall() {
        #expect(SecurityPosture.sip(out("System Integrity Protection status: enabled.")).status == .pass)
        #expect(SecurityPosture.sip(out("System Integrity Protection status: disabled.")).status == .fail)
        #expect(SecurityPosture.sip(out("System Integrity Protection status: enabled (Custom Configuration).")).status == .warning)
        #expect(SecurityPosture.sip(out("System Integrity Protection status: unknown (Custom Configuration).")).status == .warning)
        #expect(SecurityPosture.sip(nil).status == .unknown)
        #expect(SecurityPosture.sip(out("garbage")).status == .unknown)

        #expect(SecurityPosture.gatekeeper(out("assessments enabled")).status == .pass)
        #expect(SecurityPosture.gatekeeper(out("assessments disabled")).status == .fail)
        #expect(SecurityPosture.gatekeeper(out("")).status == .unknown)

        #expect(SecurityPosture.fileVault(out("FileVault is On.")).status == .pass)
        #expect(SecurityPosture.fileVault(out("FileVault is Off.")).status == .warning)
        #expect(SecurityPosture.fileVault(out("FileVault is On.\nEncryption in progress: Percent completed = 12")).summary.contains("still in progress"))

        #expect(SecurityPosture.firewall(out("Firewall is disabled. (State = 0)")).status == .warning)
        #expect(SecurityPosture.firewall(out("Firewall is enabled. (State = 1)")).status == .pass)
        #expect(SecurityPosture.firewall(out("Firewall is set to block all non-essential incoming connections. (State = 2)")).summary == "On, blocking all incoming connections.")
        #expect(SecurityPosture.firewall(out("nope")).status == .unknown)
    }

    @Test func xprotectAge() throws {
        let formatter = ISO8601DateFormatter()
        let now = try #require(formatter.date(from: "2026-11-18T12:00:00Z"))
        let fresh = SecurityPosture.xprotect(out("Version: 5372 Installed: 2026-11-11 20:06:26 +0000"), now: now)
        #expect(fresh.status == .pass)
        #expect(fresh.summary == "Version 5372, updated 6 days ago.")
        let stale = SecurityPosture.xprotect(out("Version: 5300 Installed: 2026-07-01 08:00:00 +0000"), now: now)
        #expect(stale.status == .warning)
        #expect(SecurityPosture.xprotect(out("Version: 5372"), now: now).summary == "Version 5372.")
        #expect(SecurityPosture.xprotect(out("xprotect: command not found"), now: now).status == .unknown)
    }

    @Test func updates() {
        #expect(SecurityPosture.updates(out("Software Update Tool\n\nNo new software available.")).status == .pass)
        let waiting = SecurityPosture.updates(out("""
        Software Update Tool

        Software Update found the following new or updated software:
        * Label: macOS 27.3-26C100
        \tTitle: macOS 27.3, Version: 27.3, Size: 5000000KiB, Recommended: YES, Action: restart,
        * Label: Safari27.3-27.3
        """))
        #expect(waiting.status == .warning)
        #expect(waiting.summary == "2 updates waiting: macOS 27.3-26C100, Safari27.3-27.3")
        #expect(SecurityPosture.updates(out("something else")).status == .unknown)

        #expect(SecurityPosture.autoUpdates(["AutomaticDownload": true]).status == .pass, "absent keys are the default: on")
        let off = SecurityPosture.autoUpdates(["CriticalUpdateInstall": false, "AutomaticCheckEnabled": false])
        #expect(off.status == .warning)
        #expect(off.summary.contains("checking for updates; installing Security Responses"))
        #expect(SecurityPosture.autoUpdates(nil).status == .unknown)
    }

    @Test func loginAndLock() {
        #expect(SecurityPosture.screenLock(out("2026-11-18 14:17:05.436 sysadminctl[1:2] screenLock delay is immediate")).status == .pass)
        #expect(SecurityPosture.screenLock(out("screenLock delay is 300 seconds")).summary == "Required after 5 minutes.")
        #expect(SecurityPosture.screenLock(out("screenLock delay is 3600 seconds")).status == .warning)
        #expect(SecurityPosture.screenLock(out("screenLock is off")).status == .warning)
        #expect(SecurityPosture.screenLock(out("You need administrator access")).status == .unknown)

        #expect(SecurityPosture.autoLogin([:]).status == .pass)
        #expect(SecurityPosture.autoLogin(["autoLoginUser": "sam"]).status == .warning)
        #expect(SecurityPosture.guestAccount(out("Guest account disabled.")).status == .pass)
        #expect(SecurityPosture.guestAccount(out("Guest account enabled.")).status == .warning)
    }

    @Test func sharingServices() {
        let listing = out("""
        \tdisabled services = {
        \t\t"com.openssh.sshd" => enabled
        \t\t"com.apple.screensharing" => disabled
        \t}
        """)
        #expect(SecurityPosture.sharing(.remoteLogin, title: "t", label: "com.openssh.sshd", listing, risk: "r").status == .warning)
        #expect(SecurityPosture.sharing(.screenSharing, title: "t", label: "com.apple.screensharing", listing, risk: "r").status == .pass)
        #expect(SecurityPosture.sharing(.fileSharing, title: "t", label: "com.apple.smbd", listing, risk: "r").status == .pass, "never toggled means off")
        #expect(SecurityPosture.sharing(.fileSharing, title: "t", label: "com.apple.smbd", nil, risk: "r").status == .unknown)
    }

    @Test func runsEveryCheckOnceAndNeverGuesses() async {
        // Every tool fails: nothing may be reported as a pass.
        let blind = await SecurityPosture(run: { _, _ in nil }, readPlist: { _ in nil }).check()
        #expect(blind.map(\.id) == PostureCheckID.allCases)
        #expect(blind.allSatisfy { $0.status == .unknown })

        let healthy = await SecurityPosture(run: { tool, arguments in
            switch (tool as NSString).lastPathComponent {
            case "csrutil": PostureCommandOutput(text: "System Integrity Protection status: enabled.")
            case "spctl": PostureCommandOutput(text: "assessments enabled")
            case "fdesetup": PostureCommandOutput(text: "FileVault is On.")
            case "socketfilterfw": PostureCommandOutput(text: "Firewall is enabled. (State = 1)")
            case "xprotect": PostureCommandOutput(text: "Version: 1")
            case "softwareupdate": PostureCommandOutput(text: "No new software available.")
            case "sysadminctl": PostureCommandOutput(text: arguments.contains("-screenLock") ? "screenLock delay is immediate" : "Guest account disabled.")
            case "launchctl": PostureCommandOutput(text: "disabled services = {\n}")
            default: nil
            }
        }, readPlist: { _ in [:] }).check()
        #expect(healthy.allSatisfy { $0.status == .pass })
    }
}
