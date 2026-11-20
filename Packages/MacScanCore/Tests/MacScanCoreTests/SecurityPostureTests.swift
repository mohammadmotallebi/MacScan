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
        let blind = await SecurityPosture(run: { _, _ in nil }, readPlist: { _ in nil }, readFile: { _ in nil }, listDirectory: { _ in nil }).check()
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
            case "scutil": PostureCommandOutput(text: arguments == ["--dns"] ? "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n" : "<dictionary> {\n}")
            case "profiles": PostureCommandOutput(text: "There are no configuration profiles installed for user 'me'")
            case "security": PostureCommandOutput(exitCode: 1, text: "No Trust Settings were found.")
            default: nil
            }
        }, readPlist: { _ in [:] }, readFile: { _ in "127.0.0.1 localhost\n" }, listDirectory: { _ in [] }).check()
        #expect(healthy.allSatisfy { $0.status == .pass })
    }
}

@Suite struct TamperCheckTests {
    @Test func hostsFile() {
        let standard = "##\n# Host Database\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n::1             localhost\n"
        #expect(SecurityPosture.hostsFile(standard).status == .pass)
        #expect(SecurityPosture.hostsFile(standard).summary == "Unchanged.")
        #expect(SecurityPosture.hostsFile(nil).status == .unknown)

        let dev = SecurityPosture.hostsFile(standard + "127.0.0.1 myapp.test api.myapp.test # dev\n0.0.0.0 ads.example.com\n")
        #expect(dev.status == .pass && dev.summary.hasPrefix("3 names point to this Mac"))

        let redirected = SecurityPosture.hostsFile(standard + "10.0.0.5 nas.home\n")
        #expect(redirected.status == .warning && redirected.summary.contains("nas.home → 10.0.0.5"))

        let blocksApple = SecurityPosture.hostsFile(standard + "127.0.0.1 ocsp.apple.com\n0.0.0.0 gs.apple.com\n")
        #expect(blocksApple.status == .warning && blocksApple.summary.contains("ocsp.apple.com"))

        let hijack = SecurityPosture.hostsFile(standard + "45.1.2.3 www.paypal.com\n45.1.2.3 accounts.google.com\n")
        #expect(hijack.status == .fail && hijack.summary.contains("www.paypal.com → 45.1.2.3"))
        // "notpaypal.com" is not paypal.com.
        #expect(SecurityPosture.hostsFile(standard + "45.1.2.3 notpaypal.com\n").status == .warning)
    }

    @Test func dnsServers() {
        func dns(_ servers: [String], scoped: [String] = []) -> PostureCommandOutput {
            var text = "DNS configuration\n\nresolver #1\n"
            for (i, s) in servers.enumerated() { text += "  nameserver[\(i)] : \(s)\n" }
            text += "  flags    : Request A records\n\nresolver #2\n  domain   : local\n  nameserver[0] : 66.66.66.66\n\n"
            text += "DNS configuration (for scoped queries)\n\nresolver #1\n"
            for (i, s) in scoped.enumerated() { text += "  nameserver[\(i)] : \(s)\n" }
            return PostureCommandOutput(text: text)
        }
        let google = SecurityPosture.dnsServers(dns(["8.8.8.8"], scoped: ["77.77.77.77"]))
        #expect(google.status == .pass && google.summary == "Uses 8.8.8.8 (Google).")
        #expect(SecurityPosture.dnsServers(dns(["192.168.1.1", "fe80::1"])).status == .pass)
        let rogue = SecurityPosture.dnsServers(dns(["192.168.1.1", "45.9.9.9"]))
        #expect(rogue.status == .warning && rogue.summary.contains("45.9.9.9 isn't a well-known"))
        #expect(SecurityPosture.dnsServers(nil).status == .unknown)
        #expect(SecurityPosture.dnsServers(dns([])).summary == "None set (not connected).")
    }

    @Test func webProxy() {
        let none = PostureCommandOutput(text: "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  FTPPassive : 1\n}\n")
        #expect(SecurityPosture.webProxy(none).status == .pass)
        let proxy = PostureCommandOutput(text: "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 10.1.1.1\n  HTTPPort : 8080\n  HTTPSEnable : 0\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://evil.example/proxy.pac\n}\n")
        let found = SecurityPosture.webProxy(proxy)
        #expect(found.status == .warning)
        #expect(found.summary.contains("web proxy 10.1.1.1:8080") && found.summary.contains("http://evil.example/proxy.pac"))
        #expect(!found.summary.contains("secure web"))
        #expect(SecurityPosture.webProxy(nil).status == .unknown)
    }

    @Test func profiles() {
        #expect(SecurityPosture.profiles(PostureCommandOutput(text: "There are no configuration profiles installed for user 'me'")).status == .pass)
        let installed = SecurityPosture.profiles(PostureCommandOutput(text: "_computerlevel[1] attribute: profileIdentifier: com.adware.search\nme[2] attribute: profileIdentifier: com.work.wifi\n"))
        #expect(installed.status == .warning && installed.summary.hasPrefix("2 installed: com.adware.search, com.work.wifi"))
        #expect(SecurityPosture.profiles(PostureCommandOutput(text: "profiles: something odd")).status == .unknown)
        #expect(SecurityPosture.profiles(nil).status == .unknown)
    }

    @Test func trustedCertificates() {
        let none = PostureCommandOutput(exitCode: 1, text: "SecTrustSettingsCopyCertificates: No Trust Settings were found.")
        #expect(SecurityPosture.trustedCertificates(user: none, admin: none).status == .pass)
        #expect(SecurityPosture.trustedCertificates(user: nil, admin: nil).status == .unknown)

        let dev = PostureCommandOutput(text: "Number of trusted certs = 2\nCert 0: mkcert me@laptop (Me)\n   Number of trust settings : 2\nCert 1: Laravel Valet CA Self Signed CN\n")
        let devResult = SecurityPosture.trustedCertificates(user: none, admin: dev)
        #expect(devResult.status == .pass)
        #expect(devResult.summary == "Only certificates from development tools you installed: mkcert me@laptop (Me), Laravel Valet CA Self Signed CN.")

        let odd = PostureCommandOutput(text: "Number of trusted certs = 2\nCert 0: Totally Legit Root CA\nCert 1: Charles Proxy CA (1 Jan 2026)\n")
        let oddResult = SecurityPosture.trustedCertificates(user: odd, admin: dev)
        #expect(oddResult.status == .warning)
        #expect(oddResult.summary.contains("Added: Totally Legit Root CA.") && oddResult.summary.contains("Debugging proxy: Charles Proxy CA"))
        #expect(oddResult.summary.contains("Development tools: mkcert"))
    }

    @Test func sudoRules() {
        #expect(SecurityPosture.sudoRules([]).status == .pass)
        #expect(SecurityPosture.sudoRules([".placeholder"]).status == .pass)
        #expect(SecurityPosture.sudoRules(nil).status == .unknown)
        let herd = SecurityPosture.sudoRules(["herd"])
        #expect(herd.status == .pass && herd.summary.contains("herd"))
        let other = SecurityPosture.sudoRules(["herd", "zz-updater"])
        #expect(other.status == .warning && other.summary.contains("herd, zz-updater"))
    }

    @Test func groups() {
        #expect(PostureCheckID.hostsFile.group == .tampering)
        #expect(PostureCheckID.sip.group == .protections)
        #expect(PostureCheckID.allCases.filter { $0.group == .tampering }.count == 6)
    }
}
