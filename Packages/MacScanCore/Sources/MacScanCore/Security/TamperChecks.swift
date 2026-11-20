import Foundation

/// Settings adware and malware change instead of (or as well as) dropping a file. All read-only.
extension SecurityPosture {

    // MARK: Hosts file

    /// The lines macOS ships with.
    static let standardHosts: Set<String> = ["127.0.0.1 localhost", "255.255.255.255 broadcasthost", "::1 localhost", "fe80::1%lo0 localhost"]

    /// Sites that are worth hijacking: a redirect of one of these is a fail.
    static let majorSites = [
        "apple.com", "icloud.com", "mzstatic.com", "google.com", "googleapis.com", "gstatic.com", "youtube.com",
        "microsoft.com", "live.com", "office.com", "windowsupdate.com", "facebook.com", "instagram.com", "whatsapp.com",
        "amazon.com", "paypal.com", "github.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
        "binance.com", "coinbase.com", "kraken.com", "blockchain.com", "metamask.io",
    ]

    /// Apple servers that check software is safe; blocking them stops those checks.
    static let appleSecurityHosts = ["ocsp.apple.com", "ocsp2.apple.com", "gs.apple.com", "swscan.apple.com", "swdist.apple.com",
                                     "xp.apple.com", "api.apple-cloudkit.com", "mesu.apple.com", "valid.apple.com", "crl.apple.com"]

    static func isLoopback(_ address: String) -> Bool {
        address.hasPrefix("127.") || address == "0.0.0.0" || address == "::1" || address == "::" || address.hasPrefix("fe80::1%lo")
    }

    static func matches(_ host: String, _ domain: String) -> Bool {
        host == domain || host.hasSuffix("." + domain)
    }

    static func hostsFile(_ text: String?) -> PostureCheck {
        let title = "Hosts file"
        guard let text else { return unknown(.hostsFile, title) }
        var blocked: [String] = []
        var redirected: [String] = []
        var hijacked: [String] = []
        var securityBlocked: [String] = []
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map { String($0).lowercased() }
            guard fields.count >= 2 else { continue }
            let address = fields[0]
            for host in fields.dropFirst() where !standardHosts.contains("\(address) \(host)") {
                if isLoopback(address) {
                    if appleSecurityHosts.contains(where: { matches(host, $0) }) { securityBlocked.append(host) } else { blocked.append(host) }
                } else if majorSites.contains(where: { matches(host, $0) }) {
                    hijacked.append("\(host) → \(address)")
                } else {
                    redirected.append("\(host) → \(address)")
                }
            }
        }
        func list(_ items: [String]) -> String { items.prefix(4).joined(separator: ", ") + (items.count > 4 ? ", …" : "") }
        if !hijacked.isEmpty {
            return PostureCheck(id: .hostsFile, title: title, status: .fail,
                                summary: "Sends well-known sites to another address: \(list(hijacked)). This is how fake login pages are served.",
                                advice: "Unless you added these yourself, remove the lines from /etc/hosts and change the passwords you used on those sites.")
        }
        if !securityBlocked.isEmpty {
            return PostureCheck(id: .hostsFile, title: title, status: .warning,
                                summary: "Blocks Apple's security servers: \(list(securityBlocked)). macOS can't check apps or get security updates.",
                                advice: "Cracked apps often add these lines. Remove them from /etc/hosts unless you know why they are there.")
        }
        if !redirected.isEmpty {
            return PostureCheck(id: .hostsFile, title: title, status: .warning,
                                summary: "\(redirected.count) name\(redirected.count == 1 ? " points" : "s point") to another address: \(list(redirected)).",
                                advice: "Fine if you set this up (for example for development). Otherwise remove the lines from /etc/hosts.")
        }
        if !blocked.isEmpty {
            return PostureCheck(id: .hostsFile, title: title, status: .pass,
                                summary: "\(blocked.count) name\(blocked.count == 1 ? " points" : "s point") to this Mac (blocked, or local development): \(list(blocked)).")
        }
        return PostureCheck(id: .hostsFile, title: title, status: .pass, summary: "Unchanged.")
    }

    // MARK: DNS

    /// Well-known public DNS services.
    static let knownDNS: [String: String] = [
        "8.8.8.8": "Google", "8.8.4.4": "Google", "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
        "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare", "1.0.0.2": "Cloudflare", "1.1.1.3": "Cloudflare", "1.0.0.3": "Cloudflare",
        "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
        "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
        "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS", "208.67.222.123": "OpenDNS", "208.67.220.123": "OpenDNS",
        "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard", "76.76.2.0": "Control D", "76.76.10.0": "Control D",
        "185.228.168.9": "CleanBrowsing", "185.228.169.9": "CleanBrowsing", "45.90.28.0": "NextDNS", "45.90.30.0": "NextDNS",
    ]

    /// `scutil --dns`: the servers of resolvers that aren't limited to one domain (those are the ones used for everything).
    static func dnsServers(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "DNS servers"
        guard let text = output?.text, text.contains("resolver") else { return unknown(.dnsServers, title, settings: Pane.network) }
        var servers: [String] = []
        // Only the first block ("DNS configuration"); the second lists the same resolvers per interface.
        let main = text.components(separatedBy: "DNS configuration (for scoped queries)").first ?? text
        for block in main.components(separatedBy: "resolver #").dropFirst() {
            if block.contains("domain   :") || block.contains("domain :") { continue }
            for line in block.split(whereSeparator: \.isNewline) where line.contains("nameserver[") {
                if let value = line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces), !servers.contains(value) {
                    servers.append(value)
                }
            }
        }
        if servers.isEmpty {
            return PostureCheck(id: .dnsServers, title: title, status: .pass, summary: "None set (not connected).", settingsURL: Pane.network)
        }
        let unknownServers = servers.filter { knownDNS[$0] == nil && NetworkScope.of($0) == .internet }
        let names = servers.map { server in
            if let name = knownDNS[server] { return "\(server) (\(name))" }
            return NetworkScope.of(server) == .internet ? server : "\(server) (\(NetworkScope.of(server).title))"
        }
        if !unknownServers.isEmpty {
            return PostureCheck(id: .dnsServers, title: title, status: .warning,
                                summary: "Uses \(names.joined(separator: ", ")). \(unknownServers.joined(separator: ", ")) \(unknownServers.count == 1 ? "isn't" : "aren't") a well-known DNS service. A rogue DNS server can send you to fake sites.",
                                advice: "Fine if it's your internet provider's or your VPN's. If you don't know it, set DNS back to automatic in Network › Details › DNS.",
                                settingsURL: Pane.network)
        }
        return PostureCheck(id: .dnsServers, title: title, status: .pass, summary: "Uses \(names.joined(separator: ", ")).", settingsURL: Pane.network)
    }

    // MARK: Proxy

    /// `scutil --proxy` prints a dictionary such as "HTTPEnable : 1", "HTTPProxy : 1.2.3.4", "ProxyAutoConfigURLString : …".
    static func webProxy(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "Web proxy"
        guard let text = output?.text, text.contains("<dictionary>") else { return unknown(.webProxy, title, settings: Pane.network) }
        var values: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 { values[parts[0]] = parts[1] }
        }
        var found: [String] = []
        for (kind, prefix) in [("web", "HTTP"), ("secure web", "HTTPS"), ("SOCKS", "SOCKS")] where values["\(prefix)Enable"] == "1" {
            found.append("\(kind) proxy \(values["\(prefix)Proxy"] ?? "?")" + (values["\(prefix)Port"].map { ":\($0)" } ?? ""))
        }
        if values["ProxyAutoConfigEnable"] == "1" {
            found.append("automatic proxy file \(values["ProxyAutoConfigURLString"] ?? "?")")
        }
        if found.isEmpty {
            let auto = values["ProxyAutoDiscoveryEnable"] == "1" ? " Automatic proxy discovery is on." : ""
            return PostureCheck(id: .webProxy, title: title, status: .pass, summary: "None set." + auto, settingsURL: Pane.network)
        }
        return PostureCheck(id: .webProxy, title: title, status: .warning,
                            summary: "Your traffic goes through: \(found.joined(separator: "; ")). Whoever runs the proxy can see the sites you visit.",
                            advice: "Fine if your work or school set this up. Otherwise turn it off in Network › Details › Proxies; adware often adds one.",
                            settingsURL: Pane.network)
    }

    // MARK: Configuration profiles

    /// `profiles list` (as the user) prints "There are no configuration profiles installed…" or one line per profile.
    static func profiles(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "Configuration profiles"
        guard let text = output?.text, !text.isEmpty else { return unknown(.profiles, title, settings: Pane.profiles) }
        if text.contains("There are no configuration profiles installed") {
            return PostureCheck(id: .profiles, title: title, status: .pass,
                                summary: "None installed for your account. (Profiles for the whole Mac are listed in System Settings › Privacy & Security › Profiles.)",
                                settingsURL: Pane.profiles)
        }
        var identifiers: [String] = []
        for line in text.split(whereSeparator: \.isNewline) {
            if let range = line.range(of: "profileIdentifier:") {
                identifiers.append(line[range.upperBound...].trimmingCharacters(in: .whitespaces))
            }
        }
        guard !identifiers.isEmpty else { return unknown(.profiles, title, settings: Pane.profiles) }
        return PostureCheck(id: .profiles, title: title, status: .warning,
                            summary: "\(identifiers.count) installed: \(identifiers.prefix(4).joined(separator: ", "))\(identifiers.count > 4 ? ", …" : ""). A profile can force browser settings, certificates, proxies or a VPN.",
                            advice: "Fine if your work or school manages this Mac. Otherwise remove unknown profiles in Privacy & Security › Profiles.",
                            settingsURL: Pane.profiles)
    }

    // MARK: Trusted certificates

    /// Root certificates that local development tools create for "https://localhost".
    static let developmentCertificates = ["mkcert", "laravel valet", "herd", "localhost", "devcert", "caddy local authority", "ddev", "lando", "docker desktop"]
    /// Debugging proxies that read encrypted traffic by design.
    static let interceptingProxies = ["charles proxy", "mitmproxy", "proxyman", "fiddler", "burp", "http toolkit", "zscaler", "netskope"]

    /// `security dump-trust-settings` lists "Cert N: <name>" for certificates someone marked as trusted.
    static func certificateNames(_ output: PostureCommandOutput?) -> [String]? {
        guard let text = output?.text else { return nil }
        if text.contains("No Trust Settings were found") { return [] }
        let names = text.split(whereSeparator: \.isNewline).compactMap { line -> String? in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("Cert "), let colon = trimmed.firstIndex(of: ":") else { return nil }
            return trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        return names.isEmpty && !text.contains("Number of trusted certs") ? nil : names
    }

    static func trustedCertificates(user: PostureCommandOutput?, admin: PostureCommandOutput?) -> PostureCheck {
        let title = "Trusted certificates"
        let lists = [certificateNames(user), certificateNames(admin)]
        guard lists.contains(where: { $0 != nil }) else { return unknown(.trustedCertificates, title) }
        var names: [String] = []
        for name in lists.compactMap({ $0 }).joined() where !names.contains(name) { names.append(name) }
        if names.isEmpty {
            return PostureCheck(id: .trustedCertificates, title: title, status: .pass, summary: "None added. Only Apple's built-in list is trusted.")
        }
        func isOne(of list: [String], _ name: String) -> Bool { list.contains { name.lowercased().contains($0) } }
        let proxies = names.filter { isOne(of: interceptingProxies, $0) }
        let development = names.filter { isOne(of: developmentCertificates, $0) && !proxies.contains($0) }
        let other = names.filter { !proxies.contains($0) && !development.contains($0) }
        let devNote = development.isEmpty ? "" : " Development tools: \(development.joined(separator: ", "))."
        if !other.isEmpty || !proxies.isEmpty {
            var parts: [String] = []
            if !other.isEmpty { parts.append("Added: \(other.joined(separator: ", ")).") }
            if !proxies.isEmpty { parts.append("Debugging proxy: \(proxies.joined(separator: ", ")).") }
            return PostureCheck(id: .trustedCertificates, title: title, status: .warning,
                                summary: parts.joined(separator: " ") + devNote + " Whoever holds such a certificate can read your secure (https) traffic.",
                                advice: "Fine if your work or a tool you use added it. Otherwise open Keychain Access, find the certificate and delete it.")
        }
        return PostureCheck(id: .trustedCertificates, title: title, status: .pass,
                            summary: "Only certificates from development tools you installed: \(development.joined(separator: ", ")).")
    }

    // MARK: sudo rules

    /// Rule files that local development tools install so they can restart their services.
    static let developmentSudoers = ["herd", "valet", "brew", "orbstack", "docker"]

    static func sudoRules(_ files: [String]?) -> PostureCheck {
        let title = "Extra administrator rules"
        guard let files else { return unknown(.sudoRules, title) }
        let names = files.filter { !$0.hasPrefix(".") }.sorted()
        if names.isEmpty {
            return PostureCheck(id: .sudoRules, title: title, status: .pass, summary: "None in /etc/sudoers.d.")
        }
        let development = names.filter { name in developmentSudoers.contains { name.lowercased().contains($0) } }
        let other = names.filter { !development.contains($0) }
        if other.isEmpty {
            return PostureCheck(id: .sudoRules, title: title, status: .pass,
                                summary: "Only rules from development tools you installed: \(development.joined(separator: ", ")) (in /etc/sudoers.d).")
        }
        return PostureCheck(id: .sudoRules, title: title, status: .warning,
                            summary: "Rule files in /etc/sudoers.d: \(names.joined(separator: ", ")). They can let programs run as administrator without asking for your password.",
                            advice: "Fine if a tool you trust added them. Only an administrator can read or remove them (`sudo cat /etc/sudoers.d/<name>`).")
    }
}
