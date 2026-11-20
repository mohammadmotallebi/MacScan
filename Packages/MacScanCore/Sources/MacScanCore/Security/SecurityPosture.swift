import Foundation

public enum PostureStatus: String, Sendable, CaseIterable {
    case pass
    case warning
    case fail
    /// The check couldn't be read; never treated as a pass.
    case unknown
}

public enum PostureCheckID: String, Sendable, CaseIterable {
    case sip, gatekeeper, fileVault, firewall, xprotect, updates, autoUpdates
    case screenLock, autoLogin, guestAccount, remoteLogin, screenSharing, fileSharing
    case hostsFile, dnsServers, webProxy, profiles, trustedCertificates, sudoRules

    public var group: PostureGroup {
        switch self {
        case .hostsFile, .dnsServers, .webProxy, .profiles, .trustedCertificates, .sudoRules: .tampering
        default: .protections
        }
    }
}

/// How the Security section groups its rows.
public enum PostureGroup: String, Sendable, CaseIterable, Identifiable {
    /// macOS's built-in protections.
    case protections
    /// Settings that adware and malware change instead of dropping a file.
    case tampering

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .protections: "macOS protections"
        case .tampering: "Signs of tampering"
        }
    }
}

/// One of macOS's own protections and whether it is on.
public struct PostureCheck: Identifiable, Hashable, Sendable {
    public let id: PostureCheckID
    public var title: String
    public var status: PostureStatus
    /// What was found, in one line.
    public var summary: String
    /// What to do about it (nil when there is nothing to do).
    public var advice: String?
    /// The System Settings pane where this is changed, if there is one.
    public var settingsURL: URL?

    public var group: PostureGroup { id.group }

    public init(id: PostureCheckID, title: String, status: PostureStatus, summary: String, advice: String? = nil, settingsURL: URL? = nil) {
        self.id = id
        self.title = title
        self.status = status
        self.summary = summary
        self.advice = advice
        self.settingsURL = settingsURL
    }
}

/// What a system tool printed (stdout and stderr together).
public struct PostureCommandOutput: Sendable {
    public var exitCode: Int32
    public var text: String

    public init(exitCode: Int32 = 0, text: String) {
        self.exitCode = exitCode
        self.text = text
    }
}

/// Reads the state of macOS's built-in protections with the system's own status tools. Read-only: it
/// never changes a setting, and never asks for a password.
public struct SecurityPosture: Sendable {
    public typealias Runner = @Sendable (_ tool: String, _ arguments: [String]) async -> PostureCommandOutput?
    public typealias PlistReader = @Sendable (_ path: String) -> [String: any Sendable]?
    public typealias FileReader = @Sendable (_ path: String) -> String?
    public typealias DirectoryLister = @Sendable (_ path: String) -> [String]?

    let run: Runner
    let readPlist: PlistReader
    let readFile: FileReader
    let listDirectory: DirectoryLister
    let now: Date

    public init(run: @escaping Runner = SecurityPosture.systemRunner, readPlist: @escaping PlistReader = SecurityPosture.systemPlistReader,
                readFile: @escaping FileReader = { try? String(contentsOfFile: $0, encoding: .utf8) },
                listDirectory: @escaping DirectoryLister = { try? FileManager.default.contentsOfDirectory(atPath: $0) },
                now: Date = Date()) {
        self.run = run
        self.readPlist = readPlist
        self.readFile = readFile
        self.listDirectory = listDirectory
        self.now = now
    }

    public static let systemRunner: Runner = { tool, arguments in
        guard FileManager.default.isExecutableFile(atPath: tool),
              let result = try? await ProcessRunner.run(URL(fileURLWithPath: tool), arguments) else { return nil }
        return PostureCommandOutput(exitCode: result.exitCode, text: result.stdout + result.stderr)
    }

    public static let systemPlistReader: PlistReader = { path in
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] else { return nil }
        // Only the scalar values are needed (and they are Sendable).
        var result: [String: any Sendable] = [:]
        for (key, value) in plist {
            if let value = value as? Bool { result[key] = value } else if let value = value as? String { result[key] = value }
        }
        return result
    }

    enum Pane {
        static func url(_ id: String) -> URL? { URL(string: "x-apple.systempreferences:" + id) }
        static let security = url("com.apple.settings.PrivacySecurity.extension?Security")
        static let fileVault = url("com.apple.settings.PrivacySecurity.extension?FileVault")
        static let firewall = url("com.apple.Network-Settings.extension?Firewall")
        static let softwareUpdate = url("com.apple.Software-Update-Settings.extension")
        static let lockScreen = url("com.apple.Lock-Screen-Settings.extension")
        static let users = url("com.apple.Users-Groups-Settings.extension")
        static let sharing = url("com.apple.Sharing-Settings.extension")
        static let network = url("com.apple.Network-Settings.extension")
        static let profiles = url("com.apple.Profiles-Settings.extension")
    }

    /// Runs every check (concurrently) and returns them in display order.
    public func check() async -> [PostureCheck] {
        async let sip = run("/usr/bin/csrutil", ["status"])
        async let gatekeeper = run("/usr/sbin/spctl", ["--status"])
        async let fileVault = run("/usr/bin/fdesetup", ["status"])
        async let firewall = run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"])
        async let xprotect = run("/usr/bin/xprotect", ["version"])
        async let updates = run("/usr/sbin/softwareupdate", ["-l", "--no-scan"])
        async let screenLock = run("/usr/sbin/sysadminctl", ["-screenLock", "status"])
        async let guest = run("/usr/sbin/sysadminctl", ["-guestAccount", "status"])
        async let services = run("/bin/launchctl", ["print-disabled", "system"])
        async let dns = run("/usr/sbin/scutil", ["--dns"])
        async let proxy = run("/usr/sbin/scutil", ["--proxy"])
        async let profiles = run("/usr/bin/profiles", ["list"])
        async let userTrust = run("/usr/bin/security", ["dump-trust-settings"])
        async let adminTrust = run("/usr/bin/security", ["dump-trust-settings", "-d"])
        let updatePrefs = readPlist("/Library/Preferences/com.apple.SoftwareUpdate.plist")
        let loginPrefs = readPlist("/Library/Preferences/com.apple.loginwindow.plist")
        let serviceList = await services

        return [
            Self.sip(await sip),
            Self.gatekeeper(await gatekeeper),
            Self.fileVault(await fileVault),
            Self.firewall(await firewall),
            Self.xprotect(await xprotect, now: now),
            Self.updates(await updates),
            Self.autoUpdates(updatePrefs),
            Self.screenLock(await screenLock),
            Self.autoLogin(loginPrefs),
            Self.guestAccount(await guest),
            Self.sharing(.remoteLogin, title: "Remote Login (SSH)", label: "com.openssh.sshd", serviceList,
                         risk: "Anyone on your network who knows a user's password can open a Terminal session on this Mac."),
            Self.sharing(.screenSharing, title: "Screen Sharing", label: "com.apple.screensharing", serviceList,
                         risk: "Anyone on your network who knows a user's password can see and control this Mac's screen."),
            Self.sharing(.fileSharing, title: "File Sharing", label: "com.apple.smbd", serviceList,
                         risk: "Shared folders are reachable from other computers on your network."),
            Self.hostsFile(readFile("/etc/hosts")),
            Self.dnsServers(await dns),
            Self.webProxy(await proxy),
            Self.profiles(await profiles),
            Self.trustedCertificates(user: await userTrust, admin: await adminTrust),
            Self.sudoRules(listDirectory("/etc/sudoers.d")),
        ]
    }

    static func unknown(_ id: PostureCheckID, _ title: String, settings: URL? = nil) -> PostureCheck {
        PostureCheck(id: id, title: title, status: .unknown, summary: "MacScan couldn't read this setting.", settingsURL: settings)
    }

    // MARK: - Individual checks (pure: output in, verdict out)

    static func sip(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "System Integrity Protection"
        guard let text = output?.text.lowercased(), text.contains("system integrity protection status") else { return unknown(.sip, title) }
        if text.contains("status: enabled.") {
            return PostureCheck(id: .sip, title: title, status: .pass, summary: "On. System files and processes are protected, even from administrators.")
        }
        if text.contains("status: disabled") {
            return PostureCheck(id: .sip, title: title, status: .fail, summary: "Off. Any program with administrator rights can modify macOS itself.",
                                advice: "Restart into Recovery (hold the power button on Apple silicon), open Terminal and run `csrutil enable`.")
        }
        return PostureCheck(id: .sip, title: title, status: .warning, summary: "Partly on (custom configuration).",
                            advice: "Unless you set this up on purpose, restart into Recovery, open Terminal and run `csrutil enable`.")
    }

    static func gatekeeper(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "Gatekeeper"
        guard let text = output?.text.lowercased() else { return unknown(.gatekeeper, title, settings: Pane.security) }
        if text.contains("assessments enabled") {
            return PostureCheck(id: .gatekeeper, title: title, status: .pass, summary: "On. Apps from unidentified developers are blocked until you approve them.", settingsURL: Pane.security)
        }
        if text.contains("assessments disabled") {
            return PostureCheck(id: .gatekeeper, title: title, status: .fail, summary: "Off. Downloaded apps run without any check of who made them.",
                                advice: "In Privacy & Security, set \"Allow applications from\" to App Store & Known Developers.", settingsURL: Pane.security)
        }
        return unknown(.gatekeeper, title, settings: Pane.security)
    }

    static func fileVault(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "FileVault disk encryption"
        guard let text = output?.text else { return unknown(.fileVault, title, settings: Pane.fileVault) }
        if text.contains("FileVault is On") {
            let progress = text.contains("Encryption in progress") ? " Encryption is still in progress." : ""
            return PostureCheck(id: .fileVault, title: title, status: .pass, summary: "On. Your data can't be read without your password." + progress, settingsURL: Pane.fileVault)
        }
        if text.contains("FileVault is Off") {
            return PostureCheck(id: .fileVault, title: title, status: .warning, summary: "Off. Someone with the Mac in their hands can get at your files more easily.",
                                advice: "Turn on FileVault in Privacy & Security, and keep the recovery key somewhere safe.", settingsURL: Pane.fileVault)
        }
        return unknown(.fileVault, title, settings: Pane.fileVault)
    }

    static func firewall(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "Firewall"
        guard let text = output?.text, let range = text.range(of: #"State = (\d)"#, options: .regularExpression) else {
            return unknown(.firewall, title, settings: Pane.firewall)
        }
        if text[range].hasSuffix("0") {
            return PostureCheck(id: .firewall, title: title, status: .warning, summary: "Off. Programs on this Mac accept incoming connections without asking.",
                                advice: "Turn the firewall on in Network › Firewall. It matters most on shared or public Wi-Fi.", settingsURL: Pane.firewall)
        }
        return PostureCheck(id: .firewall, title: title, status: .pass,
                            summary: text[range].hasSuffix("2") ? "On, blocking all incoming connections." : "On.", settingsURL: Pane.firewall)
    }

    /// `xprotect version` prints "Version: 5372 Installed: 2026-11-11 20:06:26 +0000".
    static func xprotect(_ output: PostureCommandOutput?, now: Date) -> PostureCheck {
        let title = "XProtect malware definitions"
        guard let text = output?.text, let versionRange = text.range(of: #"Version: (\S+)"#, options: .regularExpression) else {
            return unknown(.xprotect, title, settings: Pane.softwareUpdate)
        }
        let version = text[versionRange].dropFirst("Version: ".count)
        var installed: Date?
        if let dateRange = text.range(of: #"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}"#, options: .regularExpression) {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
            installed = formatter.date(from: String(text[dateRange]))
        }
        guard let installed else {
            return PostureCheck(id: .xprotect, title: title, status: .pass, summary: "Version \(version).", settingsURL: Pane.softwareUpdate)
        }
        let days = max(0, Int(now.timeIntervalSince(installed) / 86_400))
        let when = days == 0 ? "today" : days == 1 ? "yesterday" : "\(days) days ago"
        // Apple ships new definitions every week or two; two months without one means updates are stuck.
        if days > 60 {
            return PostureCheck(id: .xprotect, title: title, status: .warning, summary: "Version \(version), last updated \(when).",
                                advice: "Apple normally updates these every week or two. Make sure \"Install Security Responses and system files\" is on in Software Update › Automatic Updates.", settingsURL: Pane.softwareUpdate)
        }
        return PostureCheck(id: .xprotect, title: title, status: .pass, summary: "Version \(version), updated \(when).", settingsURL: Pane.softwareUpdate)
    }

    /// `softwareupdate -l --no-scan` lists what macOS already knows about, without going online.
    static func updates(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "macOS updates"
        guard let text = output?.text else { return unknown(.updates, title, settings: Pane.softwareUpdate) }
        let labels = text.split(separator: "\n").compactMap { line -> String? in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("* Label: ") else { return nil }
            return String(trimmed.dropFirst("* Label: ".count))
        }
        if !labels.isEmpty {
            return PostureCheck(id: .updates, title: title, status: .warning,
                                summary: "\(labels.count) update\(labels.count == 1 ? "" : "s") waiting: " + labels.prefix(3).joined(separator: ", ") + (labels.count > 3 ? ", …" : ""),
                                advice: "Install them in Software Update. Updates often fix security holes that are already being used.", settingsURL: Pane.softwareUpdate)
        }
        if text.contains("No new software available") {
            return PostureCheck(id: .updates, title: title, status: .pass, summary: "No updates waiting, as of macOS's last check.", settingsURL: Pane.softwareUpdate)
        }
        return unknown(.updates, title, settings: Pane.softwareUpdate)
    }

    static func autoUpdates(_ prefs: [String: any Sendable]?) -> PostureCheck {
        let title = "Automatic security updates"
        guard let prefs else { return unknown(.autoUpdates, title, settings: Pane.softwareUpdate) }
        // Absent keys mean the default, which is on.
        func isOff(_ key: String) -> Bool { (prefs[key] as? Bool) == false }
        var off: [String] = []
        if isOff("AutomaticCheckEnabled") { off.append("checking for updates") }
        if isOff("CriticalUpdateInstall") || isOff("ConfigDataInstall") { off.append("installing Security Responses and system files (this includes XProtect)") }
        if off.isEmpty {
            return PostureCheck(id: .autoUpdates, title: title, status: .pass, summary: "On. Security Responses and XProtect updates install by themselves.", settingsURL: Pane.softwareUpdate)
        }
        return PostureCheck(id: .autoUpdates, title: title, status: .warning, summary: "Turned off: " + off.joined(separator: "; ") + ".",
                            advice: "Turn these on in Software Update › Automatic Updates.", settingsURL: Pane.softwareUpdate)
    }

    /// `sysadminctl -screenLock status` prints "screenLock delay is immediate", "… is 300 seconds" or "screenLock is off".
    static func screenLock(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "Password after sleep or screen saver"
        guard let text = output?.text.lowercased(), text.contains("screenlock") else { return unknown(.screenLock, title, settings: Pane.lockScreen) }
        if text.contains("screenlock is off") {
            return PostureCheck(id: .screenLock, title: title, status: .warning, summary: "Off. Anyone can wake the Mac and use it as you.",
                                advice: "In Lock Screen, set \"Require password after screen saver begins or display is turned off\".", settingsURL: Pane.lockScreen)
        }
        if text.contains("immediate") {
            return PostureCheck(id: .screenLock, title: title, status: .pass, summary: "Required immediately.", settingsURL: Pane.lockScreen)
        }
        if let range = text.range(of: #"is (\d+) seconds"#, options: .regularExpression),
           let seconds = Int(text[range].dropFirst(3).dropLast(8)) {
            let delay = seconds >= 120 ? "\(seconds / 60) minutes" : "\(seconds) seconds"
            if seconds > 900 {
                return PostureCheck(id: .screenLock, title: title, status: .warning, summary: "Required only after \(delay).",
                                    advice: "Choose a shorter delay in Lock Screen.", settingsURL: Pane.lockScreen)
            }
            return PostureCheck(id: .screenLock, title: title, status: .pass, summary: "Required after \(delay).", settingsURL: Pane.lockScreen)
        }
        return unknown(.screenLock, title, settings: Pane.lockScreen)
    }

    static func autoLogin(_ prefs: [String: any Sendable]?) -> PostureCheck {
        let title = "Automatic login"
        guard let prefs else { return unknown(.autoLogin, title, settings: Pane.users) }
        if let user = prefs["autoLoginUser"] as? String, !user.isEmpty {
            return PostureCheck(id: .autoLogin, title: title, status: .warning, summary: "On for “\(user)”. The Mac starts up straight into that account without a password.",
                                advice: "Set \"Automatically log in as\" to Off in Users & Groups.", settingsURL: Pane.users)
        }
        return PostureCheck(id: .autoLogin, title: title, status: .pass, summary: "Off. A password is needed after starting up.", settingsURL: Pane.users)
    }

    static func guestAccount(_ output: PostureCommandOutput?) -> PostureCheck {
        let title = "Guest account"
        guard let text = output?.text.lowercased(), text.contains("guest account") else { return unknown(.guestAccount, title, settings: Pane.users) }
        if text.contains("guest account enabled") {
            return PostureCheck(id: .guestAccount, title: title, status: .warning, summary: "On. Anyone can log in to this Mac without a password.",
                                advice: "Turn off Guest User in Users & Groups unless you need it.", settingsURL: Pane.users)
        }
        return PostureCheck(id: .guestAccount, title: title, status: .pass, summary: "Off.", settingsURL: Pane.users)
    }

    /// `launchctl print-disabled system` lists `"label" => enabled|disabled` for services whose state was
    /// ever changed. Sharing services are off unless listed as enabled.
    static func sharing(_ id: PostureCheckID, title: String, label: String, _ output: PostureCommandOutput?, risk: String) -> PostureCheck {
        guard let text = output?.text, text.contains("disabled services") else { return unknown(id, title, settings: Pane.sharing) }
        if text.contains("\"\(label)\" => enabled") {
            return PostureCheck(id: id, title: title, status: .warning, summary: "On. " + risk,
                                advice: "Turn it off in General › Sharing if you don't use it.", settingsURL: Pane.sharing)
        }
        return PostureCheck(id: id, title: title, status: .pass, summary: "Off.", settingsURL: Pane.sharing)
    }
}
