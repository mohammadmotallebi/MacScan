import AppKit
import Foundation
import SQLite3

/// A kind of access macOS asks the user about (System Settings › Privacy & Security).
public enum PrivacyPermission: String, CaseIterable, Sendable, Identifiable {
    case camera, microphone, screenRecording, accessibility, inputMonitoring, fullDiskAccess, automation
    case filesAndFolders, contacts, calendar, reminders, photos, appManagement, developerTools

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .camera: "Camera"
        case .microphone: "Microphone"
        case .screenRecording: "Screen Recording"
        case .accessibility: "Accessibility"
        case .inputMonitoring: "Input Monitoring"
        case .fullDiskAccess: "Full Disk Access"
        case .automation: "Automation"
        case .filesAndFolders: "Files and Folders"
        case .contacts: "Contacts"
        case .calendar: "Calendar"
        case .reminders: "Reminders"
        case .photos: "Photos"
        case .appManagement: "App Management"
        case .developerTools: "Developer Tools"
        }
    }

    /// What an app with this permission can do.
    public var explanation: String {
        switch self {
        case .camera: "Can use the camera."
        case .microphone: "Can listen through the microphone."
        case .screenRecording: "Can see and record everything on your screen."
        case .accessibility: "Can control this Mac: click, type and read other apps' windows."
        case .inputMonitoring: "Can see what you type, in any app."
        case .fullDiskAccess: "Can read all your files, including Mail, Messages and other apps' data."
        case .automation: "Can control other apps and use their data."
        case .filesAndFolders: "Can read your Desktop, Documents, Downloads or drives."
        case .contacts: "Can read your contacts."
        case .calendar: "Can read your calendar."
        case .reminders: "Can read your reminders."
        case .photos: "Can read your photo library."
        case .appManagement: "Can update or delete other apps."
        case .developerTools: "Can run programs that skip macOS's security checks."
        }
    }

    /// The page in System Settings where this permission is changed.
    public var settingsURL: URL? {
        let anchor = switch self {
        case .camera: "Privacy_Camera"
        case .microphone: "Privacy_Microphone"
        case .screenRecording: "Privacy_ScreenCapture"
        case .accessibility: "Privacy_Accessibility"
        case .inputMonitoring: "Privacy_ListenEvent"
        case .fullDiskAccess: "Privacy_AllFiles"
        case .automation: "Privacy_Automation"
        case .filesAndFolders: "Privacy_FilesAndFolders"
        case .contacts: "Privacy_Contacts"
        case .calendar: "Privacy_Calendars"
        case .reminders: "Privacy_Reminders"
        case .photos: "Privacy_Photos"
        case .appManagement: "Privacy_AppBundles"
        case .developerTools: "Privacy_DevTools"
        }
        return URL(string: "x-apple.systempreferences:com.apple.preference.security?" + anchor)
    }

    /// The permission a macOS service name stands for, and which part of it (a folder, for example).
    /// Services MacScan doesn't show return nil.
    static func parse(service: String) -> (permission: PrivacyPermission, part: String?)? {
        let name = service.hasPrefix("kTCCService") ? String(service.dropFirst("kTCCService".count)) : service
        return switch name {
        case "Camera": (.camera, nil)
        case "Microphone": (.microphone, nil)
        case "ScreenCapture": (.screenRecording, nil)
        case "Accessibility", "PostEvent": (.accessibility, nil)
        case "ListenEvent": (.inputMonitoring, nil)
        case "SystemPolicyAllFiles": (.fullDiskAccess, nil)
        case "AppleEvents": (.automation, nil)
        case "SystemPolicyDesktopFolder": (.filesAndFolders, "Desktop")
        case "SystemPolicyDocumentsFolder": (.filesAndFolders, "Documents")
        case "SystemPolicyDownloadsFolder": (.filesAndFolders, "Downloads")
        case "SystemPolicyNetworkVolumes": (.filesAndFolders, "network drives")
        case "SystemPolicyRemovableVolumes": (.filesAndFolders, "external drives")
        case "AddressBook": (.contacts, nil)
        case "Calendar": (.calendar, nil)
        case "Reminders": (.reminders, nil)
        case "Photos": (.photos, nil)
        case "PhotosAdd": (.photos, "adding photos only")
        case "SystemPolicyAppBundles": (.appManagement, nil)
        case "DeveloperTool": (.developerTools, nil)
        default: nil
        }
    }
}

public enum PrivacyDecision: String, Sendable {
    case allowed, limited, denied
}

public enum PrivacyRisk: Int, Sendable, Comparable {
    case none, review, warning

    public static func < (a: PrivacyRisk, b: PrivacyRisk) -> Bool { a.rawValue < b.rawValue }
}

/// One row of a macOS permission database.
public struct TCCRecord: Hashable, Sendable {
    public var service: String
    /// A bundle ID, or a full path when `clientIsPath`.
    public var client: String
    public var clientIsPath: Bool
    /// 0 denied, 1 not decided, 2 allowed, 3 or more limited.
    public var authValue: Int
    /// For Automation: the app being controlled.
    public var target: String?
    public var modified: Date?

    public init(service: String, client: String, clientIsPath: Bool = false, authValue: Int = 2, target: String? = nil, modified: Date? = nil) {
        self.service = service
        self.client = client
        self.clientIsPath = clientIsPath
        self.authValue = authValue
        self.target = target
        self.modified = modified
    }
}

/// Reads a macOS permission database (TCC.db). It works on a private copy, so the real file is never opened by SQLite.
public enum TCCDatabase {
    public enum ReadError: Error, Equatable, Sendable {
        case missing
        /// macOS refused: MacScan has no Full Disk Access.
        case noAccess
        case failed(String)
    }

    public static func read(_ url: URL) -> Result<[TCCRecord], ReadError> {
        let fd = open(url.path, O_RDONLY)
        guard fd >= 0 else {
            return .failure(errno == ENOENT ? .missing : errno == EPERM || errno == EACCES ? .noAccess : .failed(String(cString: strerror(errno))))
        }
        close(fd)

        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("MacScan-privacy-\(UUID().uuidString)", isDirectory: true)
        defer { try? fm.removeItem(at: dir) }
        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try fm.copyItem(at: url, to: dir.appendingPathComponent("TCC.db"))
        } catch {
            return .failure(PermissionErrors.isPermissionDenied(error) ? .noAccess : .failed(error.localizedDescription))
        }
        // Recent changes may still be in the write-ahead log.
        for suffix in ["-wal", "-shm"] {
            try? fm.copyItem(atPath: url.path + suffix, toPath: dir.appendingPathComponent("TCC.db" + suffix).path)
        }
        return readCopy(dir.appendingPathComponent("TCC.db"))
    }

    static func readCopy(_ url: URL) -> Result<[TCCRecord], ReadError> {
        var db: OpaquePointer?
        defer { sqlite3_close(db) }
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else {
            return .failure(.failed(db.map { String(cString: sqlite3_errmsg($0)) } ?? "can't open"))
        }

        // The columns changed between macOS versions.
        var columns: Set<String> = []
        var info: OpaquePointer?
        if sqlite3_prepare_v2(db, "PRAGMA table_info(access)", -1, &info, nil) == SQLITE_OK {
            while sqlite3_step(info) == SQLITE_ROW {
                if let name = sqlite3_column_text(info, 1) { columns.insert(String(cString: name)) }
            }
        }
        sqlite3_finalize(info)
        guard columns.contains("service"), columns.contains("client") else {
            return .failure(.failed("not a permission database"))
        }
        let auth = columns.contains("auth_value") ? "auth_value" : columns.contains("allowed") ? "allowed * 2" : "2"
        let type = columns.contains("client_type") ? "client_type" : "0"
        let target = columns.contains("indirect_object_identifier") ? "indirect_object_identifier" : "NULL"
        let modified = columns.contains("last_modified") ? "last_modified" : "NULL"

        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(db, "SELECT service, client, \(type), \(auth), \(target), \(modified) FROM access", -1, &statement, nil) == SQLITE_OK else {
            return .failure(.failed(String(cString: sqlite3_errmsg(db))))
        }
        var records: [TCCRecord] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let service = sqlite3_column_text(statement, 0), let client = sqlite3_column_text(statement, 1) else { continue }
            var record = TCCRecord(service: String(cString: service), client: String(cString: client),
                                   clientIsPath: sqlite3_column_int(statement, 2) == 1,
                                   authValue: Int(sqlite3_column_int(statement, 3)))
            if let text = sqlite3_column_text(statement, 4) {
                let value = String(cString: text)
                if !value.isEmpty, value != "UNUSED" { record.target = value }
            }
            let seconds = sqlite3_column_int64(statement, 5)
            if seconds > 0 { record.modified = Date(timeIntervalSince1970: TimeInterval(seconds)) }
            records.append(record)
        }
        return .success(records)
    }
}

/// One app's answer for one permission.
public struct PrivacyGrant: Identifiable, Hashable, Sendable {
    public var id: String { permission.rawValue + "|" + client }
    public var permission: PrivacyPermission
    /// Bundle ID or path, as macOS recorded it.
    public var client: String
    public var name: String
    /// Where the app is, when it was found.
    public var path: String?
    public var decision: PrivacyDecision
    /// Which part is allowed (folders, or the apps it controls).
    public var detail: String?
    public var signer: String?
    public var risk: PrivacyRisk
    public var reasons: [String]
    public var modified: Date?
    /// macOS's names for what this row covers, such as "kTCCServiceCamera".
    public var services: [String] = []
    public var clientIsPath = false
    /// The app isn't on this Mac any more.
    public var appMissing = false

    /// A leftover MacScan can remove: the app is gone and macOS knows it by an app ID.
    public var canRemove: Bool {
        appMissing && !clientIsPath && !client.hasPrefix("com.apple.") && PrivacyLeftoverRemover.isAppID(client)
    }
}

public struct PrivacyReport: Sendable {
    public enum Source: Hashable, Sendable {
        case read(Int)
        case missing
        case noAccess
        case failed(String)
    }

    public var grants: [PrivacyGrant]
    /// This user's permissions (camera, microphone, automation, files…).
    public var user: Source
    /// Permissions for the whole Mac (screen recording, accessibility, Full Disk Access…).
    public var system: Source

    public var needsFullDiskAccess: Bool { user == .noAccess || system == .noAccess }

    public func grants(for permission: PrivacyPermission) -> [PrivacyGrant] {
        grants.filter { $0.permission == permission }
    }

    public func count(_ risk: PrivacyRisk) -> Int {
        grants.lazy.filter { $0.risk == risk }.count
    }
}

/// Lists which apps have which privacy permissions and points out the ones worth a look. Read-only.
public struct PrivacyAudit: Sendable {
    public typealias AppResolver = @Sendable (_ bundleID: String) -> URL?
    public typealias Signer = @Sendable (URL) -> SigningStatus

    var userDatabase: URL
    var systemDatabase: URL
    var home: URL
    var resolveApp: AppResolver
    var signing: Signer

    public static let systemResolver: AppResolver = { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }

    public init(userDatabase: URL = AppPaths.home.appendingPathComponent("Library/Application Support/com.apple.TCC/TCC.db"),
                systemDatabase: URL = URL(fileURLWithPath: "/Library/Application Support/com.apple.TCC/TCC.db"),
                home: URL = AppPaths.home,
                resolveApp: @escaping AppResolver = PrivacyAudit.systemResolver,
                signing: @escaping Signer = { CodeSigning.status(of: $0) }) {
        self.userDatabase = userDatabase
        self.systemDatabase = systemDatabase
        self.home = home
        self.resolveApp = resolveApp
        self.signing = signing
    }

    public func run() -> PrivacyReport {
        var records: [TCCRecord] = []
        func load(_ url: URL) -> PrivacyReport.Source {
            switch TCCDatabase.read(url) {
            case .success(let rows): records += rows; return .read(rows.count)
            case .failure(.missing): return .missing
            case .failure(.noAccess): return .noAccess
            case .failure(.failed(let why)): return .failed(why)
            }
        }
        let user = load(userDatabase)
        let system = load(systemDatabase)
        return PrivacyReport(grants: grants(from: records), user: user, system: system)
    }

    private struct Subject {
        var name: String
        var url: URL?
        var status: SigningStatus?
    }

    private func lookUp(client: String, isPath: Bool) -> Subject {
        var url: URL?
        if isPath {
            if FileManager.default.fileExists(atPath: client) {
                url = PersistenceScanner.enclosingApp(of: client) ?? URL(fileURLWithPath: client)
            }
        } else {
            url = resolveApp(client)
        }
        guard let url else {
            return Subject(name: isPath ? (client as NSString).lastPathComponent : client)
        }
        return Subject(name: url.deletingPathExtension().lastPathComponent, url: url, status: signing(url))
    }

    func grants(from records: [TCCRecord]) -> [PrivacyGrant] {
        struct Key: Hashable { var permission: PrivacyPermission; var client: String }
        var groups: [Key: [(record: TCCRecord, part: String?)]] = [:]
        for record in records where record.authValue != 1 {
            guard let (permission, part) = PrivacyPermission.parse(service: record.service) else { continue }
            groups[Key(permission: permission, client: record.client), default: []].append((record, part))
        }

        var subjects: [String: Subject] = [:]
        func subject(of record: TCCRecord) -> Subject {
            if let known = subjects[record.client] { return known }
            let found = lookUp(client: record.client, isPath: record.clientIsPath)
            subjects[record.client] = found
            return found
        }

        var grants: [PrivacyGrant] = []
        for (key, rows) in groups {
            let granted = rows.filter { $0.record.authValue >= 2 }
            let decision: PrivacyDecision = granted.isEmpty ? .denied : granted.contains { $0.record.authValue == 2 } ? .allowed : .limited
            let subject = subject(of: rows[0].record)

            var detail: String?
            if key.permission == .automation {
                let targets = Set(granted.compactMap(\.record.target)).map { resolveApp($0)?.deletingPathExtension().lastPathComponent ?? $0 }.sorted()
                if !targets.isEmpty { detail = "Controls " + targets.joined(separator: ", ") }
            } else if !granted.contains(where: { $0.part == nil }) {
                let parts = Set(granted.compactMap(\.part)).sorted()
                if !parts.isEmpty { detail = parts.joined(separator: ", ") }
            }

            grants.append(PrivacyGrant(
                permission: key.permission, client: key.client, name: subject.name, path: subject.url?.path,
                decision: decision, detail: detail, signer: signerText(subject), risk: .none, reasons: [],
                modified: rows.compactMap(\.record.modified).max(),
                services: Set(rows.map(\.record.service)).sorted(),
                clientIsPath: rows[0].record.clientIsPath, appMissing: subject.url == nil))
        }

        // Apps that can both watch the screen and control the Mac.
        func allowed(_ permission: PrivacyPermission) -> Set<String> {
            Set(grants.filter { $0.permission == permission && $0.decision != .denied }.map(\.client))
        }
        let watchAndControl = allowed(.screenRecording).intersection(allowed(.accessibility))

        for index in grants.indices where grants[index].decision != .denied {
            let grant = grants[index]
            var reasons: [(PrivacyRisk, String)] = []
            if let subject = subjects[grant.client] { reasons += problems(subject, client: grant.client) }
            if grant.permission == .screenRecording, watchAndControl.contains(grant.client), !grant.client.hasPrefix("com.apple.") {
                reasons.append((.review, "Can also control this Mac (Accessibility). That is normal for remote-control and screen-sharing apps you use."))
            }
            grants[index].risk = reasons.map(\.0).max() ?? .none
            grants[index].reasons = reasons.map(\.1)
        }

        let order = PrivacyPermission.allCases
        return grants.sorted { a, b in
            if a.permission != b.permission { return order.firstIndex(of: a.permission)! < order.firstIndex(of: b.permission)! }
            if a.risk != b.risk { return a.risk > b.risk }
            if a.name.lowercased() != b.name.lowercased() { return a.name.lowercased() < b.name.lowercased() }
            return a.client < b.client
        }
    }

    private func signerText(_ subject: Subject) -> String? {
        guard let url = subject.url, let status = subject.status else { return nil }
        if let browser = WebAppShortcut.browser(ofApp: url, status: status) { return "\(browser) web-app shortcut" }
        return status.description
    }

    /// What is worth a look about an app that holds a permission.
    private func problems(_ subject: Subject, client: String) -> [(PrivacyRisk, String)] {
        guard let url = subject.url, let status = subject.status else {
            // macOS's own helpers often can't be looked up by ID.
            if client.hasPrefix("com.apple.") { return [] }
            return [(.review, "MacScan can't find this app. If you removed it, this permission is a leftover.")]
        }
        let path = url.path
        if case .unreadable = status { return [(.review, "MacScan couldn't read this app's signature.")] }
        guard status.isUntrusted else { return [] }
        if case .adhoc = status {
            if PersistenceScanner.isPackageManagerPath(path) || WebAppShortcut.browser(ofApp: url, status: status) != nil { return [] }
        }
        let who = switch status {
        case .unsigned: "It isn't signed, so macOS can't tell who made it."
        case .selfSigned: "It is signed with a certificate Apple didn't issue."
        default: "It is signed without a developer identity, so macOS can't tell who made it."
        }
        var result: [(PrivacyRisk, String)] = [(.warning, who)]
        if path.hasPrefix(home.appendingPathComponent("Downloads").path + "/") {
            result.append((.warning, "It runs from the Downloads folder."))
        } else if ProcessScanner.temporaryPrefixes.contains(where: { path.hasPrefix($0) }) {
            result.append((.warning, "It runs from a temporary folder."))
        } else if PersistenceScanner.isUnusualLocation(path) {
            result.append((.warning, "It runs from a hidden folder."))
        }
        return result
    }
}
