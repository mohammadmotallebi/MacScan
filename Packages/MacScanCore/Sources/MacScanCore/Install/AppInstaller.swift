import Foundation

// Install an app safely: open the download without running anything, check every app inside, and only
// after the user agrees copy it into /Applications. Packages (.pkg) are checked and then handed to Apple's
// Installer; MacScan never runs a package's scripts itself.

public enum InstallerKind: String, Sendable {
    case diskImage, archive, app, package

    public static func of(_ url: URL) -> InstallerKind? {
        switch url.pathExtension.lowercased() {
        case "dmg": .diskImage
        case "zip": .archive
        case "app": .app
        case "pkg", "mpkg": .package
        default: nil
        }
    }

    public var title: String {
        switch self {
        case .diskImage: "Disk image"
        case .archive: "Zip archive"
        case .app: "App"
        case .package: "Installer package"
        }
    }
}

public enum InstallError: Error, LocalizedError, Equatable {
    case notSupported(String)
    case couldNotOpen(String)
    case noApp
    case copyFailed(String)
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .notSupported(let name): "MacScan can install .dmg, .zip, .app and .pkg files. “\(name)” is none of these."
        case .couldNotOpen(let why): "MacScan couldn't open the installer: \(why)"
        case .noApp: "There's no app inside to install."
        case .copyFailed(let why): "Installing failed: \(why)"
        case .cancelled: "The password prompt was cancelled, so nothing was installed."
        }
    }
}

/// An installer opened for checking: a mounted disk image, an unpacked zip, an app or an expanded package.
public struct OpenedInstaller: Sendable {
    public var source: URL
    public var kind: InstallerKind
    /// Apps found inside (for a package: the apps in its payload).
    public var apps: [URL]
    /// The unpacked package (payload and scripts), for packages.
    public var expandedPackage: URL?
    var mountPoint: URL?
    var tempFolder: URL?
}

/// Opens and closes installers. Read-only towards the user's files: disk images are mounted read-only and
/// hidden, zips and packages are unpacked into MacScan's own temporary folder.
public struct InstallerOpener: Sendable {
    public typealias Runner = @Sendable (String, [String]) async -> PostureCommandOutput?

    var run: Runner
    var tempRoot: URL

    public init(run: @escaping Runner = SecurityPosture.systemRunner,
                tempRoot: URL = FileManager.default.temporaryDirectory.appendingPathComponent("MacScan-Install")) {
        self.run = run
        self.tempRoot = tempRoot
    }

    public func open(_ url: URL) async throws -> OpenedInstaller {
        guard let kind = InstallerKind.of(url) else { throw InstallError.notSupported(url.lastPathComponent) }
        let fm = FileManager.default
        var opened = OpenedInstaller(source: url, kind: kind, apps: [])
        switch kind {
        case .app:
            opened.apps = [url]
            return opened
        case .diskImage:
            let mount = tempRoot.appendingPathComponent("mount-" + UUID().uuidString)
            try fm.createDirectory(at: mount, withIntermediateDirectories: true)
            opened.mountPoint = mount
            // `yes` answers the license agreement some disk images show. Nothing on the image is opened or run.
            let script = "yes | /usr/bin/hdiutil attach -nobrowse -readonly -noautoopen -mountpoint \"$1\" \"$2\" > /dev/null"
            let result = await run("/bin/sh", ["-c", script, "sh", mount.path, url.path])
            guard result?.exitCode == 0 else {
                try? fm.removeItem(at: mount)
                throw InstallError.couldNotOpen(result?.text.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty ?? "hdiutil failed")
            }
            opened.apps = Self.findApps(in: mount)
        case .archive:
            let folder = tempRoot.appendingPathComponent("zip-" + UUID().uuidString)
            try fm.createDirectory(at: folder, withIntermediateDirectories: true)
            opened.tempFolder = folder
            let result = await run("/usr/bin/ditto", ["-x", "-k", url.path, folder.path])
            guard result?.exitCode == 0 else {
                try? fm.removeItem(at: folder)
                throw InstallError.couldNotOpen(result?.text.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty ?? "ditto failed")
            }
            opened.apps = Self.findApps(in: folder)
        case .package:
            let folder = tempRoot.appendingPathComponent("pkg-" + UUID().uuidString)
            try fm.createDirectory(at: folder, withIntermediateDirectories: true)
            opened.tempFolder = folder
            let expanded = folder.appendingPathComponent("expanded")
            let result = await run("/usr/sbin/pkgutil", ["--expand-full", url.path, expanded.path])
            guard result?.exitCode == 0 else {
                try? fm.removeItem(at: folder)
                throw InstallError.couldNotOpen(result?.text.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty ?? "pkgutil failed")
            }
            opened.expandedPackage = expanded
            opened.apps = Self.findApps(in: expanded, depth: 6)
        }
        return opened
    }

    /// Ejects the disk image and deletes MacScan's temporary copy.
    public func close(_ opened: OpenedInstaller) async {
        if let mount = opened.mountPoint {
            if await run("/usr/bin/hdiutil", ["detach", mount.path, "-quiet"])?.exitCode != 0 {
                _ = await run("/usr/bin/hdiutil", ["detach", mount.path, "-force", "-quiet"])
            }
            try? FileManager.default.removeItem(at: mount)
        }
        if let folder = opened.tempFolder { try? FileManager.default.removeItem(at: folder) }
    }

    /// Apps in a folder, a few levels down. Symbolic links (like a disk image's "Applications" shortcut) are not followed,
    /// and nothing inside an app is listed.
    static func findApps(in folder: URL, depth: Int = 2) -> [URL] {
        guard depth >= 0 else { return [] }
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: folder.path) else { return [] }
        var apps: [URL] = []
        for name in names.sorted() where !name.hasPrefix(".") {
            let url = folder.appendingPathComponent(name)
            let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
            guard values?.isSymbolicLink != true, values?.isDirectory == true else { continue }
            if name.lowercased().hasSuffix(".app") { apps.append(url) } else { apps += findApps(in: url, depth: depth - 1) }
        }
        return apps
    }
}

/// What the user should know about one app before installing it.
public struct InstallCandidate: Identifiable, Sendable {
    public struct Concern: Hashable, Sendable {
        public enum Level: Int, Comparable, Sendable {
            case info, warning, danger
            public static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
        }
        public var level: Level
        public var text: String
    }

    public enum VersionChange: Sendable, Equatable {
        case new, newer, same, older, unknown
    }

    public var id: String { url.path }
    public var url: URL
    public var name: String
    public var bundleID: String?
    public var version: String?
    public var size: Int64
    public var signing: SigningStatus
    public var gatekeeper: GatekeeperAssessment?
    /// Background helpers, login items and system extensions the app carries inside.
    public var embedded: [String]
    /// The copy already in the destination folder, if any.
    public var existing: URL?
    public var existingVersion: String?
    public var existingSigning: SigningStatus?
    public var concerns: [Concern] = []

    public var versionChange: VersionChange {
        guard existing != nil else { return .new }
        guard let version, let existingVersion else { return .unknown }
        switch version.compare(existingVersion, options: .numeric) {
        case .orderedDescending: return .newer
        case .orderedSame: return .same
        case .orderedAscending: return .older
        }
    }

    public var worst: Concern.Level? { concerns.map(\.level).max() }
}

/// Reads an app's details and compares it with the copy already installed.
public struct AppInspector: Sendable {
    public typealias Signer = @Sendable (URL) -> SigningStatus
    public typealias Gatekeeper = @Sendable (URL) async -> GatekeeperAssessment?

    var destination: URL
    var signing: Signer
    var gatekeeper: Gatekeeper

    public init(destination: URL = URL(fileURLWithPath: "/Applications"),
                signing: @escaping Signer = { CodeSigning.status(of: $0) },
                gatekeeper: @escaping Gatekeeper = AppInspector.systemGatekeeper) {
        self.destination = destination
        self.signing = signing
        self.gatekeeper = gatekeeper
    }

    public static let systemGatekeeper: Gatekeeper = { url in
        guard let result = try? await ProcessRunner.run(URL(fileURLWithPath: "/usr/sbin/spctl"), ["--assess", "--type", "execute", "-vv", url.path]) else { return nil }
        return GatekeeperAssessment.parse(exitCode: result.exitCode, output: result.stderr + result.stdout)
    }

    public func inspect(_ app: URL) async -> InstallCandidate {
        let info = Self.info(of: app)
        let signing = signing(app)
        let existing = destination.appendingPathComponent(app.lastPathComponent)
        let hasExisting = FileManager.default.fileExists(atPath: existing.path)
        var candidate = InstallCandidate(
            url: app, name: app.deletingPathExtension().lastPathComponent,
            bundleID: info?["CFBundleIdentifier"] as? String,
            version: (info?["CFBundleShortVersionString"] as? String) ?? (info?["CFBundleVersion"] as? String),
            size: Self.size(of: app), signing: signing, gatekeeper: await gatekeeper(app),
            embedded: Self.embeddedItems(in: app),
            existing: hasExisting ? existing : nil,
            existingVersion: hasExisting ? Self.info(of: existing).flatMap { ($0["CFBundleShortVersionString"] ?? $0["CFBundleVersion"]) as? String } : nil,
            existingSigning: hasExisting ? self.signing(existing) : nil)
        candidate.concerns = concerns(for: candidate)
        return candidate
    }

    func concerns(for c: InstallCandidate) -> [InstallCandidate.Concern] {
        var result: [InstallCandidate.Concern] = []
        switch c.signing {
        case .unsigned: result.append(.init(level: .danger, text: "Not signed: no one vouches for this app."))
        case .adhoc: result.append(.init(level: .warning, text: "Signed only by itself (ad-hoc), not by a known developer."))
        case .selfSigned: result.append(.init(level: .warning, text: "Signed with a home-made certificate, not one from Apple."))
        case .unreadable(let why): result.append(.init(level: .warning, text: "The signature couldn't be read: \(why)"))
        case .signed: break
        }
        if let g = c.gatekeeper, !g.accepted {
            result.append(.init(level: .warning, text: "macOS would block this app" + (g.message.isEmpty ? "." : ": \(g.message)")))
        }
        // The biggest red flag for a fake update: the new copy comes from someone else.
        if let old = c.existingSigning?.teamID, let new = c.signing.teamID, old != new {
            result.append(.init(level: .danger, text: "Signed by a different developer (\(new)) than the copy you have (\(old))."))
        } else if c.existingSigning?.teamID != nil, c.signing.teamID == nil {
            result.append(.init(level: .danger, text: "The copy you have is signed by a developer; this one isn't."))
        }
        if c.versionChange == .older {
            result.append(.init(level: .info, text: "Older than the copy you have (\(c.existingVersion ?? "?"))."))
        }
        for item in c.embedded {
            result.append(.init(level: .info, text: item))
        }
        return result.sorted { $0.level > $1.level }
    }

    static func info(of app: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }

    /// "Adds a background helper that runs as administrator: com.foo.helper", and the like.
    static func embeddedItems(in app: URL) -> [String] {
        let fm = FileManager.default
        func names(_ relative: String) -> [String] {
            ((try? fm.contentsOfDirectory(atPath: app.appendingPathComponent(relative).path)) ?? []).filter { !$0.hasPrefix(".") }.sorted()
        }
        var result: [String] = []
        for name in names("Contents/Library/LaunchServices") {
            result.append("Carries a helper that can run as administrator: \(name)")
        }
        for name in names("Contents/Library/LaunchDaemons") {
            result.append("Can add a system background service: \(name.replacingOccurrences(of: ".plist", with: ""))")
        }
        for name in names("Contents/Library/LaunchAgents") {
            result.append("Can add a background agent: \(name.replacingOccurrences(of: ".plist", with: ""))")
        }
        for name in names("Contents/Library/LoginItems") {
            result.append("Can open at login: \(name.replacingOccurrences(of: ".app", with: ""))")
        }
        for name in names("Contents/Library/SystemExtensions") {
            result.append("Carries a system extension: \(name)")
        }
        return result
    }

    static func size(of url: URL) -> Int64 {
        var total: Int64 = 0
        let walker = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.totalFileAllocatedSizeKey], options: [], errorHandler: { _, _ in true })
        while let item = walker?.nextObject() as? URL {
            total += Int64((try? item.resourceValues(forKeys: [.totalFileAllocatedSizeKey]))?.totalFileAllocatedSize ?? 0)
        }
        return total
    }
}

/// What a package will do: its signature and its install scripts (which run as administrator).
public struct PackageReview: Sendable {
    public struct Script: Hashable, Sendable {
        public var name: String
        public var path: String
        public var concerns: [String]
    }

    /// e.g. "Developer ID Installer: Zoom Video Communications, Inc. (BJ4HAAB9B3)", nil when unsigned.
    public var signer: String?
    public var notarized: Bool
    public var scripts: [Script]

    public init(signer: String?, notarized: Bool, scripts: [Script]) {
        self.signer = signer
        self.notarized = notarized
        self.scripts = scripts
    }

    static let scriptNames: Set<String> = ["preinstall", "postinstall", "preflight", "postflight", "preupgrade", "postupgrade"]

    public static func review(package: URL, expanded: URL,
                              run: InstallerOpener.Runner = SecurityPosture.systemRunner) async -> PackageReview {
        let output = await run("/usr/sbin/pkgutil", ["--check-signature", package.path])?.text ?? ""
        return PackageReview(signer: signer(fromCheckSignature: output),
                             notarized: output.contains("Notarization: trusted"),
                             scripts: scripts(in: expanded))
    }

    /// The first certificate in `pkgutil --check-signature` output.
    static func signer(fromCheckSignature text: String) -> String? {
        guard !text.contains("Status: no signature") else { return nil }
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if let range = trimmed.range(of: #"^1\. "#, options: .regularExpression) {
                return String(trimmed[range.upperBound...])
            }
        }
        return nil
    }

    static func scripts(in expanded: URL) -> [Script] {
        var result: [Script] = []
        let walker = FileManager.default.enumerator(at: expanded, includingPropertiesForKeys: [.isRegularFileKey])
        while let url = walker?.nextObject() as? URL {
            // Don't look inside the payload's apps.
            if url.pathExtension == "app" { walker?.skipDescendants(); continue }
            guard scriptNames.contains(url.lastPathComponent.lowercased()) || url.deletingLastPathComponent().lastPathComponent == "Scripts",
                  (try? url.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true,
                  let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            var concerns = PersistenceScanner.suspiciousReasons(in: text)
            if text.contains("LaunchDaemons") { concerns.append("adds a system background service") }
            if text.contains("LaunchAgents") { concerns.append("adds a background agent") }
            if text.contains("curl ") || text.contains("wget ") { concerns.append("downloads something while installing") }
            result.append(Script(name: url.lastPathComponent, path: url.path, concerns: Array(NSOrderedSet(array: concerns)) as? [String] ?? concerns))
        }
        return result.sorted { $0.name < $1.name }
    }
}

/// Copies an app into the Applications folder. An older copy goes to the Trash first.
public struct AppInstaller: Sendable {
    var destination: URL
    var trasher: any Trasher
    var admin: any AdminRunner
    var run: InstallerOpener.Runner
    /// Where the admin step puts the old copy (the user's Trash).
    var userTrash: URL

    public init(destination: URL = URL(fileURLWithPath: "/Applications"), trasher: any Trasher = SystemTrasher(),
                admin: any AdminRunner = OsascriptAdminRunner(), run: @escaping InstallerOpener.Runner = SecurityPosture.systemRunner,
                userTrash: URL = AppPaths.home.appendingPathComponent(".Trash")) {
        self.destination = destination
        self.trasher = trasher
        self.admin = admin
        self.run = run
        self.userTrash = userTrash
    }

    /// Installs `app` and returns where it went. Asks for an administrator password only when the folder or the old copy needs it.
    public func install(_ app: URL) async throws -> URL {
        let target = destination.appendingPathComponent(app.lastPathComponent)
        let staging = destination.appendingPathComponent(".\(app.lastPathComponent).macscan-\(UUID().uuidString.prefix(8))")
        // ditto keeps the download flag, so Gatekeeper still checks the app the first time it opens.
        let copy = await run("/usr/bin/ditto", [app.path, staging.path])
        if copy?.exitCode == 0 {
            do {
                if FileManager.default.fileExists(atPath: target.path) { try trasher.trash(target) }
                try FileManager.default.moveItem(at: staging, to: target)
                return target
            } catch {
                try? FileManager.default.removeItem(at: staging)
                if !PermissionErrors.isPermissionDenied(error) { throw InstallError.copyFailed(error.localizedDescription) }
            }
        } else {
            try? FileManager.default.removeItem(at: staging)
        }
        try await installAsAdmin(app, target: target)
        return target
    }

    /// Same steps as root: copy, move the old copy to the user's Trash, put the new one in place, give it to the user.
    func installAsAdmin(_ app: URL, target: URL) async throws {
        let q = Uninstaller.shellQuote
        let staging = destination.appendingPathComponent(".\(app.lastPathComponent).macscan-admin").path
        let trash = userTrash.appendingPathComponent("\(app.deletingPathExtension().lastPathComponent) \(Int(Date().timeIntervalSince1970)).app").path
        let user = AppPaths.userName
        let script = [
            "set -e",
            "rm -rf \(q(staging))",
            "/usr/bin/ditto \(q(app.path)) \(q(staging))",
            "if [ -e \(q(target.path)) ]; then mv \(q(target.path)) \(q(trash)); chown -R \(q(user)) \(q(trash)) || true; fi",
            "mv \(q(staging)) \(q(target.path))",
            "chown -R \(q(user)):admin \(q(target.path)) || true",
        ].joined(separator: "\n")
        do {
            _ = try await admin.run(script: script, prompt: "MacScan needs your password to install \(app.deletingPathExtension().lastPathComponent).")
        } catch UninstallError.adminCancelled {
            throw InstallError.cancelled
        } catch {
            throw InstallError.copyFailed(error.localizedDescription)
        }
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
