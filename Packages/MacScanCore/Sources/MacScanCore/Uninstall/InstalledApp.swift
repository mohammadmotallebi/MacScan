import Foundation

/// An application bundle that can be inspected for uninstalling.
public struct InstalledApp: Identifiable, Hashable, Sendable {
    public var id: String { url.path }
    public let url: URL
    public let name: String
    public let bundleID: String?
    public let version: String?
    public let teamID: String?
    /// Bundle IDs of helpers, login items, XPC services and extensions inside the app.
    public let nestedBundleIDs: [String]
    /// Alternative names (CFBundleName / display name / file name) used for name matching.
    public let names: [String]
    /// Non-nil when MacScan refuses to uninstall this app.
    public let protectionReason: String?

    public var isProtected: Bool { protectionReason != nil }

    /// All bundle identifiers that belong to this app.
    public var allBundleIDs: [String] {
        ([bundleID].compactMap { $0 } + nestedBundleIDs).filter { $0.contains(".") }
    }

    public static func load(_ url: URL) -> InstalledApp? {
        guard url.pathExtension.lowercased() == "app", let bundle = Bundle(url: url) else { return nil }
        let info = bundle.infoDictionary ?? [:]
        let fileName = url.deletingPathExtension().lastPathComponent
        let bundleName = info["CFBundleName"] as? String
        let displayName = info["CFBundleDisplayName"] as? String
        let version = (info["CFBundleShortVersionString"] as? String) ?? (info["CFBundleVersion"] as? String)
        let bundleID = bundle.bundleIdentifier

        var names: [String] = []
        for n in [displayName, bundleName, fileName].compactMap({ $0 }) where !names.contains(n) {
            names.append(n)
        }

        return InstalledApp(
            url: url,
            name: displayName ?? fileName,
            bundleID: bundleID,
            version: version,
            teamID: CodeSigning.status(of: url).teamID,
            nestedBundleIDs: nestedIdentifiers(in: url, excluding: bundleID),
            names: names,
            protectionReason: protection(for: url, bundleID: bundleID)
        )
    }

    /// Identifiers of nested bundles (login items, helpers, XPC services, app extensions, plug-ins).
    static func nestedIdentifiers(in app: URL, excluding own: String?) -> [String] {
        let contents = app.appendingPathComponent("Contents")
        let places = ["Library/LoginItems", "Library/LaunchServices", "Library/SystemExtensions", "XPCServices", "PlugIns", "Helpers", "MacOS", "Frameworks"]
        var ids: [String] = []
        let fm = FileManager.default
        for place in places {
            let dir = contents.appendingPathComponent(place)
            for name in (try? fm.contentsOfDirectory(atPath: dir.path)) ?? [] {
                let ext = (name as NSString).pathExtension.lowercased()
                guard ["app", "xpc", "appex", "systemextension", "plugin", "bundle"].contains(ext) else { continue }
                if let id = Bundle(url: dir.appendingPathComponent(name))?.bundleIdentifier, id != own, !ids.contains(id) {
                    ids.append(id)
                }
            }
        }
        // Privileged helpers embedded for SMJobBless/SMAppService are plain executables named after their ID.
        let launchServices = contents.appendingPathComponent("Library/LaunchServices")
        for name in (try? fm.contentsOfDirectory(atPath: launchServices.path)) ?? [] where name.contains(".") && !ids.contains(name) {
            if (name as NSString).pathExtension.isEmpty || name.split(separator: ".").count >= 3 {
                ids.append(name)
            }
        }
        // Frameworks are often shared/vendor IDs (e.g. org.sparkle-project.Sparkle) — don't use them for matching.
        return ids.filter { !$0.lowercased().hasPrefix("org.sparkle-project") && !$0.lowercased().hasPrefix("com.apple.") }
    }

    static func protection(for url: URL, bundleID: String?) -> String? {
        let path = url.path
        if path.hasPrefix("/System/") { return "Part of macOS" }
        if bundleID == Bundle.main.bundleIdentifier, bundleID != nil { return "This is MacScan itself" }
        var st = stat()
        if lstat(path, &st) == 0, st.st_flags & UInt32(SF_RESTRICTED) != 0 {
            return "Protected by System Integrity Protection"
        }
        if let bundleID, bundleID.hasPrefix("com.apple."), path.hasPrefix("/Applications/Safari") {
            return "Part of macOS"
        }
        return nil
    }

    /// Apps sitting in the user's Trash (they can still have registered background items).
    public static func listTrash(_ trash: URL = AppPaths.home.appendingPathComponent(".Trash")) -> [InstalledApp] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: trash.path)) ?? []
        return names.filter { $0.lowercased().hasSuffix(".app") }
            .compactMap { load(trash.appendingPathComponent($0)) }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    public var isInTrash: Bool { url.path.hasPrefix(AppPaths.home.path + "/.Trash/") }

    /// Apps in /Applications (including one level of subfolders) and ~/Applications.
    public static func listInstalled(folders: [URL] = FileEnumerator.applicationFolders) -> [InstalledApp] {
        var result: [InstalledApp] = []
        var seen = Set<String>()
        let fm = FileManager.default
        func consider(_ url: URL) {
            guard seen.insert(url.path).inserted, let app = load(url) else { return }
            result.append(app)
        }
        for folder in folders {
            for name in (try? fm.contentsOfDirectory(atPath: folder.path)) ?? [] where !name.hasPrefix(".") {
                let url = folder.appendingPathComponent(name)
                if name.lowercased().hasSuffix(".app") {
                    consider(url)
                } else {
                    var isDir: ObjCBool = false
                    if fm.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue {
                        for inner in (try? fm.contentsOfDirectory(atPath: url.path)) ?? [] where inner.lowercased().hasSuffix(".app") {
                            consider(url.appendingPathComponent(inner))
                        }
                    }
                }
            }
        }
        return result.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }
}
