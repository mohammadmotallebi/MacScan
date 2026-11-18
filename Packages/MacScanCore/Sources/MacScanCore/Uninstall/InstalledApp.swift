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
    /// Executable names of nested helpers that start with the app's name (e.g. `CleanMyMac_5_HealthMonitor`).
    /// Helpers often create support folders, crash caches and crash reports under these names.
    public var helperNames: [String] = []
    /// The app bundle is already gone; only its leftovers (found by bundle ID and name) can be removed.
    public var isMissing: Bool = false

    /// Describes an app that has already been deleted, so its leftovers can still be found.
    /// Returns nil when neither a usable bundle ID nor a usable name is given.
    public static func removed(bundleID rawID: String?, name rawName: String?) -> InstalledApp? {
        let id = rawID?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        let name = rawName?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        if let id, !isPlausibleBundleID(id) { return nil }
        let lastComponent = id.flatMap { $0.split(separator: ".").last.map(String.init) }
        guard let display = name ?? lastComponent else { return nil }
        var names: [String] = []
        for n in [name, lastComponent].compactMap({ $0 }) where !names.contains(n) { names.append(n) }
        var protection: String?
        if let id, id.lowercased().hasPrefix("com.apple.") { protection = "Part of macOS" }
        if let id, id == Bundle.main.bundleIdentifier { protection = "This is MacScan itself" }
        // A path that never exists, unique per bundle ID / name, so it can't collide with a real app in the list.
        let key = (id ?? display).replacingOccurrences(of: "/", with: "-")
        let placeholder = URL(fileURLWithPath: "/.macscan-removed-apps").appendingPathComponent(key + ".app")
        return InstalledApp(url: placeholder, name: display, bundleID: id, version: nil, teamID: nil,
                            nestedBundleIDs: [], names: names, protectionReason: protection, isMissing: true)
    }

    /// Reverse-DNS with at least three components, e.g. `com.vendor.App`.
    public static func isPlausibleBundleID(_ id: String) -> Bool {
        let parts = id.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 3, parts.allSatisfy({ !$0.isEmpty }) else { return false }
        return id.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }
    }

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
            protectionReason: protection(for: url, bundleID: bundleID),
            helperNames: helperNames(in: url, appNames: names)
        )
    }

    /// Executable names of nested helper bundles (login items, XPC services, helpers, extensions) and the
    /// main executable, kept only when they start with one of the app's names. That prefix rule keeps generic
    /// names such as "Autoupdate" or "Installer" out of name matching.
    static func helperNames(in app: URL, appNames: [String]) -> [String] {
        let contents = app.appendingPathComponent("Contents")
        let prefixes = appNames.map { $0.lowercased() }.filter { $0.count >= 4 }
        var candidates: [String] = []
        if let main = Bundle(url: app)?.infoDictionary?["CFBundleExecutable"] as? String { candidates.append(main) }
        let fm = FileManager.default
        for place in ["Library/LoginItems", "Library/LaunchServices", "XPCServices", "PlugIns", "Helpers", "MacOS"] {
            let dir = contents.appendingPathComponent(place)
            for name in (try? fm.contentsOfDirectory(atPath: dir.path)) ?? [] {
                let ext = (name as NSString).pathExtension.lowercased()
                guard ["app", "xpc", "appex"].contains(ext) else { continue }
                let nested = dir.appendingPathComponent(name)
                candidates.append((Bundle(url: nested)?.infoDictionary?["CFBundleExecutable"] as? String)
                                  ?? (name as NSString).deletingPathExtension)
            }
        }
        var result: [String] = []
        for c in candidates where !result.contains(c) && !appNames.contains(c) {
            let lower = c.lowercased()
            if prefixes.contains(where: { lower.hasPrefix($0) && lower.count > $0.count }) { result.append(c) }
        }
        return result
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

    public var isInTrash: Bool { !isMissing && url.path.hasPrefix(AppPaths.home.path + "/.Trash/") }

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

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
