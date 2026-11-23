import CoreServices
import Foundation

/// An app that seems to be gone but left files in the user's Library.
public struct RemovedAppCandidate: Identifiable, Hashable, Sendable {
    public var id: String { bundleID }
    public let bundleID: String
    /// The last part of the bundle ID, e.g. "CleanMyMac5".
    public let name: String
    /// Total size of what was found.
    public let size: Int64
    /// The folders and files named after it.
    public let paths: [String]
}

/// Looks in the user's Library for folders and files named after an app (`com.vendor.App`) whose app is no
/// longer on this Mac. Only reads; it never changes anything.
public struct RemovedAppFinder: Sendable {
    public typealias InstalledCheck = @Sendable (String) -> Bool

    var library: URL
    /// Bundle IDs of the apps found in the Applications folders and the Trash (helpers included).
    var installedIDs: Set<String>
    /// Asks macOS whether any app with this bundle ID exists anywhere.
    var isInstalled: InstalledCheck

    /// Library subfolders whose items are named by bundle ID.
    static let places = ["Application Support", "Preferences", "Caches", "Containers", "Logs",
                         "Saved Application State", "HTTPStorages", "WebKit"]
    /// Bundle-ID-like names that belong to tools and libraries, not apps.
    static let notApps = ["org.swift.", "com.crashlytics.", "com.breakpad.", "io.fabric.", "com.google.keystone",
                          "com.microsoft.autoupdate", "org.sparkle-project."]
    /// Below this, an app shows up only when it left files in several places.
    static let minimumSize: Int64 = 64 * 1024

    public init(library: URL = AppPaths.home.appendingPathComponent("Library"),
                installedIDs: Set<String>,
                isInstalled: @escaping InstalledCheck = RemovedAppFinder.launchServicesKnows) {
        self.library = library
        self.installedIDs = Set(installedIDs.map { $0.lowercased() })
        self.isInstalled = isInstalled
    }

    /// True when Launch Services knows an app with this bundle ID.
    public static let launchServicesKnows: InstalledCheck = { id in
        guard let urls = LSCopyApplicationURLsForBundleIdentifier(id as CFString, nil)?.takeRetainedValue() as? [URL] else { return false }
        return urls.contains { FileManager.default.fileExists(atPath: $0.path) }
    }

    public func find() -> [RemovedAppCandidate] {
        let fm = FileManager.default
        var byID: [String: (id: String, paths: [String])] = [:]
        for place in Self.places {
            let folder = library.appendingPathComponent(place)
            guard let names = try? fm.contentsOfDirectory(atPath: folder.path) else { continue }
            for name in names {
                guard let id = Self.bundleID(fromItemName: name) else { continue }
                byID[id.lowercased(), default: (id, [])].paths.append(folder.appendingPathComponent(name).path)
            }
        }

        // A helper's items (com.vendor.App.Helper) join its app's (com.vendor.App) when both are found.
        for key in byID.keys.sorted(by: { $0.count > $1.count }) {
            guard let parent = byID.keys.filter({ key.hasPrefix($0 + ".") }).max(by: { $0.count < $1.count }),
                  let child = byID.removeValue(forKey: key) else { continue }
            byID[parent]?.paths += child.paths
        }

        var result: [RemovedAppCandidate] = []
        for (key, entry) in byID where !isKept(key) && !isInstalled(entry.id) {
            let size = entry.paths.reduce(Int64(0)) { $0 + Self.size(of: $1) }
            guard size >= Self.minimumSize || entry.paths.count >= 3 else { continue }
            let name = entry.id.split(separator: ".").last.map(String.init) ?? entry.id
            result.append(RemovedAppCandidate(bundleID: entry.id, name: name, size: size, paths: entry.paths.sorted()))
        }
        return result.sorted { $0.size > $1.size }
    }

    /// Apple's own items, MacScan's, and anything that belongs to an installed app (its ID, a helper of it, or its parent).
    func isKept(_ id: String) -> Bool {
        if id.hasPrefix("com.apple.") || id.hasPrefix("group.") || id.hasPrefix("systemgroup.") { return true }
        if let own = Bundle.main.bundleIdentifier?.lowercased(), id == own || id.hasPrefix(own + ".") { return true }
        if id.hasPrefix("com.local.macscan") { return true }
        // Caches of developer tools and crash reporters, not apps.
        if Self.notApps.contains(where: { id.hasPrefix($0) }) { return true }
        return installedIDs.contains { installed in
            id == installed || id.hasPrefix(installed + ".") || installed.hasPrefix(id + ".")
        }
    }

    /// "com.vendor.App", "com.vendor.App.plist" or "com.vendor.App.savedState" → "com.vendor.App". Nil for other names.
    static func bundleID(fromItemName name: String) -> String? {
        var id = name
        for suffix in [".plist", ".savedState", ".binarycookies"] where id.hasSuffix(suffix) {
            id = String(id.dropLast(suffix.count))
        }
        let parts = id.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 3, parts.allSatisfy({ !$0.isEmpty }),
              let first = parts.first, ["com", "org", "net", "io", "app", "co", "de", "me", "us", "dev"].contains(first.lowercased()),
              id.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }) else { return nil }
        return id
    }

    /// Disk space used by a file or folder. Unreadable parts count as zero.
    static func size(of path: String) -> Int64 {
        let url = URL(fileURLWithPath: path)
        let keys: Set<URLResourceKey> = [.totalFileAllocatedSizeKey, .isDirectoryKey]
        guard let values = try? url.resourceValues(forKeys: keys) else { return 0 }
        if values.isDirectory != true { return Int64(values.totalFileAllocatedSize ?? 0) }
        var total: Int64 = 0
        let walker = FileManager.default.enumerator(at: url, includingPropertiesForKeys: Array(keys), options: [], errorHandler: { _, _ in true })
        while let item = walker?.nextObject() as? URL {
            total += Int64((try? item.resourceValues(forKeys: [.totalFileAllocatedSizeKey]))?.totalFileAllocatedSize ?? 0)
        }
        return total
    }
}
