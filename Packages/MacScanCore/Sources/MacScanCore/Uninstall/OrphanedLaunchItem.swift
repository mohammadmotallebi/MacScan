import Foundation

/// A launch agent or daemon whose program no longer exists, usually left behind by an uninstalled app.
/// Removing it stops (unloads) the job and moves its plist to the Trash. Nothing else is touched.
public struct OrphanedLaunchItem: Sendable, Equatable {
    public let plist: URL
    public let label: String?
    public let missingProgram: String
    public let domain: LaunchDomain
    /// The plist is owned by root (e.g. /Library/LaunchDaemons): macOS will ask for a password.
    public let requiresAdmin: Bool

    public var displayName: String { label ?? plist.deletingPathExtension().lastPathComponent }

    /// Re-reads the plist and returns an item only if it lives in a launch folder and its program is still
    /// missing. Programs on other volumes (`/Volumes/…`) are never treated as missing: the disk may just be
    /// unplugged.
    public static func inspect(_ path: String, locations: PersistenceLocations = .system) -> OrphanedLaunchItem? {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        guard url.pathExtension == "plist" else { return nil }
        let folders: [(URL, LaunchDomain)] = [
            (locations.user("Library/LaunchAgents"), .gui),
            (locations.system("Library/LaunchAgents"), .gui),
            (locations.system("Library/LaunchDaemons"), .system),
        ]
        guard let domain = folders.first(where: { $0.0.standardizedFileURL.path == url.deletingLastPathComponent().path })?.1,
              let data = try? Data(contentsOf: url),
              let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
        else { return nil }
        let args = plist["ProgramArguments"] as? [String] ?? []
        guard let program = (plist["Program"] as? String) ?? args.first,
              program.hasPrefix("/"), !program.hasPrefix("/Volumes/"),
              !FileManager.default.fileExists(atPath: program)
        else { return nil }
        let label = plist["Label"] as? String
        if let label, label.lowercased().hasPrefix("com.apple.") { return nil }
        return OrphanedLaunchItem(plist: url, label: label, missingProgram: program, domain: domain,
                                  requiresAdmin: LeftoverFinder.requiresAdmin(url) || domain == .system)
    }

    /// A one-item uninstall plan, so removal reuses the Uninstaller's unloading, Trash, admin step and safety checks.
    func plan() -> UninstallPlan {
        let owner = InstalledApp(url: URL(fileURLWithPath: "/.macscan-orphaned-launch-items").appendingPathComponent(plist.lastPathComponent),
                                 name: displayName, bundleID: nil, version: nil, teamID: nil, nestedBundleIDs: [],
                                 names: [], protectionReason: nil, isMissing: true)
        let leftover = Leftover(url: plist, category: domain == .system ? .launchDaemon : .launchAgent,
                                matchedBy: "Starts \(missingProgram), which no longer exists", matchedByNameOnly: false,
                                requiresAdmin: requiresAdmin, size: LeftoverFinder.allocatedSize(of: plist),
                                launchLabel: label, launchDomain: domain)
        var plan = UninstallPlan(app: owner, leftovers: [leftover], processes: [], packageReceipts: [], notes: [])
        if let label { plan.launchJobs = [LaunchJob(label: label, domain: domain)] }
        return plan
    }

    /// Stops the job and moves its plist to the Trash (asking for a password if root owns it).
    /// Refuses if the program has come back since the scan.
    public func remove(with uninstaller: Uninstaller = Uninstaller(), locations: PersistenceLocations = .system) async throws -> UninstallReport {
        guard let current = Self.inspect(plist.path, locations: locations), current.missingProgram == missingProgram else {
            throw OrphanedLaunchItemError.noLongerOrphaned(displayName)
        }
        let plan = plan()
        return try await uninstaller.uninstall(plan, selected: Set(plan.leftovers.map(\.path)))
    }
}

public enum OrphanedLaunchItemError: Error, LocalizedError, Equatable {
    case noLongerOrphaned(String)

    public var errorDescription: String? {
        switch self {
        case .noLongerOrphaned(let name): "\(name) was left in place: its program exists again, or the item changed since the scan. Scan Startup Items again to check."
        }
    }
}
