import Foundation

// Cleanup suggestions: after a disk usage scan, points out folders and files that are usually safe or
// worthwhile to delete (caches, build output, old installers, …), with what deleting them means and how.
// Read-only. The app removes something only after the user confirms.

public enum CleanupPriority: Int, Comparable, Sendable, CaseIterable {
    /// Rebuilt or re-downloaded automatically; deleting loses nothing you made.
    case safe = 0
    /// Probably not needed, but check first: deleting can lose data or force a long re-download.
    case review = 1

    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }

    public var title: String {
        switch self {
        case .safe: "Safe to clean"
        case .review: "Review first"
        }
    }
}

/// How the app should offer to clean a suggestion.
public enum CleanupAction: Sendable, Equatable {
    /// Move the item itself to the Trash.
    case trashItem
    /// Move everything inside to the Trash, keeping the folder (apps expect folders like Caches to exist).
    case trashContents
    /// Don't delete in Finder; follow these instructions instead (e.g. Docker's disk image).
    case manual(String)
}

public struct CleanupSuggestion: Identifiable, Sendable, Equatable {
    public var id: String { item.path }
    public let item: DiskItem
    public let title: String
    public let priority: CleanupPriority
    /// What it is and what happens if it's deleted.
    public let explanation: String
    public let action: CleanupAction
}

public struct CleanupAdvisor: Sendable {
    struct Rule: Sendable {
        /// Path relative to the home folder.
        let relativePath: String
        let title: String
        let priority: CleanupPriority
        let explanation: String
        let action: CleanupAction
    }

    let home: String
    /// Files in Downloads older than this are suggested (installers and archives).
    let oldDownloadAge: TimeInterval
    /// Large files unchanged for longer than this are suggested for review.
    let staleFileAge: TimeInterval
    let now: Date
    /// Smaller folders aren't worth suggesting.
    let minimumSize: Int64
    /// Smallest old download / stale file worth suggesting.
    let minimumDownloadSize: Int64
    let minimumStaleFileSize: Int64

    public init(home: URL = AppPaths.home, now: Date = Date(), oldDownloadDays: Double = 30, staleFileDays: Double = 365,
                minimumSize: Int64 = 50_000_000, minimumDownloadSize: Int64 = 10_000_000, minimumStaleFileSize: Int64 = 500_000_000) {
        self.home = Paths.canonical(home).path
        self.now = now
        self.oldDownloadAge = oldDownloadDays * 86_400
        self.staleFileAge = staleFileDays * 86_400
        self.minimumSize = minimumSize
        self.minimumDownloadSize = minimumDownloadSize
        self.minimumStaleFileSize = minimumStaleFileSize
    }

    static let rules: [Rule] = [
        Rule(relativePath: ".Trash", title: "Trash", priority: .safe,
             explanation: "Items you already deleted. They still take space until the Trash is emptied.",
             action: .manual("Empty the Trash in Finder (Finder › Empty Trash).")),
        Rule(relativePath: "Library/Caches", title: "App caches", priority: .safe,
             explanation: "Temporary data apps keep to work faster. Apps rebuild it as needed; the first launch afterwards may be slower. Quit apps before cleaning.",
             action: .trashContents),
        Rule(relativePath: "Library/Logs", title: "Logs", priority: .safe,
             explanation: "Diagnostic logs written by apps and macOS. Only needed when troubleshooting.",
             action: .trashContents),
        Rule(relativePath: "Library/Developer/Xcode/DerivedData", title: "Xcode build data", priority: .safe,
             explanation: "Intermediate build products and indexes. Xcode rebuilds them on the next build.",
             action: .trashContents),
        Rule(relativePath: "Library/Developer/Xcode/iOS DeviceSupport", title: "iOS device support files", priority: .safe,
             explanation: "Debug symbols copied from devices you connected. Xcode copies them again when a device is connected; old iOS versions are rarely needed.",
             action: .trashContents),
        Rule(relativePath: "Library/Developer/Xcode/watchOS DeviceSupport", title: "watchOS device support files", priority: .safe,
             explanation: "Debug symbols copied from Apple Watches. Recreated when needed.", action: .trashContents),
        Rule(relativePath: "Library/Developer/Xcode/tvOS DeviceSupport", title: "tvOS device support files", priority: .safe,
             explanation: "Debug symbols copied from Apple TVs. Recreated when needed.", action: .trashContents),
        Rule(relativePath: "Library/Developer/Xcode/visionOS DeviceSupport", title: "visionOS device support files", priority: .safe,
             explanation: "Debug symbols copied from Vision Pro. Recreated when needed.", action: .trashContents),
        Rule(relativePath: "Library/Developer/CoreSimulator/Caches", title: "Simulator caches", priority: .safe,
             explanation: "Caches of the iOS Simulator. Rebuilt automatically.", action: .trashContents),
        Rule(relativePath: "Library/Developer/Xcode/Archives", title: "Xcode archives", priority: .review,
             explanation: "Builds you archived for distribution. Keep the ones for app versions you still support: they're needed to read crash reports.",
             action: .trashItem),
        Rule(relativePath: "Library/Developer/CoreSimulator/Devices", title: "iOS Simulators", priority: .review,
             explanation: "Simulator devices with their installed apps and data. Simulators for old iOS versions can usually go.",
             action: .manual("Remove unused simulators in Xcode › Window › Devices and Simulators, or run `xcrun simctl delete unavailable` in Terminal.")),
        Rule(relativePath: "Library/Application Support/MobileSync/Backup", title: "iPhone and iPad backups", priority: .review,
             explanation: "Local device backups made by Finder. Deleting a backup can't be undone; keep the latest one of each device you use.",
             action: .manual("Manage backups in Finder: select your device in the sidebar › Manage Backups…")),
        Rule(relativePath: "Library/Containers/com.docker.docker/Data/vms", title: "Docker disk image", priority: .review,
             explanation: "All Docker images, containers and volumes live in this disk image. Deleting the file loses all of them.",
             action: .manual("Free space inside Docker instead: run `docker system prune -a` (and `docker volume prune` for unused volumes), or use Docker Desktop › Troubleshoot › Clean / Purge data.")),
        Rule(relativePath: "Library/Containers/com.apple.mail/Data/Library/Mail Downloads", title: "Mail attachments", priority: .safe,
             explanation: "Copies of attachments you opened from Mail. The originals stay in your mail.", action: .trashContents),
        Rule(relativePath: "Library/Caches/Homebrew", title: "Homebrew downloads", priority: .safe,
             explanation: "Old package downloads kept by Homebrew.", action: .manual("Run `brew cleanup --prune=all` in Terminal.")),
        Rule(relativePath: ".npm", title: "npm cache", priority: .safe,
             explanation: "Downloaded npm packages. Re-downloaded when a project needs them.",
             action: .manual("Run `npm cache clean --force` in Terminal, or move the folder to the Trash.")),
        Rule(relativePath: ".cache/pip", title: "pip cache", priority: .safe,
             explanation: "Downloaded Python packages. Re-downloaded when needed.", action: .trashItem),
        Rule(relativePath: "Library/Caches/pip", title: "pip cache", priority: .safe,
             explanation: "Downloaded Python packages. Re-downloaded when needed.", action: .trashContents),
        Rule(relativePath: ".cache/huggingface", title: "Hugging Face models", priority: .review,
             explanation: "Downloaded AI models and datasets. Delete models you no longer use; they're downloaded again (often many GB) if a project needs them.",
             action: .trashItem),
        Rule(relativePath: ".gradle/caches", title: "Gradle cache", priority: .safe,
             explanation: "Downloaded dependencies and build caches for Gradle/Android projects. Re-downloaded on the next build.",
             action: .trashItem),
        Rule(relativePath: ".m2/repository", title: "Maven repository", priority: .safe,
             explanation: "Downloaded Java libraries. Re-downloaded on the next build.", action: .trashItem),
        Rule(relativePath: ".cargo/registry", title: "Cargo registry", priority: .safe,
             explanation: "Downloaded Rust crates. Re-downloaded on the next build.", action: .trashItem),
        Rule(relativePath: "go/pkg/mod", title: "Go module cache", priority: .safe,
             explanation: "Downloaded Go modules. Re-downloaded on the next build.",
             action: .manual("Run `go clean -modcache` in Terminal (the files are read-only, so Finder may refuse).")),
        Rule(relativePath: "Library/Caches/CocoaPods", title: "CocoaPods cache", priority: .safe,
             explanation: "Downloaded pods. Re-downloaded by `pod install`.", action: .trashItem),
        Rule(relativePath: ".ollama/models", title: "Ollama models", priority: .review,
             explanation: "Local AI models downloaded by Ollama. Deleting files here directly breaks the models.",
             action: .manual("List models with `ollama list` and remove unused ones with `ollama rm <model>`.")),
        Rule(relativePath: "Library/Application Support/nomic.ai/GPT4All", title: "GPT4All models", priority: .review,
             explanation: "Local AI models downloaded by GPT4All. Delete models you no longer use.",
             action: .manual("Remove models in GPT4All › Models.")),
        Rule(relativePath: ".android/avd", title: "Android emulators", priority: .review,
             explanation: "Android Virtual Devices with their data. Remove emulators you no longer use.",
             action: .manual("Delete unused emulators in Android Studio › Device Manager.")),
        Rule(relativePath: "Library/Android/sdk/system-images", title: "Android system images", priority: .review,
             explanation: "Emulator system images. Remove Android versions you don't test on.",
             action: .manual("Uninstall old images in Android Studio › SDK Manager.")),
    ]

    /// Installer and archive types worth removing from Downloads once they're old.
    static let downloadExtensions: Set<String> = ["dmg", "pkg", "mpkg", "iso", "zip", "xip", "tar", "gz", "tgz", "rar", "7z"]

    /// Suggestions for a report, most worthwhile first ("Safe to clean" before "Review first", then by size).
    /// Runs over every folder once; call off the main thread for large reports.
    public func suggestions(for report: DiskUsageReport) -> [CleanupSuggestion] {
        var found: [CleanupSuggestion] = []

        for rule in Self.rules {
            let path = home + "/" + rule.relativePath
            guard let item = report.folder(path), item.size >= minimumSize else { continue }
            found.append(CleanupSuggestion(item: item, title: rule.title, priority: rule.priority, explanation: rule.explanation, action: rule.action))
        }

        // Project dependency folders: node_modules, Python virtual environments, CocoaPods. Only in projects:
        // not inside ~/Library or a hidden folder in home (editor extensions, global tool installs), where
        // deleting them breaks the tool.
        let library = home + "/Library/"
        let hiddenInHome = home + "/."
        for path in report.folders.keys where !path.hasPrefix(library) && !path.hasPrefix(hiddenInHome) {
            let name = (path as NSString).lastPathComponent
            let parent = (path as NSString).deletingLastPathComponent
            let suggestion: (String, String)?
            switch name {
            case "node_modules" where !parent.contains("/node_modules"):
                suggestion = ("Node.js dependencies", "Packages installed for a JavaScript project. `npm install` (or yarn/pnpm) restores them; delete them for projects you're not working on.")
            case ".venv" where report.folders[path + "/bin"] != nil || report.folders[path + "/lib"] != nil,
                 "venv" where report.folders[path + "/bin"] != nil || report.folders[path + "/lib"] != nil:
                suggestion = ("Python virtual environment", "Packages installed for a Python project. Recreate it from the project's requirements when needed.")
            case "Pods" where report.folders[parent + "/Pods/Target Support Files"] != nil:
                suggestion = ("CocoaPods dependencies", "Pods installed for an iOS project. `pod install` restores them.")
            default:
                suggestion = nil
            }
            guard let (title, explanation) = suggestion, let item = report.folder(path), item.size >= minimumSize else { continue }
            found.append(CleanupSuggestion(item: item, title: title, priority: .review, explanation: explanation, action: .trashItem))
        }

        // Old installers and archives in Downloads.
        for item in report.children(of: home + "/Downloads") where !item.isAggregate && !item.isDirectory {
            let ext = (item.path as NSString).pathExtension.lowercased()
            guard Self.downloadExtensions.contains(ext), item.size >= minimumDownloadSize,
                  let modified = item.modified, now.timeIntervalSince(modified) > oldDownloadAge else { continue }
            found.append(CleanupSuggestion(item: item, title: "Old download", priority: .review,
                                           explanation: "An installer or archive downloaded \(Self.age(modified, now: now)) ago. If you've already installed or unpacked it, it's no longer needed.",
                                           action: .trashItem))
        }

        // Large files nobody has changed for a long time.
        for item in report.largestFiles where item.size >= minimumStaleFileSize {
            guard let modified = item.modified, now.timeIntervalSince(modified) > staleFileAge else { continue }
            found.append(CleanupSuggestion(item: item, title: "Large, unchanged file", priority: .review,
                                           explanation: "Not changed for \(Self.age(modified, now: now)). If you don't need it any more, it frees a lot of space; consider an external disk for archives.",
                                           action: .trashItem))
        }

        // Most worthwhile first; drop anything inside an item that's already suggested (no double counting).
        found.sort { $0.priority != $1.priority ? $0.priority < $1.priority : $0.item.size > $1.item.size }
        var kept: [CleanupSuggestion] = []
        var keptPaths = Set<String>()
        for s in found where !keptPaths.contains(s.item.path) {
            if hasAncestor(s.item.path, in: keptPaths) { continue }
            // A broader suggestion (e.g. ~/Library/Caches) replaces narrower ones already kept inside it.
            let prefix = s.item.path + "/"
            kept.removeAll { $0.item.path.hasPrefix(prefix) }
            keptPaths = keptPaths.filter { !$0.hasPrefix(prefix) }
            kept.append(s)
            keptPaths.insert(s.item.path)
        }
        return kept.sorted { $0.priority != $1.priority ? $0.priority < $1.priority : $0.item.size > $1.item.size }
    }

    private func hasAncestor(_ path: String, in paths: Set<String>) -> Bool {
        var p = (path as NSString).deletingLastPathComponent
        while p.count > 1 {
            if paths.contains(p) { return true }
            p = (p as NSString).deletingLastPathComponent
        }
        return false
    }

    static func age(_ date: Date, now: Date) -> String {
        let days = Int(now.timeIntervalSince(date) / 86_400)
        if days >= 730 { return "\(days / 365) years" }
        if days >= 365 { return "over a year" }
        if days >= 60 { return "\(days / 30) months" }
        return "\(days) days"
    }
}

// MARK: - Clean up several suggestions at once

/// What happened to one suggestion during a clean-up.
public struct CleanupOutcome: Sendable, Equatable {
    public let suggestion: CleanupSuggestion
    /// Paths moved to the Trash: the item itself, or the folder's contents.
    public let moved: [String]
    /// Paths that couldn't be moved, with the reason.
    public let failed: [String: String]
    /// The whole suggestion was cleaned (item moved, or folder fully emptied).
    public var complete: Bool { failed.isEmpty }
}

/// Moves suggestions to the Trash: `.trashItem` moves the item, `.trashContents` moves everything inside the folder.
/// `.manual` suggestions are never touched. Every path is checked with `Uninstaller.isSafeToRemove` first.
public struct CleanupRunner: Sendable {
    let trash: @Sendable (URL) throws -> Void

    public init(trash: @escaping @Sendable (URL) throws -> Void = { try FileManager.default.trashItem(at: $0, resultingItemURL: nil) }) {
        self.trash = trash
    }

    public func run(_ suggestions: [CleanupSuggestion], progress: (@Sendable (Int, Int, String) -> Void)? = nil) -> [CleanupOutcome] {
        let runnable = suggestions.filter { $0.action == .trashItem || $0.action == .trashContents }
        var outcomes: [CleanupOutcome] = []
        for (index, suggestion) in runnable.enumerated() {
            if Task.isCancelled { break }
            progress?(index, runnable.count, suggestion.title)
            var moved: [String] = []
            var failed: [String: String] = [:]
            let targets: [URL]
            switch suggestion.action {
            case .trashContents:
                targets = (try? FileManager.default.contentsOfDirectory(at: suggestion.item.url, includingPropertiesForKeys: nil, options: [])) ?? []
            default:
                targets = [suggestion.item.url]
            }
            for url in targets {
                guard Uninstaller.isSafeToRemove(url.path) else {
                    failed[url.path] = "Protected location"
                    continue
                }
                do {
                    try trash(url)
                    moved.append(url.path)
                } catch {
                    failed[url.path] = PermissionErrors.isPermissionDenied(error)
                        ? "Permission denied (in use, or protected by macOS)" : error.localizedDescription
                }
            }
            outcomes.append(CleanupOutcome(suggestion: suggestion, moved: moved, failed: failed))
        }
        progress?(runnable.count, runnable.count, "")
        return outcomes
    }
}

extension DiskUsageReport {
    /// Applies a clean-up's outcomes: removed items leave the report, fully emptied folders stay with size 0.
    /// (For partly emptied folders only the listed sub-items that moved are subtracted.)
    public mutating func apply(_ outcomes: [CleanupOutcome]) {
        for outcome in outcomes {
            let item = outcome.suggestion.item
            switch outcome.suggestion.action {
            case .trashItem where !outcome.moved.isEmpty:
                markRemoved(folder(item.path) ?? item)
            case .trashContents where outcome.failed.isEmpty:
                markEmptied(item.path)
            case .trashContents:
                let moved = Set(outcome.moved)
                for child in children(of: item.path) where moved.contains(child.path) { markRemoved(child) }
            default:
                break
            }
        }
    }
}
