import Foundation

/// Where to look for browser extensions. `.system` is the real Mac; tests point `home` at a temporary
/// folder and pass canned `pluginkit` output.
public struct BrowserLocations: Sendable {
    public let home: URL
    /// Output of `pluginkit -mAvvv -p <extension point>`, or nil when it can't be run.
    public let safariListing: @Sendable (_ extensionPoint: String) -> String?

    public init(home: URL, safariListing: @escaping @Sendable (String) -> String?) {
        self.home = home
        self.safariListing = safariListing
    }

    public static var system: BrowserLocations {
        BrowserLocations(home: AppPaths.home, safariListing: { point in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/pluginkit")
            process.arguments = ["-mAvvv", "-p", point]
            let out = Pipe()
            process.standardOutput = out
            process.standardError = FileHandle.nullDevice
            process.standardInput = FileHandle.nullDevice
            do { try process.run() } catch { return nil }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return process.terminationStatus == 0 ? String(decoding: data, as: UTF8.self) : nil
        })
    }

    func support(_ relative: String) -> URL {
        home.appendingPathComponent("Library/Application Support/" + relative, isDirectory: true)
    }
}

/// One installed browser extension, as far as the browser's own files describe it.
public struct BrowserExtension: Equatable, Sendable {
    public enum Source: String, Sendable {
        case store = "the browser's extension store"
        case installedByDefault = "installed with the browser"
        case notFromStore = "outside the browser's store"
        case localFolder = "a local folder (developer mode)"
        case otherProgram = "another program on this Mac"
        case policy = "a management policy"
        case temporary = "a temporary developer install"
        case unsigned = "an unsigned add-on file"
        case app = "a Mac app"
        case unknown = "unknown"

        /// Not chosen by the user in the browser's store: worth a look.
        var isSideloaded: Bool {
            switch self {
            case .notFromStore, .localFolder, .otherProgram, .policy, .temporary, .unsigned: true
            case .store, .installedByDefault, .app, .unknown: false
            }
        }
    }

    public var browser: String
    /// Shown only when the browser has several profiles.
    public var profile: String?
    /// The profile folder, always set: part of the extension's identity between scans.
    public var profileID: String = ""
    public var id: String
    public var name: String
    public var version: String?
    public var enabled: Bool
    public var source: Source
    /// API permissions (`cookies`, `nativeMessaging`, …), sorted.
    public var permissions: [String]
    /// Website patterns it can read and change (`<all_urls>`, `https://example.com/*`, …), sorted.
    public var sites: [String]
    /// Folder or file to show in Finder and to run through the scan engines.
    public var path: String
    /// Safari: signature of the app that contains the extension.
    public var signature: SigningStatus?

    static let allSitesPatterns: Set<String> = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/"]

    public var canAccessAllSites: Bool { sites.contains { Self.allSitesPatterns.contains($0) } }

    /// Permissions that, combined with access to every website, allow spying or traffic tampering.
    static let sensitivePermissions: [(name: String, meaning: String)] = [
        ("cookies", "read cookies (your logins)"),
        ("history", "read your browsing history"),
        ("nativeMessaging", "talk to programs on this Mac"),
        ("debugger", "inspect and control pages with the debugger"),
        ("proxy", "route your traffic through a proxy"),
        ("management", "manage other extensions"),
        ("webRequest", "watch your network requests"),
        ("webRequestBlocking", "block or change network requests"),
        ("clipboardRead", "read the clipboard"),
        ("privacy", "change privacy settings"),
    ]

    public var sensitiveMeanings: [String] {
        Self.sensitivePermissions.filter { permissions.contains($0.name) }.map(\.meaning)
    }
}

/// What a browser extension is allowed to do, for change tracking between scans. The version is left
/// out on purpose: updates are routine, a new permission or install source is not.
public struct BrowserExtensionState: TrackedItemState {
    public var name: String
    public var source: String
    public var permissions: [String]
    public var sites: [String]

    public func differences(from old: BrowserExtensionState) -> [String] {
        var result: [String] = []
        if source != old.source { result.append("Installed from changed: \(old.source) → \(source)") }
        let added = permissions.filter { !old.permissions.contains($0) }
        let removed = old.permissions.filter { !permissions.contains($0) }
        if !added.isEmpty { result.append("Permissions added: " + added.joined(separator: ", ")) }
        if !removed.isEmpty { result.append("Permissions removed: " + removed.joined(separator: ", ")) }
        let newSites = sites.filter { !old.sites.contains($0) }
        if !newSites.isEmpty { result.append("Website access added: " + newSites.prefix(8).joined(separator: ", ") + (newSites.count > 8 ? ", …" : "")) }
        if sites.count < old.sites.count, newSites.isEmpty { result.append("Website access reduced") }
        return result
    }
}

public struct BrowserExtensionInventory: Sendable {
    public var extensions: [BrowserExtension] = []
    /// One finding per extension (engine `.extensions`), any severity.
    public var findings: [Finding] = []
    /// Extension folders/files to run through the scan engines, each as one unit.
    public var scanPaths: [String] = []
    public var coveredUnits: Set<String> = []
    public var snapshot: [String: BrowserExtensionState] = [:]
    public var notes: [String] = []
}

/// Lists the extensions of Chromium-based browsers, Firefox and Safari and flags the ones that were not
/// installed from the browser's store or that combine access to every website with sensitive
/// permissions. Read-only: nothing is disabled or removed.
public struct BrowserExtensionScanner: Sendable {
    public let locations: BrowserLocations

    public init(locations: BrowserLocations = .system) {
        self.locations = locations
    }

    /// Chromium-based browsers and their user-data folder under ~/Library/Application Support.
    static let chromiumBrowsers: [(name: String, folder: String)] = [
        ("Chrome", "Google/Chrome"), ("Chrome Beta", "Google/Chrome Beta"), ("Chrome Canary", "Google/Chrome Canary"),
        ("Chromium", "Chromium"), ("Edge", "Microsoft Edge"), ("Brave", "BraveSoftware/Brave-Browser"),
        ("Arc", "Arc/User Data"), ("Vivaldi", "Vivaldi"), ("Opera", "com.operasoftware.Opera"),
    ]

    static let safariExtensionPoints = ["com.apple.Safari.web-extension", "com.apple.Safari.extension", "com.apple.Safari.content-blocker"]

    public func collect() throws -> BrowserExtensionInventory {
        var inv = BrowserExtensionInventory()
        var browsers: [String] = []
        var unreadable: [String] = []

        for (name, folder) in Self.chromiumBrowsers {
            try Task.checkCancellation()
            let userData = locations.support(folder)
            guard FileManager.default.fileExists(atPath: userData.path) else { continue }
            let profiles = Self.chromiumProfiles(in: userData)
            if profiles.isEmpty, (try? FileManager.default.contentsOfDirectory(atPath: userData.path)) == nil {
                unreadable.append(name)
                continue
            }
            browsers.append(name)
            for profile in profiles {
                inv.extensions += Self.chromiumExtensions(browser: name, profile: profile, multipleProfiles: profiles.count > 1)
            }
        }

        let firefoxProfiles = locations.support("Firefox/Profiles")
        if let names = try? FileManager.default.contentsOfDirectory(atPath: firefoxProfiles.path) {
            browsers.append("Firefox")
            for name in names.sorted() {
                inv.extensions += Self.firefoxExtensions(profile: firefoxProfiles.appendingPathComponent(name), multipleProfiles: names.count > 1)
            }
        }

        var safari: [BrowserExtension] = []
        var safariListed = false
        for point in Self.safariExtensionPoints {
            guard let listing = locations.safariListing(point) else { continue }
            safariListed = true
            for found in Self.parseSafariListing(listing) where !safari.contains(where: { $0.id == found.id }) {
                safari.append(found)
            }
        }
        if safariListed { browsers.append("Safari") }
        inv.extensions += safari

        for item in inv.extensions {
            let key = [item.browser, item.profileID, item.id].joined(separator: "|")
            guard inv.snapshot[key] == nil else { continue }
            inv.snapshot[key] = BrowserExtensionState(name: "\(item.name) (\(item.browser))", source: item.source.rawValue,
                                                      permissions: item.permissions, sites: item.sites)
            inv.findings.append(Self.finding(for: item, key: key))
            inv.coveredUnits.insert(item.path)
            if FileManager.default.fileExists(atPath: item.path), !inv.scanPaths.contains(item.path) {
                inv.scanPaths.append(item.path)
            }
        }

        let count = inv.findings.count
        inv.notes.append(browsers.isEmpty
            ? "Browser extensions: no supported browser data was found."
            : "Browser extensions: \(count) extension\(count == 1 ? "" : "s") in \(browsers.joined(separator: ", ")). Nothing is disabled or removed; do that in the browser's own extension settings. For Safari, macOS shows what an extension may ask for, not which websites you allowed.")
        if !unreadable.isEmpty {
            inv.notes.append("Could not read the extension data of \(unreadable.joined(separator: ", ")) (macOS denied access).")
        }
        return inv
    }

    // MARK: - Verdict

    static func problems(for item: BrowserExtension) -> [(Severity, String)] {
        var problems: [(Severity, String)] = []
        switch item.source {
        case .localFolder, .temporary:
            problems.append((.warning, "loaded from a local folder, not installed from the store"))
        case .otherProgram:
            problems.append((.warning, "installed by another program, not by you in the browser"))
        case .policy:
            problems.append((.warning, "force-installed by a management policy"))
        case .notFromStore:
            problems.append((.warning, "not installed from the browser's store"))
        case .unsigned:
            problems.append((.warning, "not signed by the browser's add-on store"))
        case .store, .installedByDefault, .app, .unknown:
            break
        }
        if let signature = item.signature, signature.isUntrusted {
            problems.append((.warning, "its app isn't signed by a trusted developer"))
        }
        // A disabled extension can't use its permissions; how it got there still matters.
        if item.enabled, item.canAccessAllSites, !item.sensitiveMeanings.isEmpty {
            problems.append((.warning, "can read and change all websites and " + item.sensitiveMeanings.joined(separator: ", ")))
        }
        return problems
    }

    static func finding(for item: BrowserExtension, key: String) -> Finding {
        let problems = problems(for: item)
        var notes = ["Browser: \(item.browser)" + (item.profile.map { " (profile \($0))" } ?? "")]
        if let version = item.version { notes.append("Version: \(version)") }
        notes.append("ID: \(item.id)")
        notes.append("Status: " + (item.enabled ? "enabled" : "disabled"))
        notes.append("Installed from: \(item.source.rawValue)")
        if let signature = item.signature { notes.append("App signature: \(signature.description)") }
        let safari = item.browser == "Safari"
        if item.canAccessAllSites {
            notes.append("Website access: all websites" + (safari ? " (may ask; you choose the sites in Safari)" : ""))
        } else if !item.sites.isEmpty {
            notes.append("Website access: " + item.sites.prefix(8).joined(separator: ", ") + (item.sites.count > 8 ? " and \(item.sites.count - 8) more" : ""))
        } else {
            notes.append("Website access: none listed")
        }
        if !item.permissions.isEmpty { notes.append("Permissions: " + item.permissions.joined(separator: ", ")) }
        if problems.contains(where: { $0.1.hasPrefix("can read and change all websites") }) {
            notes.append("Ad blockers and password managers legitimately need this much access. Keep it if you installed it on purpose and trust its maker; choose Ignore to stop seeing this warning.")
        }

        let worst = problems.max { $0.0 < $1.0 }
        let summary = worst.map { problems.count > 1 ? "\($0.1) (+\(problems.count - 1) more)" : $0.1 }
            ?? "\(item.browser) extension" + (item.enabled ? "" : " (disabled)")
        return Finding(
            path: item.path,
            severity: worst?.0 ?? .clean,
            engine: .extensions,
            reason: "\(item.name): \(summary)",
            detail: (problems.count > 1 ? problems.map { "• \($0.1)" } + [""] : []).joined(separator: "\n") + notes.joined(separator: "\n"),
            unitPath: item.path,
            trackingKey: key
        )
    }

    // MARK: - Chromium

    /// Folders that hold a profile: the user-data folder itself (Opera) and its direct children.
    static func chromiumProfiles(in userData: URL) -> [URL] {
        let fm = FileManager.default
        func isProfile(_ url: URL) -> Bool {
            fm.fileExists(atPath: url.appendingPathComponent("Preferences").path)
                || fm.fileExists(atPath: url.appendingPathComponent("Secure Preferences").path)
        }
        var profiles = isProfile(userData) ? [userData] : []
        for name in (try? fm.contentsOfDirectory(atPath: userData.path))?.sorted() ?? []
        where name != "System Profile" && name != "Guest Profile" {
            let url = userData.appendingPathComponent(name, isDirectory: true)
            if isProfile(url) { profiles.append(url) }
        }
        return profiles
    }

    static func chromiumSettings(in profile: URL) -> [String: [String: Any]] {
        var merged: [String: [String: Any]] = [:]
        // Later file wins: Chromium keeps the authoritative copy in "Secure Preferences".
        for file in ["Preferences", "Secure Preferences"] {
            guard let data = try? Data(contentsOf: profile.appendingPathComponent(file)),
                  let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let settings = (root["extensions"] as? [String: Any])?["settings"] as? [String: Any] else { continue }
            for (id, value) in settings {
                if let value = value as? [String: Any] { merged[id] = value }
            }
        }
        return merged
    }

    static func chromiumExtensions(browser: String, profile: URL, multipleProfiles: Bool) -> [BrowserExtension] {
        let fm = FileManager.default
        let settings = chromiumSettings(in: profile)
        let extensionsDir = profile.appendingPathComponent("Extensions", isDirectory: true)
        let onDisk = ((try? fm.contentsOfDirectory(atPath: extensionsDir.path)) ?? []).filter { $0.count == 32 }
        let profileName = multipleProfiles ? profile.lastPathComponent : nil
        var result: [BrowserExtension] = []

        for id in Set(settings.keys).union(onDisk).sorted() {
            let entry = settings[id] ?? [:]
            let location = (entry["location"] as? NSNumber)?.intValue
            // 5 and 10 are components built into the browser itself.
            if location == 5 || location == 10 { continue }

            var folder = extensionsDir.appendingPathComponent(id, isDirectory: true)
            var versionFolder = newestVersionFolder(in: folder)
            if let path = entry["path"] as? String, path.hasPrefix("/") {
                folder = URL(fileURLWithPath: path, isDirectory: true)   // unpacked: lives wherever the user loaded it from
                versionFolder = folder
            }
            let manifest = (entry["manifest"] as? [String: Any])
                ?? versionFolder.flatMap { readJSON($0.appendingPathComponent("manifest.json")) }
            // In neither the settings nor on disk as a real extension: a stale entry.
            guard manifest != nil || fm.fileExists(atPath: folder.path) else { continue }

            var (permissions, sites) = permissionsAndSites(manifest: manifest ?? [:])
            if let active = entry["active_permissions"] as? [String: Any] {
                permissions = (active["api"] as? [Any] ?? []).compactMap { $0 as? String }
                sites = ((active["explicit_host"] as? [Any] ?? []) + (active["scriptable_host"] as? [Any] ?? [])).compactMap { $0 as? String }
            }
            result.append(BrowserExtension(
                browser: browser, profile: profileName, profileID: profile.lastPathComponent, id: id,
                name: chromiumName(manifest: manifest ?? [:], versionFolder: versionFolder) ?? id,
                version: manifest?["version"] as? String,
                enabled: chromiumEnabled(entry),
                source: chromiumSource(entry, location: location),
                permissions: Array(Set(permissions)).sorted(), sites: Array(Set(sites)).sorted(),
                path: folder.path))
        }
        return result
    }

    static func chromiumEnabled(_ entry: [String: Any]) -> Bool {
        if let reasons = entry["disable_reasons"] as? [Any] { return reasons.isEmpty }
        if let reasons = entry["disable_reasons"] as? NSNumber { return reasons.intValue == 0 }
        if let state = entry["state"] as? NSNumber { return state.intValue != 0 }
        return true
    }

    static func chromiumSource(_ entry: [String: Any], location: Int?) -> BrowserExtension.Source {
        switch location {
        case 4, 8: return .localFolder
        case 2, 3, 6: return .otherProgram
        case 7, 9: return .policy
        case 1:
            if (entry["was_installed_by_default"] as? Bool) == true || (entry["was_installed_by_oem"] as? Bool) == true { return .installedByDefault }
            if let fromStore = entry["from_webstore"] as? Bool { return fromStore ? .store : .notFromStore }
            return .store
        default: return .unknown
        }
    }

    static func newestVersionFolder(in folder: URL) -> URL? {
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []).filter { !$0.hasPrefix(".") }
        guard let newest = names.max(by: { $0.compare($1, options: .numeric) == .orderedAscending }) else { return nil }
        return folder.appendingPathComponent(newest, isDirectory: true)
    }

    /// Splits a manifest's permission lists into API names and website patterns (MV2 mixes them).
    static func permissionsAndSites(manifest: [String: Any]) -> (permissions: [String], sites: [String]) {
        var permissions: [String] = []
        var sites: [String] = []
        func add(_ values: Any?) {
            for case let value as String in values as? [Any] ?? [] {
                if value == "<all_urls>" || value.contains("://") { sites.append(value) } else { permissions.append(value) }
            }
        }
        add(manifest["permissions"])
        add(manifest["host_permissions"])
        for case let script as [String: Any] in manifest["content_scripts"] as? [Any] ?? [] { add(script["matches"]) }
        return (permissions, sites)
    }

    /// The manifest name, with `__MSG_key__` placeholders looked up in the default locale.
    static func chromiumName(manifest: [String: Any], versionFolder: URL?) -> String? {
        guard let name = manifest["name"] as? String, !name.isEmpty else { return nil }
        guard name.hasPrefix("__MSG_"), name.hasSuffix("__"), let versionFolder else { return name }
        let key = String(name.dropFirst(6).dropLast(2)).lowercased()
        for locale in [manifest["default_locale"] as? String, "en", "en_US"].compactMap({ $0 }) {
            guard let messages = readJSON(versionFolder.appendingPathComponent("_locales/\(locale)/messages.json")) else { continue }
            if let match = messages.first(where: { $0.key.lowercased() == key })?.value as? [String: Any],
               let message = match["message"] as? String, !message.isEmpty {
                return message
            }
        }
        return nil
    }

    static func readJSON(_ url: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    // MARK: - Firefox

    static func firefoxExtensions(profile: URL, multipleProfiles: Bool) -> [BrowserExtension] {
        guard let root = readJSON(profile.appendingPathComponent("extensions.json")) else { return [] }
        var result: [BrowserExtension] = []
        for case let addon as [String: Any] in root["addons"] as? [Any] ?? [] {
            guard addon["type"] as? String == "extension", let id = addon["id"] as? String else { continue }
            let location = addon["location"] as? String ?? ""
            // Built into Firefox itself.
            if location.hasPrefix("app-system") || location == "app-builtin" || location == "app-builtin-addons" { continue }

            let granted = addon["userPermissions"] as? [String: Any] ?? [:]
            let signedState = (addon["signedState"] as? NSNumber)?.intValue
            var source = BrowserExtension.Source.store
            if (addon["temporarilyInstalled"] as? Bool) == true {
                source = .temporary
            } else if let signedState, signedState < 1 {
                source = .unsigned
            } else if location != "app-profile" {
                source = .otherProgram
            }
            let path = addon["path"] as? String ?? profile.appendingPathComponent("extensions/\(id).xpi").path
            result.append(BrowserExtension(
                browser: "Firefox", profile: multipleProfiles ? profile.lastPathComponent : nil, profileID: profile.lastPathComponent, id: id,
                name: (addon["defaultLocale"] as? [String: Any])?["name"] as? String ?? id,
                version: addon["version"] as? String,
                enabled: (addon["active"] as? Bool) ?? !((addon["userDisabled"] as? Bool) ?? false),
                source: source,
                permissions: (granted["permissions"] as? [Any] ?? []).compactMap { $0 as? String }.sorted(),
                sites: (granted["origins"] as? [Any] ?? []).compactMap { $0 as? String }.sorted(),
                path: path))
        }
        return result
    }

    // MARK: - Safari

    /// Parses `pluginkit -mAvvv` output: one block per extension, starting with `[+-!] id(version)`.
    static func parseSafariListing(_ listing: String) -> [BrowserExtension] {
        var result: [BrowserExtension] = []
        var header: (id: String, version: String?, enabled: Bool)?
        var fields: [String: String] = [:]

        func flush() {
            defer { header = nil; fields = [:] }
            guard let header, let path = fields["Path"] else { return }
            let parent = fields["Parent Bundle"]
            let manifest = readJSON(URL(fileURLWithPath: path).appendingPathComponent("Contents/Resources/manifest.json")) ?? [:]
            let (permissions, sites) = permissionsAndSites(manifest: manifest)
            var name = fields["Display Name"] ?? header.id
            if name.contains("$("), let parent { name = URL(fileURLWithPath: parent).deletingPathExtension().lastPathComponent }
            result.append(BrowserExtension(
                browser: "Safari", profile: nil, id: header.id, name: name, version: header.version,
                enabled: header.enabled, source: .app,
                permissions: Array(Set(permissions)).sorted(), sites: Array(Set(sites)).sorted(),
                path: path,
                signature: CodeSigning.status(of: URL(fileURLWithPath: parent ?? path))))
        }

        for raw in listing.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if let separator = line.range(of: " = ") {
                fields[String(line[..<separator.lowerBound])] = String(line[separator.upperBound...])
            } else if line.hasSuffix(")"), let open = line.lastIndex(of: "("), !line.contains(" = ") {
                flush()
                var id = String(line[..<open])
                var enabled = true
                if let marker = id.first, "+-!".contains(marker) {
                    enabled = marker == "+"
                    id = String(id.dropFirst())
                }
                id = id.trimmingCharacters(in: .whitespaces)
                let version = String(line[line.index(after: open)..<line.index(before: line.endIndex)])
                header = (id, version == "(null)" || version.isEmpty ? nil : version, enabled)
            }
        }
        flush()
        return result
    }
}
