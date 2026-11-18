import Foundation

/// One record from macOS's Background Task Management database (what System Settings › General ›
/// Login Items & Extensions shows), as printed by `sfltool dumpbtm` (no root needed).
public struct BTMRecord: Hashable, Sendable {
    public var identifier: String = ""        // e.g. "2.com.openai.chat", "8.com.openai.chat-helper"
    public var name: String = ""
    public var type: String = ""              // e.g. "app (0x2)", "agent (0x8)", "legacy agent (0x10008)"
    public var url: String?                   // absolute, or relative to the parent app for embedded items
    public var executablePath: String?
    public var bundleID: String?
    public var parentIdentifier: String?
    public var teamID: String?
    public var developerName: String?

    var typeCode: Int {
        guard let open = type.lastIndex(of: "("), let close = type.lastIndex(of: ")"),
              let value = Int(type[type.index(open, offsetBy: 3)..<close], radix: 16) else { return 0 }
        return value
    }

    public var isApp: Bool { typeCode == 0x2 }
    public var isLegacy: Bool { typeCode & 0x10000 != 0 }
    /// Launch agent or login item (user session) or daemon (system), legacy or SMAppService.
    public var launchDomain: LaunchDomain? {
        switch typeCode & 0xFFFF {
        case 0x4, 0x8: .gui
        case 0x10: .system
        default: nil
        }
    }

    /// launchd label for agents/daemons: the identifier without its "<type>." prefix.
    public var label: String? {
        guard launchDomain != nil, let dot = identifier.firstIndex(of: ".") else { return nil }
        return String(identifier[identifier.index(after: dot)...])
    }

    public var isEmbedded: Bool { !(url ?? "/").hasPrefix("/") }
}

public enum BackgroundItems {
    public static func load() -> [BTMRecord] {
        guard let text = LeftoverFinder.run("/usr/bin/sfltool", ["dumpbtm"]) else { return [] }
        return parse(text)
    }

    public static func parse(_ text: String) -> [BTMRecord] {
        var records: [BTMRecord] = []
        var current: BTMRecord?
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            // A record starts with "#<n>:" at the record indentation (embedded item lists use the same form,
            // but those lines have content after the colon).
            if line.hasPrefix("#"), line.hasSuffix(":"), Int(line.dropFirst().dropLast()) != nil {
                if let c = current { records.append(c) }
                current = BTMRecord()
                continue
            }
            guard current != nil, let colon = line.range(of: ": ") else { continue }
            let key = String(line[..<colon.lowerBound])
            var value = String(line[colon.upperBound...]).trimmingCharacters(in: .whitespaces)
            if value == "(null)" { value = "" }
            switch key {
            case "Identifier": current?.identifier = value
            case "Name": current?.name = value
            case "Type": current?.type = value
            case "URL": current?.url = value.isEmpty ? nil : decodeURL(value)
            case "Executable Path": current?.executablePath = value.isEmpty ? nil : value
            case "Bundle Identifier": current?.bundleID = value.isEmpty ? nil : value
            case "Parent Identifier": current?.parentIdentifier = value.isEmpty ? nil : value
            case "Team Identifier": current?.teamID = value.isEmpty ? nil : value
            case "Developer Name": current?.developerName = value.isEmpty ? nil : value
            default: break
            }
        }
        if let c = current { records.append(c) }
        return records.filter { !$0.identifier.isEmpty }
    }

    /// BTM prints file URLs as paths, with "/Users/<uid>/" instead of the user name, and sometimes percent-encoded.
    static func decodeURL(_ value: String) -> String {
        var path = value
        if path.hasPrefix("file://"), let url = URL(string: path) { path = url.path }
        path = path.removingPercentEncoding ?? path
        let uidHome = "/Users/\(getuid())/"
        if path.hasPrefix(uidHome) {
            path = AppPaths.home.path + "/" + path.dropFirst(uidHome.count)
        }
        return path
    }

    /// Background items that belong to an app: its app record's children, plus legacy items grouped under
    /// the app's name. Team-only matches (same developer, different product) are returned separately.
    public static func items(for app: InstalledApp, in records: [BTMRecord]) -> (owned: [BTMRecord], sameDeveloper: [BTMRecord]) {
        let ids = Set(app.allBundleIDs.map { $0.lowercased() })
        let appRecords = records.filter { r in
            r.isApp && (r.bundleID.map { ids.contains($0.lowercased()) } == true || r.url == app.url.path)
        }
        let parentIDs = Set(appRecords.map(\.identifier))
        let names = Set(app.names.map { $0.lowercased() } + appRecords.map { $0.name.lowercased() })

        var owned: [BTMRecord] = []
        var sameDeveloper: [BTMRecord] = []
        for r in records where !r.isApp {
            if let parent = r.parentIdentifier, parentIDs.contains(parent) {
                owned.append(r)
            } else if let parent = r.parentIdentifier, r.isLegacy, names.contains(parent.lowercased()),
                      app.teamID == nil || r.teamID == nil || r.teamID == app.teamID {
                owned.append(r)
            } else if r.bundleID.map({ ids.contains($0.lowercased()) }) == true {
                owned.append(r)
            } else if r.isLegacy, let team = app.teamID, r.teamID == team {
                sameDeveloper.append(r)
            }
        }
        return (owned, sameDeveloper)
    }
}
