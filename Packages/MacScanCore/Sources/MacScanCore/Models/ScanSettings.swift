import Foundation

/// User-configurable scan settings. Persisted as JSON in UserDefaults by `SettingsStore`.
public struct ScanSettings: Codable, Hashable, Sendable {
    /// Files larger than this are skipped (and passed to clamscan as its max file size).
    public var maxFileSizeMB: Int = 100
    /// When true, symbolic links are ignored. When false, links to regular files are scanned
    /// at their destination (symlinked directories are never followed, to avoid loops).
    public var skipSymlinks: Bool = true
    /// Absolute path prefixes that are never scanned.
    public var excludedPaths: [String] = []
    /// In "Scan Applications", only scan executables and scripts inside bundles (much faster).
    public var appScanExecutablesOnly: Bool = true

    public var enableClamAV: Bool = true
    public var enableYara: Bool = true
    public var enableIntegrity: Bool = true

    /// Optional explicit tool paths. `nil`/empty means auto-detect (Homebrew locations).
    public var clamscanPath: String?
    public var freshclamPath: String?
    public var yaraPath: String?
    public var yaracPath: String?

    /// Optional explicit ClamAV database directory.
    public var clamDatabasePath: String?
    /// Folder with .yar/.yara files. `nil` means the bundled sample rules.
    public var yaraRulesFolder: String?
    /// Also use Apple's XProtect YARA rules that ship with macOS (read in place, never modified).
    public var useXProtectRules: Bool = true

    /// If true (and an API key is set), flagged files are looked up on VirusTotal by hash after a scan.
    public var vtAutoLookupFlagged: Bool = false

    /// Run scans as root after asking for an administrator password once per scan, so files owned by
    /// other users or the system can be read. (Privacy-protected folders still need Full Disk Access.)
    public var elevatedScans: Bool = false

    public init() {}

    public var maxFileSizeBytes: Int64 { Int64(max(1, maxFileSizeMB)) * 1024 * 1024 }

    public func isExcluded(_ path: String) -> Bool {
        for raw in excludedPaths {
            let prefix = (raw as NSString).expandingTildeInPath
            guard !prefix.isEmpty else { continue }
            let trimmed = prefix.hasSuffix("/") ? String(prefix.dropLast()) : prefix
            if path == trimmed || path.hasPrefix(trimmed + "/") { return true }
        }
        return false
    }

    // Tolerant decoding: missing keys fall back to defaults so new settings never wipe old ones.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = ScanSettings()
        maxFileSizeMB = try c.decodeIfPresent(Int.self, forKey: .maxFileSizeMB) ?? d.maxFileSizeMB
        skipSymlinks = try c.decodeIfPresent(Bool.self, forKey: .skipSymlinks) ?? d.skipSymlinks
        excludedPaths = try c.decodeIfPresent([String].self, forKey: .excludedPaths) ?? d.excludedPaths
        appScanExecutablesOnly = try c.decodeIfPresent(Bool.self, forKey: .appScanExecutablesOnly) ?? d.appScanExecutablesOnly
        enableClamAV = try c.decodeIfPresent(Bool.self, forKey: .enableClamAV) ?? d.enableClamAV
        enableYara = try c.decodeIfPresent(Bool.self, forKey: .enableYara) ?? d.enableYara
        enableIntegrity = try c.decodeIfPresent(Bool.self, forKey: .enableIntegrity) ?? d.enableIntegrity
        clamscanPath = try c.decodeIfPresent(String.self, forKey: .clamscanPath)
        freshclamPath = try c.decodeIfPresent(String.self, forKey: .freshclamPath)
        yaraPath = try c.decodeIfPresent(String.self, forKey: .yaraPath)
        yaracPath = try c.decodeIfPresent(String.self, forKey: .yaracPath)
        clamDatabasePath = try c.decodeIfPresent(String.self, forKey: .clamDatabasePath)
        yaraRulesFolder = try c.decodeIfPresent(String.self, forKey: .yaraRulesFolder)
        useXProtectRules = try c.decodeIfPresent(Bool.self, forKey: .useXProtectRules) ?? d.useXProtectRules
        vtAutoLookupFlagged = try c.decodeIfPresent(Bool.self, forKey: .vtAutoLookupFlagged) ?? d.vtAutoLookupFlagged
        elevatedScans = try c.decodeIfPresent(Bool.self, forKey: .elevatedScans) ?? d.elevatedScans
    }
}

public enum SettingsStore {
    static let key = "MacScan.ScanSettings"

    public static func load(from defaults: UserDefaults = .standard) -> ScanSettings {
        guard let data = defaults.data(forKey: key),
              let settings = try? JSONDecoder().decode(ScanSettings.self, from: data)
        else { return ScanSettings() }
        return settings
    }

    public static func save(_ settings: ScanSettings, to defaults: UserDefaults = .standard) {
        if let data = try? JSONEncoder().encode(settings) {
            defaults.set(data, forKey: key)
        }
    }
}
