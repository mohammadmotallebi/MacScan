import Foundation

public enum ExternalTool: String, CaseIterable, Sendable {
    case clamscan
    case freshclam
    case yara
    case yarac
}

/// Finds command-line tools. GUI apps don't inherit the shell PATH, so we check Homebrew locations explicitly.
public enum ToolLocator {
    public static let searchDirectories = [
        "/opt/homebrew/bin",   // Homebrew on Apple Silicon
        "/usr/local/bin",      // Homebrew on Intel / manual installs
        "/opt/local/bin",      // MacPorts
    ]

    /// Returns the tool URL: the override if set (and executable), otherwise the first auto-detected match.
    public static func locate(_ tool: ExternalTool, override: String?) -> URL? {
        if let override = override?.trimmingCharacters(in: .whitespaces), !override.isEmpty {
            let path = (override as NSString).expandingTildeInPath
            return FileManager.default.isExecutableFile(atPath: path) ? URL(fileURLWithPath: path) : nil
        }
        return autodetect(tool).map { URL(fileURLWithPath: $0) }
    }

    public static func autodetect(_ tool: ExternalTool) -> String? {
        for dir in searchDirectories {
            let path = dir + "/" + tool.rawValue
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        return nil
    }
}
