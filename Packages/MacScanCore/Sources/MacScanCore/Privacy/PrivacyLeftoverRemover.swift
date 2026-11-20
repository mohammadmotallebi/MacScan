import Foundation

/// Removes the permission entries of an app that is no longer installed, with macOS's own `tccutil`.
///
/// `tccutil reset` refuses an app ID it can't find on the Mac. So a tiny stand-in app with that ID is
/// made in MacScan's own folder, shown to macOS, used for the reset, and deleted again.
public struct PrivacyLeftoverRemover: Sendable {
    public typealias Runner = @Sendable (_ tool: String, _ arguments: [String]) async -> PostureCommandOutput?

    public enum RemoveError: Error, LocalizedError, Equatable {
        case notALeftover
        case appIsInstalled(String)
        case failed(String)

        public var errorDescription: String? {
            switch self {
            case .notALeftover: "MacScan only removes permissions of apps that are no longer installed."
            case .appIsInstalled(let path): "The app is installed at \(path), so its permission was left alone."
            case .failed(let why): why
            }
        }
    }

    static let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

    var workFolder: URL
    var run: Runner
    var resolveApp: PrivacyAudit.AppResolver

    /// The stand-in must not be in a temporary folder: macOS ignores apps there.
    public init(workFolder: URL = AppPaths.applicationSupport.appendingPathComponent("PermissionCleanup", isDirectory: true),
                run: @escaping Runner = SecurityPosture.systemRunner,
                resolveApp: @escaping PrivacyAudit.AppResolver = PrivacyAudit.systemResolver) {
        self.workFolder = workFolder
        self.run = run
        self.resolveApp = resolveApp
    }

    /// Letters, digits, dots, dashes and underscores, like "com.example.App".
    public static func isAppID(_ text: String) -> Bool {
        guard let first = text.unicodeScalars.first, CharacterSet.alphanumerics.contains(first), text.count <= 255 else { return false }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        return text.unicodeScalars.allSatisfy(allowed.contains)
    }

    public func remove(_ grant: PrivacyGrant) async throws {
        guard grant.canRemove, !grant.services.isEmpty else { throw RemoveError.notALeftover }
        // Check again now: the app may have been installed since the list was read.
        if let app = resolveApp(grant.client) { throw RemoveError.appIsInstalled(app.path) }

        let fm = FileManager.default
        let folder = workFolder.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let app = folder.appendingPathComponent("Removed App.app", isDirectory: true)
        do {
            try fm.createDirectory(at: app.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
            let info: [String: Any] = [
                "CFBundleIdentifier": grant.client, "CFBundleName": "Removed App",
                "CFBundleExecutable": "stand-in", "CFBundlePackageType": "APPL",
            ]
            try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
                .write(to: app.appendingPathComponent("Contents/Info.plist"))
            try fm.copyItem(atPath: "/usr/bin/true", toPath: app.appendingPathComponent("Contents/MacOS/stand-in").path)
        } catch {
            try? fm.removeItem(at: folder)
            throw RemoveError.failed("Couldn't prepare the removal: \(error.localizedDescription)")
        }

        _ = await run("/usr/bin/codesign", ["--force", "--sign", "-", app.path])
        _ = await run(Self.lsregister, ["-f", app.path])
        var failures: [String] = []
        for service in grant.services {
            let name = service.hasPrefix("kTCCService") ? String(service.dropFirst("kTCCService".count)) : service
            var result = await run("/usr/bin/tccutil", ["reset", name, grant.client])
            if result?.exitCode != 0 {
                // macOS may need a moment to notice the stand-in.
                try? await Task.sleep(for: .seconds(1))
                result = await run("/usr/bin/tccutil", ["reset", name, grant.client])
            }
            if result?.exitCode != 0 {
                failures.append(result?.text.trimmingCharacters(in: .whitespacesAndNewlines) ?? "tccutil couldn't be run")
            }
        }
        _ = await run(Self.lsregister, ["-u", app.path])
        try? fm.removeItem(at: folder)
        if (try? fm.contentsOfDirectory(atPath: workFolder.path))?.isEmpty == true { try? fm.removeItem(at: workFolder) }

        if !failures.isEmpty { throw RemoveError.failed(failures.joined(separator: "\n")) }
    }
}
