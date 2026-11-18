import CryptoKit
import Foundation

public enum FileHasher {
    /// Streams the file through SHA-256 in 1 MB chunks.
    public static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// The file that represents a path for hashing: the main executable for bundles, the file itself otherwise.
    public static func hashTarget(for url: URL) -> URL? {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else { return nil }
        if isDir.boolValue {
            return Bundle(url: url)?.executableURL
        }
        return url
    }

    /// SHA-256 used to fingerprint a finding (file hash, or main-executable hash for bundles).
    public static func fingerprint(for path: String) -> String? {
        guard let target = hashTarget(for: URL(fileURLWithPath: path)) else { return nil }
        return try? sha256(of: target)
    }
}
