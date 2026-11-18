import Foundation
@testable import MacScanCore

/// A throwaway directory that is deleted when the helper is deallocated.
final class TempDir {
    let url: URL

    init() throws {
        let raw = FileManager.default.temporaryDirectory
            .appendingPathComponent("MacScanTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
        url = Paths.canonical(raw)
    }

    deinit {
        try? FileManager.default.removeItem(at: url)
    }

    @discardableResult
    func write(_ relative: String, _ contents: String) throws -> URL {
        try write(relative, Data(contents.utf8))
    }

    @discardableResult
    func write(_ relative: String, _ data: Data) throws -> URL {
        let file = url.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: file)
        return file
    }

    @discardableResult
    func copy(_ source: String, to relative: String) throws -> URL {
        let dest = url.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: source, toPath: dest.path)
        return dest
    }

    /// Creates a minimal .app bundle whose main executable is a copy of /usr/bin/true.
    @discardableResult
    func makeApp(_ name: String) throws -> URL {
        let app = url.appendingPathComponent("\(name).app")
        let macos = app.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: macos.appendingPathComponent(name).path)
        let plist: [String: Any] = [
            "CFBundleExecutable": name,
            "CFBundleIdentifier": "com.example.macscan.test.\(name)",
            "CFBundleName": name,
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1",
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: app.appendingPathComponent("Contents/Info.plist"))
        try "readme".write(to: app.appendingPathComponent("Contents/Resources/readme.txt"), createDirs: true)
        return app
    }
}

extension String {
    func write(to url: URL, createDirs: Bool) throws {
        if createDirs {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        }
        try write(to: url, atomically: true, encoding: .utf8)
    }
}

/// Runs a command synchronously in tests (for codesign setup etc.).
@discardableResult
func shell(_ launchPath: String, _ args: [String]) throws -> Int32 {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: launchPath)
    p.arguments = args
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    try p.run()
    p.waitUntilExit()
    return p.terminationStatus
}

/// The EICAR antivirus test string, assembled at runtime so this source file itself isn't flagged by scanners.
enum EICAR {
    static var string: String {
        let parts = [
            #"X5O!P%@AP[4\PZX54(P^)7CC)7}$"#,
            "EICAR-STANDARD-ANTIVIRUS",
            "-TEST-FILE!$H+H*",
        ]
        return parts.joined()
    }
}

actor EventRecorder {
    var findings: [Finding] = []
    var finished: [String] = []
    var notes: [String] = []

    func record(_ event: EngineEvent) {
        switch event {
        case .finding(let f): findings.append(f)
        case .itemFinished(let p): finished.append(p)
        case .note(let n): notes.append(n)
        case .itemStarted: break
        }
    }

    nonisolated var sink: EngineEventSink {
        { event in await self.record(event) }
    }
}

extension ScanContext {
    /// Context whose logger writes to a temp directory, so tests never touch ~/Library/Logs/MacScan.
    static var test: ScanContext {
        ScanContext(settings: ScanSettings(), logger: FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs")))
    }
}

/// Creates a throwaway self-signed code-signing identity in a private keychain inside `dir`
/// (never added to the user's keychain search list). Returns a closure that signs a path, or nil if unavailable.
func makeSelfSignedSigner(in dir: TempDir) -> ((URL) throws -> Int32)? {
    let d = dir.url.appendingPathComponent("selfsign")
    try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
    let keychain = d.appendingPathComponent("test.keychain-db").path
    let cnf = """
    [req]
    distinguished_name=dn
    x509_extensions=ext
    prompt=no
    [dn]
    CN=MacScan Test Self-Signed
    [ext]
    keyUsage=critical,digitalSignature
    extendedKeyUsage=critical,codeSigning
    basicConstraints=critical,CA:false
    """
    do {
        try cnf.write(to: d.appendingPathComponent("cert.cnf"), atomically: true, encoding: .utf8)
        let p = { (name: String) in d.appendingPathComponent(name).path }
        guard try shell("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", p("key.pem"), "-out", p("cert.pem"), "-days", "2", "-config", p("cert.cnf")]) == 0 else { return nil }
        if try shell("/usr/bin/openssl", ["pkcs12", "-export", "-legacy", "-inkey", p("key.pem"), "-in", p("cert.pem"), "-out", p("id.p12"), "-passout", "pass:test"]) != 0 {
            guard try shell("/usr/bin/openssl", ["pkcs12", "-export", "-inkey", p("key.pem"), "-in", p("cert.pem"), "-out", p("id.p12"), "-passout", "pass:test"]) == 0 else { return nil }
        }
        guard try shell("/usr/bin/security", ["create-keychain", "-p", "test", keychain]) == 0,
              try shell("/usr/bin/security", ["unlock-keychain", "-p", "test", keychain]) == 0,
              try shell("/usr/bin/security", ["import", p("id.p12"), "-k", keychain, "-P", "test", "-T", "/usr/bin/codesign"]) == 0
        else { return nil }
        _ = try shell("/usr/bin/security", ["set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", "test", keychain])
    } catch {
        return nil
    }
    return { target in
        try shell("/usr/bin/codesign", ["--force", "--deep", "--keychain", keychain, "--sign", "MacScan Test Self-Signed", target.path])
    }
}
