import Foundation

/// Checks .app bundles and Mach-O executables:
///  - bundle: `codesign --verify --deep --strict`, `spctl --assess --type execute`, quarantine xattr, signer
///  - Mach-O files: unsigned / ad-hoc signatures (via the Security framework)
public struct AppIntegrityEngine: ScanEngine {
    public let id = EngineID.integrity
    public let displayName = "App Integrity"

    let codesignURL: URL
    let spctlURL: URL
    let maxConcurrentBundles: Int

    public init(
        codesignURL: URL = URL(fileURLWithPath: "/usr/bin/codesign"),
        spctlURL: URL = URL(fileURLWithPath: "/usr/sbin/spctl"),
        maxConcurrentBundles: Int = 4
    ) {
        self.codesignURL = codesignURL
        self.spctlURL = spctlURL
        self.maxConcurrentBundles = max(1, maxConcurrentBundles)
    }

    public func availability() async -> EngineAvailability {
        let fm = FileManager.default
        guard fm.isExecutableFile(atPath: codesignURL.path), fm.isExecutableFile(atPath: spctlURL.path) else {
            return .notInstalled(instructions: "codesign/spctl not found. They ship with macOS; reinstall the Command Line Tools with `xcode-select --install`.")
        }
        return .available(detail: "codesign + Gatekeeper checks")
    }

    public func handles(_ item: ScanItem) -> Bool {
        item.kind == .appBundle || item.isMachO
    }

    public func scan(_ items: [ScanItem], context: ScanContext, events: @escaping EngineEventSink) async throws {
        let bundles = items.filter { $0.kind == .appBundle }
        let executables = items.filter { $0.kind == .file && $0.isMachO }

        // 1. Bundles, a few at a time (codesign --deep can be slow on large apps).
        try await withThrowingTaskGroup(of: Void.self) { group in
            var iterator = bundles.makeIterator()
            func addNext() -> Bool {
                guard let bundle = iterator.next() else { return false }
                group.addTask {
                    await events(.itemStarted(bundle.path))
                    let findings = try await checkBundle(bundle.url, context: context)
                    for f in findings { await events(.finding(f)) }
                    await events(.itemFinished(bundle.path))
                }
                return true
            }
            for _ in 0..<maxConcurrentBundles where addNext() {}
            while try await group.next() != nil {
                _ = addNext()
            }
        }

        // 2. Individual Mach-O files. Compare against the containing bundle to avoid one warning per dylib
        //    when the whole app is ad-hoc signed (that's already reported at bundle level).
        var bundleStatusCache: [String: SigningStatus] = [:]
        for item in executables {
            try Task.checkCancellation()
            await events(.itemStarted(item.path))
            let status = CodeSigning.status(of: item.url)

            var bundleStatus: SigningStatus?
            if let bundle = item.bundleURL {
                if let cached = bundleStatusCache[bundle.path] {
                    bundleStatus = cached
                } else {
                    let s = CodeSigning.status(of: bundle)
                    bundleStatusCache[bundle.path] = s
                    bundleStatus = s
                }
            }

            if let finding = Self.executableFinding(item: item, status: status, bundleStatus: bundleStatus) {
                await events(.finding(finding))
            }
            await events(.itemFinished(item.path))
        }
    }

    // MARK: - Mach-O files

    static func executableFinding(item: ScanItem, status: SigningStatus, bundleStatus: SigningStatus?) -> Finding? {
        // When the whole app is already untrusted, that's reported once at bundle level.
        if let bundleStatus, bundleStatus.isUntrusted { return nil }
        switch status {
        case .unsigned:
            return Finding(
                path: item.path, severity: .warning, engine: .integrity,
                reason: "Unsigned executable",
                detail: "This Mach-O binary has no code signature. On Apple Silicon unsigned code cannot run, so it may be tampered with or dropped by another program.",
                unitPath: item.unitPath
            )
        case .adhoc(let identifier):
            // Homebrew/MacPorts compile locally and ad-hoc sign every binary by design.
            if PersistenceScanner.isPackageManagerPath(item.path) { return nil }
            return Finding(
                path: item.path, severity: .warning, engine: .integrity,
                reason: "Ad-hoc signed executable",
                detail: "Signed without a developer identity" + (identifier.map { " (identifier: \($0))" } ?? "") + ". Common for locally built tools; unusual inside a signed app.",
                unitPath: item.unitPath
            )
        case .selfSigned(let identifier, let authority):
            return Finding(
                path: item.path, severity: .threat, engine: .integrity,
                reason: "Self-signed executable (certificate not issued by Apple)",
                detail: "Signed by “\(authority ?? "unknown")”, a certificate Apple did not issue" + (identifier.map { ", identifier \($0)" } ?? "") + ". Legitimate developers sign with Apple-issued certificates; self-signed code is typical of modified or cracked software.",
                unitPath: item.unitPath
            )
        case .signed, .unreadable:
            return nil
        }
    }

    /// Detects software that claims a well-known publisher's bundle ID but isn't signed by that publisher.
    static func impersonationProblem(bundleID: String?, status: SigningStatus) -> (Severity, String, String)? {
        guard let bundleID, let publisher = KnownPublishers.publisher(forBundleID: bundleID) else { return nil }
        if case .unreadable = status { return nil }
        if status.teamID == publisher.teamID { return nil }
        return (
            .threat,
            "Claims to be \(publisher.name) software but isn't signed by \(publisher.name)",
            "Bundle ID \(bundleID) belongs to \(publisher.name) (Team ID \(publisher.teamID)), but this copy is: \(status.description). It has been modified or repackaged by someone else. Reinstall it from \(publisher.name)'s official website."
        )
    }

    // MARK: - Bundles

    func checkBundle(_ url: URL, context: ScanContext) async throws -> [Finding] {
        let path = url.path
        var problems: [(Severity, String, String?)] = []
        var notes: [String] = []

        // Signer identity.
        let signing = CodeSigning.status(of: url)
        notes.append(signing.description)
        if case .adhoc = signing, PersistenceScanner.isPackageManagerPath(path) {
            // Homebrew/MacPorts build locally and ad-hoc sign by design; Gatekeeper never sees these.
            notes.append("Homebrew/MacPorts build: package-manager builds are ad-hoc signed by design, so Gatekeeper and strict verification don't apply.")
            return [Finding(path: path, severity: .clean, engine: .integrity, reason: "Package-manager build (ad-hoc signed by design)", detail: notes.joined(separator: "\n"), unitPath: path)]
        }
        switch signing {
        case .unsigned:
            problems.append((.warning, "App is not code signed", "Unsigned apps cannot be verified and are blocked by Gatekeeper by default."))
        case .adhoc:
            problems.append((.warning, "App is ad-hoc signed", "The app has no developer identity, so its origin cannot be verified."))
        case .selfSigned(_, let authority):
            problems.append((.threat, "App is signed with a self-signed certificate",
                             "Signed by “\(authority ?? "unknown")”, a certificate Apple did not issue. Legitimate developers sign with Apple-issued certificates. Self-signed apps are typically modified, repackaged or cracked copies — a common way malware is distributed. Reinstall the app from the developer's official website."))
        case .signed, .unreadable:
            break
        }
        let bundleID = Bundle(url: url)?.bundleIdentifier
        if let bundleID { notes.append("Bundle ID: \(bundleID)") }
        if let teamID = signing.teamID { notes.append("Team ID: \(teamID)") }
        if let impersonation = Self.impersonationProblem(bundleID: bundleID, status: signing) {
            problems.append(impersonation)
        }

        // Deep, strict signature verification.
        if signing != .unsigned {
            let r = try await ProcessRunner.run(codesignURL, ["--verify", "--deep", "--strict", path])
            if r.exitCode == 0 {
                notes.append("Signature valid (codesign --deep --strict)")
            } else {
                let message = Self.firstMeaningfulLine(r.stderr, stripping: path) ?? "codesign exit code \(r.exitCode)"
                problems.append((.warning, "Code signature invalid: \(message)", Self.explainCodesignFailure(message)))
                context.logger.warning("codesign failed for \(path): \(r.stderr)")
            }
        }

        // Gatekeeper / notarization.
        let g = try await ProcessRunner.run(spctlURL, ["--assess", "--type", "execute", "-vv", path])
        let assessment = GatekeeperAssessment.parse(exitCode: g.exitCode, output: g.stderr + g.stdout)
        if assessment.accepted {
            notes.append("Gatekeeper: accepted" + (assessment.source.map { " (\($0))" } ?? ""))
        } else {
            let why = [assessment.message, assessment.source.map { "source=\($0)" }]
                .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
            problems.append((.warning, "Gatekeeper would block this app", why.isEmpty ? "spctl rejected the app" : why))
        }

        // Quarantine attribute (informational).
        if let q = QuarantineInfo.read(path: path) {
            notes.append(q.description)
        } else {
            notes.append("No quarantine attribute")
        }

        let detail = notes.joined(separator: "\n")
        if problems.isEmpty {
            let summary = assessment.source.map { "Signed and accepted by Gatekeeper (\($0))" } ?? "Signature and Gatekeeper checks passed"
            return [Finding(path: path, severity: .clean, engine: .integrity, reason: summary, detail: detail, unitPath: path)]
        }
        return problems.map { severity, reason, extra in
            Finding(
                path: path, severity: severity, engine: .integrity,
                reason: reason,
                detail: [extra, detail].compactMap { $0 }.joined(separator: "\n"),
                unitPath: path
            )
        }
    }

    /// Plain-English explanation of common `codesign --verify --strict` failures.
    static func explainCodesignFailure(_ message: String) -> String {
        let m = message.lowercased()
        if m.contains("detritus") {
            return "Extended attributes (Finder info, resource forks) were added to files inside the app after it was signed. Usually harmless, but the app no longer matches its signature exactly. Strict mode rejects this."
        }
        if m.contains("resource envelope is obsolete") {
            return "The app uses an old code-signature format. Common for older apps and not by itself a sign of tampering."
        }
        if m.contains("sealed resource is missing or invalid") || m.contains("file added") || m.contains("file modified") {
            return "Files inside the app were changed, added or removed after it was signed. This can indicate tampering, or an app that modifies itself (updaters, plug-ins). Reinstalling from the developer usually fixes it."
        }
        if m.contains("invalid signature") || m.contains("code or signature have been modified") {
            return "The executable code no longer matches its signature. Treat this app with suspicion and reinstall it from the developer."
        }
        if m.contains("not signed at all") {
            return "Part of the app has no code signature."
        }
        return "codesign --verify --deep --strict rejected this app."
    }

    static func firstMeaningfulLine(_ text: String, stripping path: String) -> String? {
        for raw in text.split(separator: "\n") {
            var line = String(raw).trimmingCharacters(in: .whitespaces)
            if line.hasPrefix(path + ": ") { line = String(line.dropFirst(path.count + 2)) }
            if line.hasPrefix("In architecture") || line.isEmpty { continue }
            return line
        }
        return nil
    }
}
