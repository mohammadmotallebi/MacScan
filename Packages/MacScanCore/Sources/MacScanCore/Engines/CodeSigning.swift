import Foundation
import Security

/// Code-signing status of a file or bundle, read with the Security framework (fast, no subprocess).
public enum SigningStatus: Equatable, Sendable {
    case unsigned
    case adhoc(identifier: String?)
    /// Signed with a certificate that does not chain to Apple (typical of re-signed / cracked software).
    case selfSigned(identifier: String?, authority: String?)
    /// Signed with an Apple-issued certificate (Apple, Developer ID, App Store, Apple Development…).
    case signed(identifier: String?, teamID: String?, authority: String?)
    case unreadable(String)

    public var isUnsignedOrAdhoc: Bool {
        switch self {
        case .unsigned, .adhoc: true
        default: false
        }
    }

    /// No identity Apple vouches for: unsigned, ad-hoc or self-signed.
    public var isUntrusted: Bool {
        switch self {
        case .unsigned, .adhoc, .selfSigned: true
        default: false
        }
    }

    public var teamID: String? {
        if case .signed(_, let team, _) = self { return team }
        return nil
    }

    public var description: String {
        switch self {
        case .unsigned:
            "Not code signed"
        case .adhoc(let id):
            "Ad-hoc signed" + (id.map { " (\($0))" } ?? "")
        case .selfSigned(_, let authority):
            "Self-signed by “\(authority ?? "unknown")” (certificate not issued by Apple)"
        case .signed(_, let team, let authority):
            "Signed by \(authority ?? "unknown authority")" + (team.map { " · Team \($0)" } ?? "")
        case .unreadable(let why):
            "Signature unreadable: \(why)"
        }
    }
}

public enum CodeSigning {
    public static func status(of url: URL) -> SigningStatus {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return .unreadable(message(for: createStatus))
        }

        var infoRef: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef)
        if infoStatus == errSecCSUnsigned { return .unsigned }
        guard infoStatus == errSecSuccess, let info = infoRef as? [String: Any] else {
            return .unreadable(message(for: infoStatus))
        }

        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        // Unsigned code yields a dictionary without an identifier.
        guard identifier != nil || info[kSecCodeInfoFlags as String] != nil else { return .unsigned }

        let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let certificates = info[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? []
        if flags & SecCodeSignatureFlags.adhoc.rawValue != 0 || certificates.isEmpty {
            return .adhoc(identifier: identifier)
        }
        let authority = certificates.first.flatMap { SecCertificateCopySubjectSummary($0) as String? }
        if !chainsToApple(code) {
            return .selfSigned(identifier: identifier, authority: authority)
        }
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String
        return .signed(identifier: identifier, teamID: team, authority: authority)
    }

    /// True if the signing certificate chains to an Apple root ("anchor apple generic").
    /// Uses basic validation only (signature + requirement), so it doesn't hash the whole binary.
    static func chainsToApple(_ code: SecStaticCode) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return true }
        let flags = SecCSFlags(rawValue: kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources)
        let status = SecStaticCodeCheckValidity(code, flags, requirement)
        // Only a failed requirement means "not Apple-issued"; other errors (e.g. broken seal) are reported elsewhere.
        return status != errSecCSReqFailed
    }

    static func message(for status: OSStatus) -> String {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
    }
}

/// Bundle-ID prefixes of well-known publishers and the Apple Team ID that signs their software.
/// Every entry was verified against genuinely installed apps. Keep this list conservative:
/// a wrong entry produces a false "impersonation" threat.
public enum KnownPublishers {
    public struct Publisher: Sendable, Equatable {
        public let name: String
        public let teamID: String
    }

    static let table: [(prefix: String, publisher: Publisher)] = [
        ("com.google.", Publisher(name: "Google", teamID: "EQHXZ8M8AV")),
        ("com.microsoft.", Publisher(name: "Microsoft", teamID: "UBF8T346G9")),
        ("us.zoom.", Publisher(name: "Zoom", teamID: "BJ4HAAB9B3")),
        ("com.tinyspeck.", Publisher(name: "Slack", teamID: "BQR82RBBHL")),
        ("com.docker.", Publisher(name: "Docker", teamID: "9BNSXJN65R")),
        ("net.whatsapp.", Publisher(name: "WhatsApp", teamID: "57T9237FN3")),
        ("ru.keepcoder.", Publisher(name: "Telegram", teamID: "6N38VWS5BX")),
        ("com.openai.", Publisher(name: "OpenAI", teamID: "2DC432GLL2")),
        ("com.valvesoftware.", Publisher(name: "Valve", teamID: "MXGJJ98X76")),
        ("org.videolan.", Publisher(name: "VideoLAN", teamID: "75GAHG3SZQ")),
    ]

    public static func publisher(forBundleID bundleID: String) -> Publisher? {
        let lower = bundleID.lowercased()
        return table.first { lower.hasPrefix($0.prefix) }?.publisher
    }

}

/// Parsed `com.apple.quarantine` extended attribute.
public struct QuarantineInfo: Equatable, Sendable {
    public let flags: UInt32
    public let date: Date?
    public let agent: String?

    /// QTN_FLAG_USER_APPROVED: the user has approved opening the item in Gatekeeper.
    public var userApproved: Bool { flags & 0x0040 != 0 }

    public var description: String {
        var parts = ["Quarantined"]
        var origin: [String] = []
        if let agent, !agent.isEmpty { origin.append("downloaded by \(agent)") }
        if let date {
            origin.append("on " + date.formatted(date: .abbreviated, time: .shortened))
        }
        if !origin.isEmpty { parts.append("(" + origin.joined(separator: " ") + ")") }
        parts.append(userApproved ? "· opened/approved by user" : "· not yet approved by user")
        return parts.joined(separator: " ")
    }

    /// Parses "flags;hex-timestamp;agent;uuid".
    public static func parse(_ raw: String) -> QuarantineInfo? {
        let fields = raw.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        guard let first = fields.first, let flags = UInt32(first, radix: 16) else { return nil }
        let date = fields.count > 1 ? UInt64(fields[1], radix: 16).map { Date(timeIntervalSince1970: TimeInterval($0)) } : nil
        let agent = fields.count > 2 ? fields[2] : nil
        return QuarantineInfo(flags: flags, date: date, agent: agent)
    }

    public static func read(path: String) -> QuarantineInfo? {
        let name = "com.apple.quarantine"
        let size = getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        let read = getxattr(path, name, &buffer, size, 0, XATTR_NOFOLLOW)
        guard read > 0 else { return nil }
        return parse(String(decoding: buffer.prefix(read), as: UTF8.self))
    }
}

/// Result of `spctl --assess`.
public struct GatekeeperAssessment: Equatable, Sendable {
    public let accepted: Bool
    public let source: String?
    public let message: String

    /// Parses spctl's stderr, e.g. "/Applications/X.app: accepted\nsource=Notarized Developer ID\norigin=…".
    public static func parse(exitCode: Int32, output: String) -> GatekeeperAssessment {
        var source: String?
        var message = ""
        for line in output.split(separator: "\n").map(String.init) {
            if line.hasPrefix("source=") {
                source = String(line.dropFirst("source=".count))
            } else if let r = line.range(of: ": ", options: .backwards), message.isEmpty {
                message = String(line[r.upperBound...])
            }
        }
        return GatekeeperAssessment(accepted: exitCode == 0, source: source, message: message)
    }
}
