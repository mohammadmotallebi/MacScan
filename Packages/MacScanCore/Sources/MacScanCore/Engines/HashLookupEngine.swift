import Foundation

public struct VirusTotalVerdict: Equatable, Sendable {
    public var found: Bool
    public var malicious = 0
    public var suspicious = 0
    public var harmless = 0
    public var undetected = 0
    public var name: String?

    public var totalEngines: Int { malicious + suspicious + harmless + undetected }
}

public enum VirusTotalError: Error, LocalizedError, Equatable {
    case noAPIKey
    case invalidAPIKey
    case quotaExceeded
    case http(Int)
    case badResponse

    public var errorDescription: String? {
        switch self {
        case .noAPIKey: "No VirusTotal API key. Add your own key in Settings › VirusTotal."
        case .invalidAPIKey: "VirusTotal rejected the API key."
        case .quotaExceeded: "VirusTotal quota exceeded (free keys allow 4 lookups/minute and 500/day). Try again later."
        case .http(let code): "VirusTotal returned HTTP \(code)."
        case .badResponse: "Unexpected response from VirusTotal."
        }
    }
}

/// Spaces requests to respect the free-tier rate limit (4 requests/minute → one every 15 s).
public actor RateLimiter {
    public static let virusTotal = RateLimiter(interval: .seconds(15))

    let interval: Duration
    private var next: ContinuousClock.Instant?

    public init(interval: Duration) {
        self.interval = interval
    }

    public func waitForSlot() async throws {
        let now = ContinuousClock.now
        let slot = max(now, next ?? now)
        next = slot + interval
        if slot > now { try await Task.sleep(until: slot, clock: .continuous) }
    }
}

/// Looks up SHA-256 hashes with the VirusTotal v3 API. Only hashes are sent; files are never uploaded.
public struct VirusTotalClient: Sendable {
    let apiKey: String
    let session: URLSession
    let baseURL: URL
    let limiter: RateLimiter

    public init(
        apiKey: String,
        session: URLSession = .shared,
        baseURL: URL = URL(string: "https://www.virustotal.com/api/v3/")!,
        limiter: RateLimiter = .virusTotal
    ) {
        self.apiKey = apiKey
        self.session = session
        self.baseURL = baseURL
        self.limiter = limiter
    }

    public func lookup(sha256: String) async throws -> VirusTotalVerdict {
        guard !apiKey.isEmpty else { throw VirusTotalError.noAPIKey }
        guard sha256.count == 64, sha256.allSatisfy(\.isHexDigit) else { throw VirusTotalError.badResponse }

        var request = URLRequest(url: baseURL.appendingPathComponent("files/\(sha256.lowercased())"))
        request.httpMethod = "GET"
        request.setValue(apiKey, forHTTPHeaderField: "x-apikey")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 30

        try await limiter.waitForSlot()
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw VirusTotalError.badResponse }
        switch http.statusCode {
        case 200: return try Self.parse(data)
        case 404: return VirusTotalVerdict(found: false)
        case 401, 403: throw VirusTotalError.invalidAPIKey
        case 429: throw VirusTotalError.quotaExceeded
        default: throw VirusTotalError.http(http.statusCode)
        }
    }

    static func parse(_ data: Data) throws -> VirusTotalVerdict {
        struct Envelope: Decodable {
            struct DataObj: Decodable {
                struct Attributes: Decodable {
                    struct Stats: Decodable {
                        var malicious: Int?
                        var suspicious: Int?
                        var harmless: Int?
                        var undetected: Int?
                    }
                    var last_analysis_stats: Stats?
                    var meaningful_name: String?
                }
                var attributes: Attributes
            }
            var data: DataObj
        }
        guard let env = try? JSONDecoder().decode(Envelope.self, from: data) else { throw VirusTotalError.badResponse }
        let s = env.data.attributes.last_analysis_stats
        return VirusTotalVerdict(
            found: true,
            malicious: s?.malicious ?? 0,
            suspicious: s?.suspicious ?? 0,
            harmless: s?.harmless ?? 0,
            undetected: s?.undetected ?? 0,
            name: env.data.attributes.meaningful_name
        )
    }
}

/// Optional engine: hashes files and looks them up on VirusTotal. Runs only when the user has entered
/// their own API key, and only on flagged items (automatic) or on demand (per result).
public struct HashLookupEngine: ScanEngine {
    public let id = EngineID.virustotal
    public let displayName = "VirusTotal"

    let client: VirusTotalClient?

    public init(client: VirusTotalClient?) {
        self.client = client
    }

    public func availability() async -> EngineAvailability {
        client == nil ? .needsSetup("Add your own VirusTotal API key in Settings to enable hash lookups.") : .available(detail: "Hash lookups (no uploads)")
    }

    public func handles(_ item: ScanItem) -> Bool { true }

    public func scan(_ items: [ScanItem], context: ScanContext, events: @escaping EngineEventSink) async throws {
        guard client != nil else { throw VirusTotalError.noAPIKey }
        for item in items {
            try Task.checkCancellation()
            await events(.itemStarted(item.path))
            do {
                await events(.finding(try await lookup(path: item.path, unitPath: item.unitPath)))
            } catch VirusTotalError.quotaExceeded {
                await events(.note(VirusTotalError.quotaExceeded.errorDescription ?? ""))
                return
            } catch let error as VirusTotalError {
                throw error
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                context.logger.warning("VirusTotal lookup failed for \(item.path): \(error.localizedDescription)")
                await events(.note("VirusTotal lookup failed for \(item.url.lastPathComponent): \(error.localizedDescription)"))
            }
            await events(.itemFinished(item.path))
        }
    }

    /// Hashes `path` (main executable for bundles) and returns a finding describing the verdict.
    public func lookup(path: String, unitPath: String? = nil) async throws -> Finding {
        guard let client else { throw VirusTotalError.noAPIKey }
        guard let target = FileHasher.hashTarget(for: URL(fileURLWithPath: path)) else {
            throw EngineError.failed("Cannot hash \(path)")
        }
        let hash = try FileHasher.sha256(of: target)
        let verdict = try await client.lookup(sha256: hash)
        return Self.finding(path: path, unitPath: unitPath, sha256: hash, verdict: verdict)
    }

    static func finding(path: String, unitPath: String?, sha256: String, verdict: VirusTotalVerdict) -> Finding {
        let link = "https://www.virustotal.com/gui/file/\(sha256)"
        guard verdict.found else {
            return Finding(
                path: path, severity: .clean, engine: .virustotal,
                reason: "Unknown to VirusTotal (hash not found)",
                detail: "No file with this SHA-256 has been submitted to VirusTotal. That is normal for private or rare files.\n\(link)",
                sha256: sha256, unitPath: unitPath
            )
        }
        let ratio = "\(verdict.malicious)/\(verdict.totalEngines)"
        let severity: Severity
        let reason: String
        if verdict.malicious >= 3 {
            severity = .threat
            reason = "VirusTotal: \(ratio) engines flag this file as malicious"
        } else if verdict.malicious > 0 || verdict.suspicious > 0 {
            severity = .warning
            reason = "VirusTotal: \(verdict.malicious) malicious, \(verdict.suspicious) suspicious detections"
        } else {
            severity = .clean
            reason = "VirusTotal: 0/\(verdict.totalEngines) detections"
        }
        var detail = "Malicious: \(verdict.malicious) · Suspicious: \(verdict.suspicious) · Harmless: \(verdict.harmless) · Undetected: \(verdict.undetected)"
        if let name = verdict.name { detail += "\nKnown as: \(name)" }
        detail += "\n\(link)"
        return Finding(path: path, severity: severity, engine: .virustotal, reason: reason, detail: detail, sha256: sha256, unitPath: unitPath)
    }
}
