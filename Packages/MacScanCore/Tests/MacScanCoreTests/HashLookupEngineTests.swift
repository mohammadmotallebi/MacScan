import Foundation
import Testing
@testable import MacScanCore

/// Serves canned VirusTotal responses. Never touches the network.
final class MockVTProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: (@Sendable (URLRequest) -> (Int, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        let (status, data) = Self.handler?(request) ?? (500, Data())
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
}

@Suite(.serialized) struct HashLookupEngineTests {
    func makeClient(key: String = "test-key") -> VirusTotalClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockVTProtocol.self]
        return VirusTotalClient(apiKey: key, session: URLSession(configuration: config), limiter: RateLimiter(interval: .zero))
    }

    static func vtJSON(malicious: Int, suspicious: Int = 0, undetected: Int = 60) -> Data {
        Data("""
        {"data":{"attributes":{"meaningful_name":"sample.bin","last_analysis_stats":{"malicious":\(malicious),"suspicious":\(suspicious),"harmless":0,"undetected":\(undetected)}}}}
        """.utf8)
    }

    @Test func sha256KnownVector() throws {
        #expect(FileHasher.sha256(of: Data("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        let dir = try TempDir()
        let f = try dir.write("abc.txt", "abc")
        #expect(try FileHasher.sha256(of: f) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test func bundleFingerprintUsesMainExecutable() throws {
        let dir = try TempDir()
        let app = try dir.makeApp("Hashy")
        let exeHash = try FileHasher.sha256(of: app.appendingPathComponent("Contents/MacOS/Hashy"))
        #expect(FileHasher.fingerprint(for: app.path) == exeHash)
    }

    @Test func maliciousHashIsThreatAndSendsOnlyTheHash() async throws {
        let dir = try TempDir()
        let f = try dir.write("bad.bin", "pretend malware")
        let expectedHash = try FileHasher.sha256(of: f)
        let seen = RequestLog()
        MockVTProtocol.handler = { req in
            seen.append(req)
            return (200, Self.vtJSON(malicious: 40))
        }
        let finding = try await HashLookupEngine(client: makeClient()).lookup(path: f.path)
        #expect(finding.severity == .threat)
        #expect(finding.sha256 == expectedHash)
        #expect(finding.reason.contains("40/100"))

        let req = try #require(seen.requests.first)
        #expect(req.httpMethod == "GET")
        #expect(req.url?.path == "/api/v3/files/\(expectedHash)")
        #expect(req.value(forHTTPHeaderField: "x-apikey") == "test-key")
        #expect(req.httpBody == nil && req.httpBodyStream == nil, "files must never be uploaded")
    }

    @Test func fewDetectionsIsWarningZeroIsClean() async throws {
        let dir = try TempDir()
        let f = try dir.write("x.bin", "x")
        MockVTProtocol.handler = { _ in (200, Self.vtJSON(malicious: 1)) }
        #expect(try await HashLookupEngine(client: makeClient()).lookup(path: f.path).severity == .warning)
        MockVTProtocol.handler = { _ in (200, Self.vtJSON(malicious: 0)) }
        #expect(try await HashLookupEngine(client: makeClient()).lookup(path: f.path).severity == .clean)
    }

    @Test func notFoundIsCleanUnknown() async throws {
        let dir = try TempDir()
        let f = try dir.write("x.bin", "unique \(UUID())")
        MockVTProtocol.handler = { _ in (404, Data(#"{"error":{"code":"NotFoundError"}}"#.utf8)) }
        let finding = try await HashLookupEngine(client: makeClient()).lookup(path: f.path)
        #expect(finding.severity == .clean)
        #expect(finding.reason.contains("Unknown"))
    }

    @Test func badKeyAndQuotaErrors() async throws {
        let client = makeClient()
        let hash = String(repeating: "a", count: 64)
        MockVTProtocol.handler = { _ in (401, Data()) }
        await #expect(throws: VirusTotalError.invalidAPIKey) { try await client.lookup(sha256: hash) }
        MockVTProtocol.handler = { _ in (429, Data()) }
        await #expect(throws: VirusTotalError.quotaExceeded) { try await client.lookup(sha256: hash) }
    }

    @Test func noKeyMeansNeedsSetup() async {
        let engine = HashLookupEngine(client: nil)
        guard case .needsSetup = await engine.availability() else {
            Issue.record("expected needsSetup"); return
        }
    }

    @Test func rateLimiterSpacesRequests() async throws {
        let limiter = RateLimiter(interval: .milliseconds(200))
        let start = ContinuousClock.now
        try await limiter.waitForSlot()
        try await limiter.waitForSlot()
        try await limiter.waitForSlot()
        #expect(ContinuousClock.now - start >= .milliseconds(380))
    }
}

final class RequestLog: @unchecked Sendable {
    private let lock = NSLock()
    private var _requests: [URLRequest] = []
    func append(_ r: URLRequest) { lock.withLock { _requests.append(r) } }
    var requests: [URLRequest] { lock.withLock { _requests } }
}
