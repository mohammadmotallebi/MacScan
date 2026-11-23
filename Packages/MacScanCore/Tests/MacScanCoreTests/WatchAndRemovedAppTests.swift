import Foundation
import Testing
@testable import MacScanCore

@Suite struct NetworkInFullCheckTests {
    func netApp(_ name: String, listening: Bool = false, internet: Bool = false, apple: Bool = false, risk: PrivacyRisk = .none) -> NetworkApp {
        NetworkApp(id: name, name: name, path: "/Applications/\(name).app", pids: [1], signer: nil, isApple: apple,
                   connections: internet ? [NetworkConnection(proto: "TCP", remoteAddress: "8.8.8.8", remotePort: "443", state: "ESTABLISHED", scope: .internet, count: 1)] : [],
                   listeners: listening ? [NetworkListener(proto: "TCP", address: "*", port: "8080", allInterfaces: true)] : [],
                   risk: risk, reasons: [])
    }

    func snapshot(_ apps: [NetworkApp]) -> NetworkSnapshot {
        NetworkSnapshot(apps: apps, takenAt: Date(), problem: nil, onlyOwnPrograms: true)
    }

    @Test func summaryCounts() {
        let s = NetworkSummary(snapshot: snapshot([
            netApp("A", internet: true), netApp("B", listening: true, risk: .warning), netApp("C", risk: .review),
        ]))
        #expect(s == NetworkSummary(programs: 3, internet: 1, openToOthers: 1, warnings: 1, review: 1))
    }

    @Test func oldFullCheckInfoDecodes() throws {
        let info = try JSONDecoder().decode(FullCheckInfo.self, from: Data(#"{"security":{"passed":1,"total":1,"problems":[]}}"#.utf8))
        #expect(info.network == nil && info.security?.passed == 1)
    }

    @Test func newListenerIsReported() throws {
        let dir = try TempDir()
        let tracker = FullCheckChangeTracker(file: dir.url.appendingPathComponent("baseline.json"))
        func session() -> ScanSession {
            var s = ScanSession(startedAt: Date(), targets: ["Applications"])
            s.status = .completed
            s.fullCheck = FullCheckInfo()
            return s
        }
        var first = session()
        tracker.apply(to: &first, checks: [], privacy: nil, network: snapshot([netApp("Old", listening: true)]))
        var second = session()
        tracker.apply(to: &second, checks: [], privacy: nil, network: snapshot([
            netApp("Old", listening: true), netApp("Server", listening: true), netApp("rapportd", listening: true, apple: true), netApp("Browser", internet: true),
        ]))
        #expect(second.fullCheck?.changes == [
            FullCheckChange(kind: .newListener, title: "Server", detail: "Now accepts connections from other computers (port 8080).", path: "/Applications/Server.app"),
        ])
        // No network this time: nothing compared, and the old list is kept.
        var third = session()
        tracker.apply(to: &third, checks: [], privacy: nil, network: nil)
        #expect(third.fullCheck?.changes == [])
    }
}

@Suite struct PermissionWatcherTests {
    func grant(_ client: String, _ permission: PrivacyPermission, decision: PrivacyDecision = .allowed) -> PrivacyGrant {
        PrivacyGrant(permission: permission, client: client, name: client, path: nil, decision: decision, detail: nil,
                     signer: nil, risk: .none, reasons: [], modified: nil, services: [])
    }

    func report(_ grants: [PrivacyGrant], readable: Bool = true) -> PrivacyReport {
        PrivacyReport(grants: grants, user: readable ? .read(1) : .noAccess, system: .read(1))
    }

    @Test func firstReadIsBaselineThenNewOnesAreReported() throws {
        let dir = try TempDir()
        let watcher = PermissionWatcher(file: dir.url.appendingPathComponent("watch.json"))
        #expect(watcher.check(report([grant("Zoom", .camera)])) == nil)
        #expect(watcher.check(report([grant("Zoom", .camera)])) == [])

        let new = try #require(watcher.check(report([
            grant("Zoom", .camera), grant("Zoom", .microphone), grant("Notes", .contacts), grant("Spy", .screenRecording, decision: .denied),
        ])))
        #expect(new.map(\.client) == ["Zoom"] && new.first?.permission == .microphone)
        #expect(PermissionWatcher.message(for: new[0]) == "Zoom can now use your microphone.")

        // An unreadable list is skipped and doesn't overwrite what was saved.
        #expect(watcher.check(report([], readable: false)) == nil)
        #expect(watcher.check(report([grant("Zoom", .camera), grant("Zoom", .microphone)])) == [])
    }
}

@Suite struct RemovedAppFinderTests {
    @Test func findsLeftoversOfAppsThatAreGone() throws {
        let dir = try TempDir()
        let lib = dir.url
        let fm = FileManager.default
        func make(_ path: String, bytes: Int = 10) throws {
            let url = lib.appendingPathComponent(path)
            try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(count: bytes).write(to: url)
        }
        // Gone, and big enough.
        try make("Application Support/com.gone.Big/data.bin", bytes: 200_000)
        try make("Preferences/com.gone.Big.plist")
        // Gone, small, but in three places.
        try make("Caches/com.gone.Small/c")
        try make("Preferences/com.gone.Small.plist")
        try make("Saved Application State/com.gone.Small.savedState/s")
        // Gone but tiny and in one place: skipped.
        try make("Preferences/com.gone.Tiny.plist")
        // Installed (directly, as a helper of an installed app, or known to macOS), Apple's, and not a bundle ID.
        try make("Application Support/com.here.App/x", bytes: 200_000)
        try make("Caches/com.here.App.helper/x", bytes: 200_000)
        try make("Caches/com.known.Elsewhere/x", bytes: 200_000)
        try make("Caches/com.apple.Safari/x", bytes: 200_000)
        try make("Application Support/Google/x", bytes: 200_000)
        try make("Caches/org.swift.swiftpm/x", bytes: 200_000)
        // A helper of a gone app joins it.
        try make("HTTPStorages/com.gone.Big.Helper/x")

        let finder = RemovedAppFinder(library: lib, installedIDs: ["com.here.App"], isInstalled: { $0 == "com.known.Elsewhere" })
        let found = finder.find()
        #expect(found.map(\.bundleID) == ["com.gone.Big", "com.gone.Small"])
        #expect(found[0].name == "Big" && found[0].paths.count == 3 && found[0].size >= 200_000)
        #expect(found[1].paths.count == 3)
    }

    @Test func bundleIDFromItemNames() {
        #expect(RemovedAppFinder.bundleID(fromItemName: "com.vendor.App.plist") == "com.vendor.App")
        #expect(RemovedAppFinder.bundleID(fromItemName: "com.vendor.App.savedState") == "com.vendor.App")
        #expect(RemovedAppFinder.bundleID(fromItemName: "Google") == nil)
        #expect(RemovedAppFinder.bundleID(fromItemName: "com.vendor") == nil)
        #expect(RemovedAppFinder.bundleID(fromItemName: "Foo.bar.baz") == nil)
    }
}
