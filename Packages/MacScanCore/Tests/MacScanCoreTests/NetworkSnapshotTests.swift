import Foundation
import Testing
@testable import MacScanCore

@Suite struct NetworkSnapshotTests {
    /// lsof -F output for one process with the given sockets ("P|n|state").
    func lsof(_ pid: Int32, _ command: String, _ sockets: [(String, String, String?)]) -> String {
        var lines = ["p\(pid)", "c\(command)", "u501"]
        for (index, socket) in sockets.enumerated() {
            lines += ["f\(index + 3)", "tIPv4", "P\(socket.0)", "n\(socket.1)"]
            if let state = socket.2 { lines += ["TST=\(state)", "TQR=0", "TQS=0"] }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static let good = SigningStatus.signed(identifier: "com.good", teamID: "TEAM123456", authority: "Developer ID Application: Good")
    static let apple = SigningStatus.signed(identifier: "com.apple.controlcenter", teamID: nil, authority: "Software Signing")

    func scanner(_ output: String, processes: [LiveProcess], signing: [String: SigningStatus], home: String = "/Users/test") -> NetworkScanner {
        NetworkScanner(runLsof: { PostureCommandOutput(exitCode: 0, text: output) },
                       processes: FakeProcessList(processes: processes),
                       signing: { signing[$0.path] ?? .unsigned },
                       home: URL(fileURLWithPath: home))
    }

    @Test func parsesLsofOutput() {
        let text = lsof(10, "nginx", [("TCP", "127.0.0.1:80", "LISTEN"), ("TCP", "*:5000", "LISTEN")])
            + lsof(11, "Notes", [("TCP", "192.168.0.129:52193->67.195.228.147:993", "ESTABLISHED"),
                                 ("TCP", "[fe80:17::3fc2%en0]:1025->[fe80:17::9114]:1028", "ESTABLISHED")])
            + lsof(12, "mDNS", [("UDP", "*:5353", nil), ("UDP", "*:*", nil), ("UDP", "10.0.0.2:5000->8.8.8.8:53", nil)])
        let sockets = NetworkSocket.parse(lsof: text)
        #expect(sockets.count == 7)
        #expect(sockets[0] == NetworkSocket(pid: 10, command: "nginx", uid: 501, proto: "TCP", localAddress: "127.0.0.1", localPort: "80", state: "LISTEN"))
        #expect(sockets[0].isListening && !sockets[0].onAllInterfaces)
        #expect(sockets[1].onAllInterfaces)
        #expect(sockets[2].remoteAddress == "67.195.228.147" && sockets[2].remotePort == "993" && !sockets[2].isListening)
        #expect(sockets[3].localAddress == "fe80:17::3fc2" && sockets[3].remoteAddress == "fe80:17::9114")
        #expect(sockets[4].isListening && sockets[4].proto == "UDP")
        #expect(!sockets[5].isListening)
        #expect(sockets[6].remotePort == "53" && sockets[6].state == nil)
    }

    @Test func scopes() {
        #expect(NetworkScope.of("127.0.0.1") == .thisMac)
        #expect(NetworkScope.of("::1") == .thisMac)
        #expect(NetworkScope.of("192.168.1.4") == .localNetwork)
        #expect(NetworkScope.of("172.20.0.1") == .localNetwork)
        #expect(NetworkScope.of("172.32.0.1") == .internet)
        #expect(NetworkScope.of("100.100.1.1") == .localNetwork)
        #expect(NetworkScope.of("fe80::1") == .localNetwork)
        #expect(NetworkScope.of("fd7a::1") == .localNetwork)
        #expect(NetworkScope.of("::ffff:10.0.0.1") == .localNetwork)
        #expect(NetworkScope.of("2607:f8b0::1") == .internet)
        #expect(NetworkScope.of("8.8.8.8") == .internet)
    }

    @Test func groupsAndFlags() async {
        let text =
            // A signed app with two helper processes, one closed connection, one listener on all interfaces.
            lsof(1, "Good", [("TCP", "10.0.0.2:5000->1.2.3.4:443", "ESTABLISHED"), ("TCP", "10.0.0.2:5001->1.2.3.4:443", "CLOSE_WAIT"), ("UDP", "*:5353", nil)])
            + lsof(2, "Good Helper", [("TCP", "10.0.0.2:5002->5.6.7.8:443", "ESTABLISHED"), ("TCP", "*:7777", "LISTEN")])
            // Unsigned tool in Downloads talking out.
            + lsof(3, "tool", [("TCP", "10.0.0.2:6000->9.9.9.9:4444", "ESTABLISHED")])
            // Ad-hoc Homebrew server on localhost only: fine.
            + lsof(4, "redis-server", [("TCP", "[::1]:6379", "LISTEN")])
            // Unsigned program that only talks to this Mac: listed, not flagged.
            + lsof(5, "localonly", [("TCP", "127.0.0.1:7000->127.0.0.1:7001", "ESTABLISHED")])
            // Apple's own, listening everywhere: listed, not flagged.
            + lsof(6, "ControlCenter", [("TCP", "*:5000", "LISTEN")])
            // A process MacScan can't find.
            + lsof(7, "ghost", [("TCP", "10.0.0.2:6001->9.9.9.9:443", "ESTABLISHED")])
            // Only closed sockets: left out.
            + lsof(8, "closed", [("TCP", "10.0.0.2:6002->9.9.9.9:443", "TIME_WAIT")])
        let processes = [
            LiveProcess(pid: 1, uid: 501, name: "Good", path: "/Applications/Good.app/Contents/MacOS/Good"),
            LiveProcess(pid: 2, uid: 501, name: "Good Helper", path: "/Applications/Good.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"),
            LiveProcess(pid: 3, uid: 501, name: "tool", path: "/Users/test/Downloads/tool"),
            LiveProcess(pid: 4, uid: 501, name: "redis-server", path: "/opt/homebrew/bin/redis-server"),
            LiveProcess(pid: 5, uid: 501, name: "localonly", path: "/usr/local/bin/localonly"),
            LiveProcess(pid: 6, uid: 501, name: "ControlCenter", path: "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"),
            LiveProcess(pid: 8, uid: 501, name: "closed", path: "/usr/local/bin/closed"),
        ]
        let snapshot = await scanner(text, processes: processes, signing: [
            "/Applications/Good.app": Self.good,
            "/opt/homebrew/bin/redis-server": .adhoc(identifier: "redis"),
            "/System/Library/CoreServices/ControlCenter.app": Self.apple,
        ]).run()

        #expect(snapshot.problem == nil)
        #expect(snapshot.apps.map(\.name) == ["tool", "ghost", "Good", "localonly", "redis-server", "ControlCenter"])
        func app(_ name: String) -> NetworkApp? { snapshot.apps.first { $0.name == name } }

        let good = app("Good")!
        #expect(good.pids == [1, 2] && good.path == "/Applications/Good.app")
        #expect(good.connections.map(\.remoteAddress) == ["5.6.7.8", "1.2.3.4"])
        #expect(good.listeners.map(\.port) == ["5353", "7777"])
        #expect(good.risk == .review)
        #expect(good.reasons == ["Accepts connections from other computers on port 7777. Fine if you share something on purpose."])

        let tool = app("tool")!
        #expect(tool.risk == .warning)
        #expect(tool.reasons.count == 3)
        #expect(tool.reasons[0].hasPrefix("It isn't signed"))
        #expect(tool.reasons[1] == "It runs from the Downloads folder.")
        #expect(tool.reasons[2].contains("4444"))

        #expect(app("ghost")?.risk == .review && app("ghost")?.path == nil)
        #expect(app("redis-server")?.risk == PrivacyRisk.none)
        #expect(app("localonly")?.risk == PrivacyRisk.none)
        let apple = app("ControlCenter")!
        #expect(apple.isApple && apple.risk == PrivacyRisk.none && apple.openToOthers)
        #expect(snapshot.count(.warning) == 1 && snapshot.count(.review) == 2)
    }

    @Test func appleAndNames() {
        #expect(NetworkScanner.isApple(Self.apple))
        #expect(!NetworkScanner.isApple(.signed(identifier: "com.tinyspeck.slackmacgap", teamID: "BQR82RBBHL", authority: "Apple Mac OS Application Signing")))
        #expect(!NetworkScanner.isApple(Self.good))
        #expect(NetworkScanner.displayName("/Applications/Docker.app") == "Docker")
        #expect(NetworkScanner.displayName("/Users/me/.local/share/devtool/versions/2.1.327") == "2.1.327")
    }

    @Test func lsofProblems() async {
        let failed = await NetworkScanner(runLsof: { nil }, processes: FakeProcessList(processes: [])).run()
        #expect(failed.problem == "MacScan couldn't run lsof." && failed.apps.isEmpty)
        // lsof exits 1 when there is nothing to show.
        let empty = await NetworkScanner(runLsof: { PostureCommandOutput(exitCode: 1, text: "") }, processes: FakeProcessList(processes: [])).run()
        #expect(empty.problem == nil && empty.apps.isEmpty)
        let broken = await NetworkScanner(runLsof: { PostureCommandOutput(exitCode: 2, text: "lsof: bad\n") }, processes: FakeProcessList(processes: [])).run()
        #expect(broken.problem == "lsof: bad")
    }
}
