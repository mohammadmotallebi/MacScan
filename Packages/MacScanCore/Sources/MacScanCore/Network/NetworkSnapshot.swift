import Foundation

/// Where the other end of a connection is.
public enum NetworkScope: Int, Sendable, Comparable {
    case thisMac, localNetwork, internet

    public static func < (a: NetworkScope, b: NetworkScope) -> Bool { a.rawValue < b.rawValue }

    public var title: String {
        switch self {
        case .thisMac: "this Mac"
        case .localNetwork: "local network"
        case .internet: "internet"
        }
    }

    /// Sorts an address (no brackets, no port) into this Mac, the local network or the internet.
    public static func of(_ address: String) -> NetworkScope {
        let a = address.lowercased()
        if a == "::1" || a.hasPrefix("127.") || a == "localhost" { return .thisMac }
        if a.contains(":") {
            // IPv6: link-local fe80::/10, unique-local fc00::/7, and IPv4 written as ::ffff:a.b.c.d.
            if a.hasPrefix("::ffff:") { return of(String(a.dropFirst("::ffff:".count))) }
            if a.hasPrefix("fe8") || a.hasPrefix("fe9") || a.hasPrefix("fea") || a.hasPrefix("feb") { return .localNetwork }
            if a.hasPrefix("fc") || a.hasPrefix("fd") { return .localNetwork }
            return .internet
        }
        let parts = a.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return .internet }
        switch (parts[0], parts[1]) {
        case (10, _), (192, 168), (169, 254): return .localNetwork
        case (172, 16...31): return .localNetwork
        case (100, 64...127): return .localNetwork   // carrier-grade NAT, also used by VPNs like Tailscale
        default: return .internet
        }
    }
}

/// One open network socket, as `lsof` reports it.
public struct NetworkSocket: Hashable, Sendable {
    public var pid: Int32
    public var command: String
    public var uid: UInt32?
    /// "TCP" or "UDP".
    public var proto: String
    public var localAddress: String
    public var localPort: String
    public var remoteAddress: String?
    public var remotePort: String?
    /// TCP state such as ESTABLISHED or LISTEN; nil for UDP.
    public var state: String?

    public init(pid: Int32, command: String, uid: UInt32? = nil, proto: String, localAddress: String, localPort: String,
                remoteAddress: String? = nil, remotePort: String? = nil, state: String? = nil) {
        self.pid = pid
        self.command = command
        self.uid = uid
        self.proto = proto
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.state = state
    }

    public var isListening: Bool {
        if proto == "TCP" { return state == "LISTEN" }
        return remoteAddress == nil && localPort != "*"
    }

    /// Bound to every network interface, so other computers can reach it.
    public var onAllInterfaces: Bool {
        ["*", "0.0.0.0", "::"].contains(localAddress)
    }

    /// Splits "address:port", where an IPv6 address is in brackets.
    static func splitEndpoint(_ text: Substring) -> (String, String)? {
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]") else { return nil }
            let address = text[text.index(after: text.startIndex)..<close]
            let rest = text[text.index(after: close)...]
            guard rest.hasPrefix(":") else { return nil }
            // Drop an interface suffix such as "%en0".
            return (String(address.split(separator: "%").first ?? address), String(rest.dropFirst()))
        }
        guard let colon = text.lastIndex(of: ":") else { return nil }
        return (String(text[..<colon]), String(text[text.index(after: colon)...]))
    }

    /// Parses `lsof -nP -i -F pcuPnT` output.
    public static func parse(lsof output: String) -> [NetworkSocket] {
        var result: [NetworkSocket] = []
        var pid: Int32?
        var command = ""
        var uid: UInt32?
        var proto: String?
        var name: Substring?
        var state: String?

        func flush() {
            defer { proto = nil; name = nil; state = nil }
            guard let pid, let proto, let name else { return }
            let halves = name.components(separatedBy: "->")
            guard let local = splitEndpoint(Substring(halves[0])) else { return }
            var socket = NetworkSocket(pid: pid, command: command, uid: uid, proto: proto, localAddress: local.0, localPort: local.1, state: state)
            if halves.count == 2, let remote = splitEndpoint(Substring(halves[1])) {
                socket.remoteAddress = remote.0
                socket.remotePort = remote.1
            }
            result.append(socket)
        }

        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let tag = line.first else { continue }
            let value = line.dropFirst()
            switch tag {
            case "p":
                flush()
                pid = Int32(value)
                command = ""
                uid = nil
            case "c": command = String(value)
            case "u": uid = UInt32(value)
            case "f": flush()
            case "P": proto = String(value)
            case "n": name = value
            case "T": if value.hasPrefix("ST=") { state = String(value.dropFirst(3)) }
            default: break
            }
        }
        flush()
        return result
    }
}

public struct NetworkConnection: Hashable, Sendable, Identifiable {
    public var id: String { "\(proto)|\(remoteAddress)|\(remotePort)|\(state ?? "")" }
    public var proto: String
    public var remoteAddress: String
    public var remotePort: String
    public var state: String?
    public var scope: NetworkScope
    /// The same address and port, counted once.
    public var count: Int
}

public struct NetworkListener: Hashable, Sendable, Identifiable {
    public var id: String { "\(proto)|\(address)|\(port)" }
    public var proto: String
    public var address: String
    public var port: String
    public var allInterfaces: Bool
}

/// One program and what it is doing on the network.
public struct NetworkApp: Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    /// The app or program file; nil when it couldn't be found.
    public var path: String?
    public var pids: [Int32]
    public var signer: String?
    public var isApple: Bool
    public var connections: [NetworkConnection]
    public var listeners: [NetworkListener]
    public var risk: PrivacyRisk
    public var reasons: [String]

    public var reachesOut: Bool { connections.contains { $0.scope != .thisMac } }
    /// A TCP port open to other computers. (UDP ports on all interfaces are mostly local discovery, such as Bonjour.)
    public var openToOthers: Bool { listeners.contains { $0.allInterfaces && $0.proto == "TCP" } }
    public var widestScope: NetworkScope? { connections.map(\.scope).max() }
}

public struct NetworkSnapshot: Sendable {
    public var apps: [NetworkApp]
    public var takenAt: Date
    /// Set when lsof couldn't be run or gave nothing usable.
    public var problem: String?
    /// Without administrator rights only this user's programs are visible.
    public var onlyOwnPrograms: Bool

    public func count(_ risk: PrivacyRisk) -> Int {
        apps.lazy.filter { $0.risk == risk }.count
    }
}

/// Lists which programs have network connections open right now, and which ones accept connections.
/// Read-only: it never blocks or closes anything, and never goes online (no name lookups).
public struct NetworkScanner: Sendable {
    public typealias LsofRunner = @Sendable () async -> PostureCommandOutput?
    public typealias Signer = @Sendable (URL) -> SigningStatus

    var runLsof: LsofRunner
    var processes: any ProcessListing
    var signing: Signer
    var home: URL

    public static let systemLsof: LsofRunner = {
        await SecurityPosture.systemRunner("/usr/sbin/lsof", ["-nP", "-i", "-F", "pcuPnT"])
    }

    /// Ports used by remote shells, IRC bots and well-known backdoors.
    static let suspiciousPorts: Set<String> = ["23", "1337", "4444", "4445", "5555", "6666", "6667", "6697", "31337", "12345", "54321"]
    /// TCP states of connections that are over or closing.
    static let closedStates: Set<String> = ["CLOSED", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "LAST_ACK", "CLOSING"]

    public init(runLsof: @escaping LsofRunner = NetworkScanner.systemLsof,
                processes: any ProcessListing = SystemProcessList(),
                signing: @escaping Signer = { CodeSigning.status(of: $0) },
                home: URL = AppPaths.home) {
        self.runLsof = runLsof
        self.processes = processes
        self.signing = signing
        self.home = home
    }

    public func run() async -> NetworkSnapshot {
        let now = Date()
        let onlyOwn = getuid() != 0
        guard let output = await runLsof() else {
            return NetworkSnapshot(apps: [], takenAt: now, problem: "MacScan couldn't run lsof.", onlyOwnPrograms: onlyOwn)
        }
        let sockets = NetworkSocket.parse(lsof: output.text)
        // lsof exits 1 when it finds nothing; that is a normal empty answer.
        if sockets.isEmpty, output.exitCode > 1 {
            return NetworkSnapshot(apps: [], takenAt: now, problem: output.text.trimmingCharacters(in: .whitespacesAndNewlines), onlyOwnPrograms: onlyOwn)
        }
        return NetworkSnapshot(apps: apps(from: sockets), takenAt: now, problem: nil, onlyOwnPrograms: onlyOwn)
    }

    func apps(from sockets: [NetworkSocket]) -> [NetworkApp] {
        let live = Dictionary(processes.runningProcesses().map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })

        struct Group {
            var name: String
            var path: String?
            var deleted = false
            var pids: Set<Int32> = []
            var sockets: [NetworkSocket] = []
        }
        var groups: [String: Group] = [:]
        for socket in sockets {
            if let state = socket.state, Self.closedStates.contains(state) { continue }
            if socket.proto == "UDP", socket.remoteAddress == nil, socket.localPort == "*" { continue }
            let process = live[socket.pid]
            let program = process?.path
            // Group by app bundle, so an app's helpers are one row.
            let unit = program.map { PersistenceScanner.enclosingApp(of: $0)?.path ?? $0 }
            let key = unit ?? "pid:\(socket.pid)"
            var group = groups[key] ?? Group(name: unit.map(Self.displayName) ?? socket.command, path: unit)
            group.deleted = group.deleted || process?.executableDeleted == true
            group.pids.insert(socket.pid)
            group.sockets.append(socket)
            groups[key] = group
        }

        var result: [NetworkApp] = []
        for (key, group) in groups {
            var connections: [String: NetworkConnection] = [:]
            var listeners: [String: NetworkListener] = [:]
            for socket in group.sockets {
                if socket.isListening {
                    let listener = NetworkListener(proto: socket.proto, address: socket.localAddress, port: socket.localPort, allInterfaces: socket.onAllInterfaces)
                    listeners[listener.id] = listener
                } else if let address = socket.remoteAddress, let port = socket.remotePort {
                    let connection = NetworkConnection(proto: socket.proto, remoteAddress: address, remotePort: port, state: socket.state,
                                                       scope: NetworkScope.of(address), count: 1)
                    if connections[connection.id] != nil { connections[connection.id]!.count += 1 } else { connections[connection.id] = connection }
                }
            }
            if connections.isEmpty && listeners.isEmpty { continue }

            let status = group.path.map { signing(URL(fileURLWithPath: $0)) }
            let isApple = status.map(Self.isApple) ?? false
            var app = NetworkApp(
                id: key, name: group.name, path: group.path, pids: group.pids.sorted(),
                signer: status.map { status in
                    if let path = group.path, let browser = WebAppShortcut.browser(ofApp: URL(fileURLWithPath: path), status: status) { return "\(browser) web-app shortcut" }
                    return status.description
                },
                isApple: isApple,
                connections: connections.values.sorted { ($0.scope, $0.remoteAddress, $0.remotePort) > ($1.scope, $1.remoteAddress, $1.remotePort) },
                listeners: listeners.values.sorted { ($0.allInterfaces ? 0 : 1, $0.port) < ($1.allInterfaces ? 0 : 1, $1.port) },
                risk: .none, reasons: [])
            let reasons = problems(app, status: status, deleted: group.deleted)
            app.risk = reasons.map(\.0).max() ?? .none
            app.reasons = reasons.map(\.1)
            result.append(app)
        }
        return result.sorted { a, b in
            if a.risk != b.risk { return a.risk > b.risk }
            if a.isApple != b.isApple { return !a.isApple }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
    }

    /// "Docker" for Docker.app, the file name for a program ("2.1.327" stays whole).
    static func displayName(_ path: String) -> String {
        let url = URL(fileURLWithPath: path)
        return url.pathExtension.lowercased() == "app" ? url.deletingPathExtension().lastPathComponent : url.lastPathComponent
    }

    static func isApple(_ status: SigningStatus) -> Bool {
        guard case .signed(let identifier, let team, let authority) = status else { return false }
        // "Apple Mac OS Application Signing" is the App Store's signature for other developers' apps, so it doesn't count.
        if let authority, authority.hasPrefix("Software Signing") { return true }
        return team == nil && identifier?.hasPrefix("com.apple.") == true
    }

    func problems(_ app: NetworkApp, status: SigningStatus?, deleted: Bool) -> [(PrivacyRisk, String)] {
        var result: [(PrivacyRisk, String)] = []
        if deleted {
            result.append((.review, "Its program file was deleted or replaced after it started."))
        }
        guard let path = app.path, let status else {
            if !deleted { result.append((.review, "MacScan couldn't find its program file.")) }
            return result
        }
        if app.isApple { return result }

        var untrusted = status.isUntrusted
        if case .adhoc = status, PersistenceScanner.isPackageManagerPath(path) || WebAppShortcut.browser(ofApp: URL(fileURLWithPath: path), status: status) != nil {
            untrusted = false
        }
        if untrusted, app.reachesOut || app.openToOthers {
            let who = switch status {
            case .unsigned: "It isn't signed, so macOS can't tell who made it,"
            case .selfSigned: "It is signed with a certificate Apple didn't issue,"
            default: "It is signed without a developer identity, so macOS can't tell who made it,"
            }
            let what = app.reachesOut && app.openToOthers ? "and it talks to other computers and accepts connections from them."
                : app.reachesOut ? "and it talks to other computers." : "and it accepts connections from other computers."
            result.append((.warning, "\(who) \(what)"))
            let scanner = ProcessScanner(lister: processes, home: home)
            if let location = scanner.locationProblem(path) {
                result.append((.warning, location.replacingOccurrences(of: "Untrusted program running from", with: "It runs from") + "."))
            }
        }
        if app.openToOthers, !untrusted {
            let ports = app.listeners.filter { $0.allInterfaces && $0.proto == "TCP" }.map(\.port)
            result.append((.review, "Accepts connections from other computers on port\(ports.count == 1 ? "" : "s") \(ports.prefix(4).joined(separator: ", ")). Fine if you share something on purpose."))
        }
        let odd = Set(app.connections.filter { $0.scope != .thisMac && Self.suspiciousPorts.contains($0.remotePort) }.map(\.remotePort)).sorted()
        if !odd.isEmpty {
            result.append((.review, "Connects to port \(odd.joined(separator: ", ")), which remote shells and backdoors often use."))
        }
        return result
    }
}
