import Darwin
import Foundation

/// Charge and power source, from `pmset -g batt`.
public struct BatteryState: Hashable, Sendable {
    /// Nil on a Mac without a battery.
    public var percent: Int?
    public var onBattery: Bool
    public var charging: Bool
    /// "4:31" when macOS has an estimate.
    public var remaining: String?

    public var hasBattery: Bool { percent != nil }

    public init(percent: Int?, onBattery: Bool, charging: Bool, remaining: String?) {
        self.percent = percent
        self.onBattery = onBattery
        self.charging = charging
        self.remaining = remaining
    }

    static func parse(pmset text: String) -> BatteryState {
        let onBattery = text.contains("'Battery Power'")
        guard let line = text.split(separator: "\n").first(where: { $0.contains("InternalBattery") }),
              let percentRange = line.range(of: #"\d+%"#, options: .regularExpression) else {
            return BatteryState(percent: nil, onBattery: onBattery, charging: false, remaining: nil)
        }
        let percent = Int(line[percentRange].dropLast())
        let rest = line[percentRange.upperBound...].lowercased()
        let charging = rest.contains("charging") && !rest.contains("not charging") && !rest.contains("discharging")
        let remaining = rest.range(of: #"\d+:\d\d remaining"#, options: .regularExpression)
            .map { String(rest[$0].split(separator: " ")[0]) }
            .flatMap { $0 == "0:00" ? nil : $0 }
        return BatteryState(percent: percent, onBattery: onBattery, charging: charging, remaining: remaining)
    }
}

/// One process line from `top -stats pid,power,cpu,command`.
struct EnergyReading: Hashable, Sendable {
    var pid: Int32
    var power: Double
    var cpu: Double
    var command: String

    /// Reads the last sample (top's first sample has no real numbers yet).
    static func parse(top text: String) -> [EnergyReading] {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard let header = lines.lastIndex(where: { $0.hasPrefix("PID") }) else { return [] }
        return lines[(header + 1)...].compactMap { line in
            let parts = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
            guard parts.count == 4, let pid = Int32(parts[0]), let power = Double(parts[1]), let cpu = Double(parts[2]) else { return nil }
            return EnergyReading(pid: pid, power: power, cpu: cpu, command: parts[3].trimmingCharacters(in: .whitespaces))
        }
    }
}

/// Something that stops the Mac or its screen from sleeping, from `pmset -g assertions`.
public struct SleepBlocker: Identifiable, Hashable, Sendable {
    public var id: String { "\(pid)-\(name)" }
    /// The process holding it.
    public var pid: Int32
    public var process: String
    /// The process it was made for (coreaudiod holds audio ones for the app playing).
    public var forPID: Int32?
    public var keepsScreenOn: Bool
    /// The name the program gave it.
    public var name: String
    /// How long it has been held, e.g. "00:03:27".
    public var held: String

    /// A plain reason, e.g. "Playing or recording audio".
    public var reason: String {
        let lower = name.lowercased()
        if lower.contains("audio") { return "Playing or recording audio" }
        if lower.contains("caffeinate") { return "The caffeinate command is running" }
        if lower.contains("video") || lower.contains("playing") { return "Playing video" }
        if lower.contains("download") { return "Downloading" }
        if lower.contains("backup") || lower.contains("timemachine") { return "Backing up" }
        if lower.contains("btstack") || lower.contains("bluetooth") { return "Bluetooth" }
        if name.contains("anon<") || name.hasPrefix("com.") { return keepsScreenOn ? "Keeps the screen on" : "Working in the background" }
        return name
    }

    static let kinds: [String: Bool] = [
        "PreventUserIdleSystemSleep": false, "PreventSystemSleep": false, "NoIdleSleepAssertion": false,
        "PreventUserIdleDisplaySleep": true, "NoDisplaySleepAssertion": true,
    ]

    static func parse(assertions text: String) -> [SleepBlocker] {
        guard let start = text.range(of: "Listed by owning process:") else { return [] }
        let pattern = #"^\s*pid (\d+)\((.*?)\): \[[^\]]*\] (\S+) (\S+) named: "(.*)"\s*$"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        var result: [SleepBlocker] = []
        // Detail lines belong to the line above, which may be one that was skipped.
        var lastKept = false
        for raw in text[start.upperBound...].split(separator: "\n") {
            let line = String(raw)
            if let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) {
                func group(_ i: Int) -> String { Range(match.range(at: i), in: line).map { String(line[$0]) } ?? "" }
                lastKept = false
                // powerd's own "while display is on" one just mirrors the screen being on.
                guard let pid = Int32(group(1)), let screen = kinds[group(4)], group(2) != "powerd" else { continue }
                result.append(SleepBlocker(pid: pid, process: group(2), forPID: nil, keepsScreenOn: screen, name: group(5), held: group(3)))
                lastKept = true
            } else if line.hasPrefix("\t"), lastKept,
                      let range = line.range(of: #"Created for PID: (\d+)"#, options: .regularExpression),
                      result[result.count - 1].forPID == nil {
                let digits = line[range].split(separator: " ").last.map { $0.filter(\.isNumber) }
                result[result.count - 1].forPID = digits.flatMap { Int32($0) }
            } else if !line.hasPrefix("\t"), !line.hasPrefix("   pid") {
                break  // The next part of the output ("Kernel Assertions") starts.
            }
        }
        return result
    }
}

public enum EnergyLevel: Int, Comparable, Sendable {
    case low, medium, high
    public static func < (a: EnergyLevel, b: EnergyLevel) -> Bool { a.rawValue < b.rawValue }

    /// Activity Monitor's "Energy Impact" scale: about 1 per 1% of one CPU core.
    static func of(_ impact: Double) -> EnergyLevel {
        impact >= 20 ? .high : impact >= 5 ? .medium : .low
    }
}

/// One app or program, with its helpers counted in.
public struct EnergyApp: Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    /// The app bundle or program file, when known.
    public var path: String?
    public var pids: [Int32]
    /// Part of macOS.
    public var isSystem: Bool
    /// Energy impact right now (Activity Monitor's number).
    public var impact: Double
    public var level: EnergyLevel { EnergyLevel.of(impact) }
    /// Energy used since it started, in watt-hours. Nil when macOS doesn't tell (other users' and system programs).
    public var usedWh: Double?
    /// When its oldest running process started.
    public var startedAt: Date?
    /// What it keeps awake, if anything.
    public var blockers: [SleepBlocker]

    /// A plain note on what a busy macOS service does.
    public var hint: String? {
        let lower = name.lowercased()
        if lower == "windowserver" { return "Draws everything on screen" }
        if lower == "kernel_task" { return "macOS itself; also keeps the Mac cool" }
        if lower.contains("virtualization") { return "A virtual machine, e.g. Docker or UTM" }
        if ["mds", "mds_stores", "mdworker", "mdworker_shared", "corespotlightd", "spotlightknowledged"].contains(where: { lower.hasPrefix($0) }) {
            return "Spotlight indexing your files"
        }
        if lower.hasPrefix("photoanalysisd") || lower.hasPrefix("mediaanalysisd") { return "Photos looking through your library" }
        if lower.hasPrefix("backupd") { return "Time Machine backup" }
        if lower.hasPrefix("bird") || lower.hasPrefix("cloudd") || lower.hasPrefix("fileproviderd") { return "iCloud syncing" }
        if lower.hasPrefix("softwareupdated") { return "Checking for or installing updates" }
        if lower.hasPrefix("contactsd") { return "Contacts syncing" }
        return isSystem ? "Part of macOS" : nil
    }
}

public struct BatteryReport: Sendable {
    public var state: BatteryState
    /// Every program seen, heaviest now first.
    public var apps: [EnergyApp]
    public var takenAt: Date
    public var problem: String?

    /// Using noticeable energy right now.
    public var usingNow: [EnergyApp] { apps.filter { $0.impact >= 0.5 } }
    /// Apps that used the most since they started.
    public var usedMost: [EnergyApp] {
        apps.filter { ($0.usedWh ?? 0) >= 0.01 }.sorted { ($0.usedWh ?? 0) > ($1.usedWh ?? 0) }
    }
    public var blockers: [EnergyApp] { apps.filter { !$0.blockers.isEmpty } }
    public var heavy: Int { apps.filter { $0.level == .high }.count }

    public init(state: BatteryState, apps: [EnergyApp], takenAt: Date, problem: String?) {
        self.state = state
        self.apps = apps
        self.takenAt = takenAt
        self.problem = problem
    }
}

/// Reads which programs use the battery. Read-only: it never quits or slows anything.
public struct BatteryScanner: Sendable {
    public typealias Runner = @Sendable (String, [String]) async -> PostureCommandOutput?
    /// Energy in joules and start date of a process, when macOS shares it.
    public typealias Usage = @Sendable (Int32) -> (joules: Double, started: Date?)?

    var run: Runner
    var processes: any ProcessListing
    var usage: Usage

    public init(run: @escaping Runner = SecurityPosture.systemRunner,
                processes: any ProcessListing = SystemProcessList(),
                usage: @escaping Usage = BatteryScanner.systemUsage) {
        self.run = run
        self.processes = processes
        self.usage = usage
    }

    public func scan() async -> BatteryReport {
        async let batt = run("/usr/bin/pmset", ["-g", "batt"])
        async let assertions = run("/usr/bin/pmset", ["-g", "assertions"])
        // Two samples two seconds apart; the second one has the real numbers.
        let top = await run("/usr/bin/top", ["-l", "2", "-s", "2", "-o", "power", "-stats", "pid,power,cpu,command"])
        let state = await batt.map { BatteryState.parse(pmset: $0.text) } ?? BatteryState(percent: nil, onBattery: false, charging: false, remaining: nil)
        let blockers = await assertions.map { SleepBlocker.parse(assertions: $0.text) } ?? []
        let readings = top.map { EnergyReading.parse(top: $0.text) } ?? []
        let problem = readings.isEmpty ? "MacScan couldn't read energy use from top." : nil
        return BatteryReport(state: state, apps: apps(readings: readings, blockers: blockers), takenAt: Date(), problem: problem)
    }

    func apps(readings: [EnergyReading], blockers: [SleepBlocker]) -> [EnergyApp] {
        let live = Dictionary(processes.runningProcesses().map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        var groups: [String: EnergyApp] = [:]
        var keyOfPID: [Int32: String] = [:]

        func key(for pid: Int32, command: String) -> String {
            if let key = keyOfPID[pid] { return key }
            let process = live[pid]
            let unit = process?.path.map { PersistenceScanner.enclosingApp(of: $0)?.path ?? $0 }
            let key = unit ?? "pid:\(pid)"
            if groups[key] == nil {
                let name = unit.map(NetworkScanner.displayName) ?? (command.isEmpty ? process?.name ?? "pid \(pid)" : command)
                let isSystem = unit.map(ProcessScanner.isSealedSystemPath) ?? (pid == 0 || process?.uid == 0)
                groups[key] = EnergyApp(id: key, name: name, path: unit, pids: [], isSystem: isSystem, impact: 0,
                                        usedWh: nil, startedAt: nil, blockers: [])
            }
            keyOfPID[pid] = key
            return key
        }

        // MacScan's own measuring tool.
        for reading in readings where !(reading.command == "top" && live[reading.pid]?.path == "/usr/bin/top") {
            let k = key(for: reading.pid, command: reading.command)
            groups[k]!.pids.append(reading.pid)
            groups[k]!.impact += reading.power
            if let used = usage(reading.pid) {
                groups[k]!.usedWh = (groups[k]!.usedWh ?? 0) + used.joules / 3600
                if let started = used.started, started < (groups[k]!.startedAt ?? .distantFuture) {
                    groups[k]!.startedAt = started
                }
            }
        }
        for blocker in blockers {
            // Audio and similar are held by a macOS service for the app that asked.
            let pid = blocker.forPID ?? blocker.pid
            let k = key(for: pid, command: pid == blocker.pid ? blocker.process : "")
            groups[k]!.blockers.append(blocker)
        }
        return groups.values
            .filter { !$0.pids.isEmpty || !$0.blockers.isEmpty }
            .sorted { $0.impact != $1.impact ? $0.impact > $1.impact : $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// Energy since start (Apple silicon counts it per process) and start time. Only works for the user's own programs.
    public static let systemUsage: Usage = { pid in
        var info = rusage_info_v6()
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V6, $0) }
        }
        guard result == 0, info.ri_energy_nj > 0 else { return nil }
        var kinfo = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var started: Date?
        if sysctl(&mib, 4, &kinfo, &size, nil, 0) == 0, size > 0 {
            let tv = kinfo.kp_proc.p_un.__p_starttime
            started = Date(timeIntervalSince1970: TimeInterval(tv.tv_sec) + TimeInterval(tv.tv_usec) / 1_000_000)
        }
        return (Double(info.ri_energy_nj) / 1_000_000_000, started)
    }
}
