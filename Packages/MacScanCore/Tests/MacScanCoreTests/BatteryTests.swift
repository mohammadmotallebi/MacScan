import Foundation
import Testing
@testable import MacScanCore

@Suite struct BatteryTests {
    @Test func batteryState() {
        let ac = BatteryState.parse(pmset: "Now drawing from 'AC Power'\n -InternalBattery-0 (id=36241507)\t80%; AC attached; not charging present: true\n")
        #expect(ac == BatteryState(percent: 80, onBattery: false, charging: false, remaining: nil))
        let battery = BatteryState.parse(pmset: "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t79%; discharging; 4:31 remaining present: true\n")
        #expect(battery == BatteryState(percent: 79, onBattery: true, charging: false, remaining: "4:31"))
        let charging = BatteryState.parse(pmset: "Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t50%; charging; 0:45 remaining present: true\n")
        #expect(charging.charging && charging.remaining == "0:45")
        let desktop = BatteryState.parse(pmset: "Now drawing from 'AC Power'\n")
        #expect(!desktop.hasBattery)
    }

    @Test func topReadsTheLastSample() {
        let text = """
        Processes: 916 total
        PID    POWER %CPU COMMAND
        22     0.0   0.0  old
        Processes: 916 total
        PID    POWER %CPU COMMAND
        22263  54.8  54.8 contactsd
        46843  16.3  16.3 Code Helper (Ren
        """
        #expect(EnergyReading.parse(top: text) == [
            EnergyReading(pid: 22263, power: 54.8, cpu: 54.8, command: "contactsd"),
            EnergyReading(pid: 46843, power: 16.3, cpu: 16.3, command: "Code Helper (Ren"),
        ])
    }

    static let assertions = """
    Assertion status system-wide:
       PreventUserIdleSystemSleep     1
    Listed by owning process:
       pid 74511(rcd): [0x000c4b7a0009836c] 00:01:17 UserIsActive named: "com.apple.rcdevent"
    \tCreated for PID: 55.
       pid 1275(caffeinate): [0x000c4f010001842e] 00:00:07 PreventUserIdleSystemSleep named: "caffeinate command-line tool"
    \tDetails: caffeinate asserting for 300 secs
       pid 743(coreaudiod): [0x000c4e3900018315] 00:03:27 PreventUserIdleSystemSleep named: "com.apple.audio.context.preventuseridlesleep"
    \tCreated for PID: 1144.
    \tResources: audio-in 189D
       pid 900(Keynote): [0x1] 00:10:00 PreventUserIdleDisplaySleep named: "Playing slideshow"
    Kernel Assertions: 0x4=USB
       id=500  level=255 0x4=USB mod=1/1/70, 12:00 AM description=com.apple.usb.externaldevice.14100000 owner=Hub
    """

    @Test func sleepBlockers() {
        let blockers = SleepBlocker.parse(assertions: Self.assertions)
        #expect(blockers.map(\.process) == ["caffeinate", "coreaudiod", "Keynote"])
        #expect(blockers[0].forPID == nil && blockers[0].reason == "The caffeinate command is running")
        #expect(blockers[1].forPID == 1144 && blockers[1].reason == "Playing or recording audio" && !blockers[1].keepsScreenOn)
        #expect(blockers[2].keepsScreenOn && blockers[2].held == "00:10:00")
    }

    @Test func groupsHelpersAndCreditsBlockers() async {
        let processes = FakeProcessList(processes: [
            LiveProcess(pid: 10, uid: 501, name: "Code", path: "/Applications/Code.app/Contents/MacOS/Code"),
            LiveProcess(pid: 11, uid: 501, name: "Code Helper", path: "/Applications/Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper"),
            LiveProcess(pid: 20, uid: 88, name: "WindowServer", path: "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer"),
            LiveProcess(pid: 1144, uid: 501, name: "Spotify", path: "/Applications/Spotify.app/Contents/MacOS/Spotify"),
            LiveProcess(pid: 743, uid: 202, name: "coreaudiod", path: "/usr/sbin/coreaudiod"),
            LiveProcess(pid: 40, uid: 501, name: "com.docker.backend", path: "/Applications/Docker.app/Contents/MacOS/com.docker.backend"),
            LiveProcess(pid: 50, uid: 501, name: "MacScan", path: "/Applications/MacScan.app/Contents/MacOS/MacScan"),
            LiveProcess(pid: 51, parentPID: 50, uid: 501, name: "clamscan", path: "/opt/homebrew/bin/clamscan"),
            LiveProcess(pid: 30, uid: 501, name: "com.apple.Virtua", path: "/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine"),
        ])
        let outputs: [String: String] = [
            "batt": "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t60%; discharging; 3:00 remaining present: true",
            "assertions": Self.assertions,
            "top": "PID POWER %CPU COMMAND\n10 4.0 4.0 Code\n11 30.0 30.0 Code Helper\n20 12.0 12.0 WindowServer\n1144 0.2 0.2 Spotify\n743 1.0 1.0 coreaudiod\n30 9.0 9.0 com.apple.Virtua\n51 60.0 60.0 clamscan\n",
        ]
        let scanner = BatteryScanner(run: { _, args in
            PostureCommandOutput(text: args.contains("batt") ? outputs["batt"]! : args.contains("assertions") ? outputs["assertions"]! : outputs["top"]!)
        }, processes: processes, usage: { pid in
            pid == 10 ? (3600, Date(timeIntervalSince1970: 100)) : pid == 11 ? (1800, Date(timeIntervalSince1970: 50)) : nil
        }, responsible: { $0 == 30 ? 40 : $0 == 20 ? 1 : nil })
        let report = await scanner.scan()
        #expect(report.state.percent == 60 && report.state.onBattery)
        let code = try! #require(report.apps.first { $0.name == "Code" })
        #expect(code.name == "Code" && code.impact == 34 && code.level == .high && code.pids == [10, 11])
        #expect(code.usedWh == 1.5 && code.startedAt == Date(timeIntervalSince1970: 50))
        #expect(report.apps.first { $0.name == "WindowServer" }?.isSystem == true)
        #expect(report.apps.first { $0.name == "WindowServer" }?.level == .medium)
        // Audio held by coreaudiod counts for Spotify.
        #expect(report.apps.first { $0.name == "Spotify" }?.blockers.map(\.reason) == ["Playing or recording audio"])
        #expect(report.apps.first { $0.name == "coreaudiod" }?.blockers.isEmpty == true)
        // Not running in top's list but holding a blocker: still shown.
        #expect(report.apps.contains { $0.name == "Keynote" && $0.blockers.first?.keepsScreenOn == true })
        // The virtual machine counts for Docker, which started it.
        #expect(report.apps.first { $0.name == "Docker" }.map { ($0.impact, $0.isSystem) } ?? (0, true) == (9, false))
        // A scan tool MacScan started says so.
        let clam = try! #require(report.apps.first { $0.name == "clamscan" })
        #expect(clam.byMacScan && clam.hint == "Started by MacScan for a scan; it stops when the scan ends")
        #expect(report.usingNow.map(\.name) == ["clamscan", "Code", "WindowServer", "Docker", "coreaudiod"])
        #expect(report.usedMost.map(\.name) == ["Code"])
        #expect(report.heavy == 2)
    }

    /// Read-only look at this Mac: MACSCAN_BATTERY_PROBE=1 swift test --filter realBatteryProbe
    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSCAN_BATTERY_PROBE"] != nil))
    func realBatteryProbe() async {
        let report = await BatteryScanner().scan()
        print("state:", report.state, "problem:", report.problem ?? "-")
        for app in report.usingNow.prefix(12) { print(String(format: "now %6.1f %@ %@", app.impact, app.name, app.isSystem ? "(macOS)" : "")) }
        for app in report.usedMost.prefix(8) { print(String(format: "used %6.2f Wh %@", app.usedWh ?? 0, app.name), app.startedAt ?? "-") }
        for app in report.blockers { print("awake:", app.name, app.blockers.map(\.reason)) }
        #expect(!report.apps.isEmpty)
    }
}

@Suite struct BatteryWatcherTests {
    /// Never the user's real MacScan log.
    let logger = FileLogger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("MacScanTestLogs"))

    func app(_ name: String, impact: Double, system: Bool = false) -> EnergyApp {
        EnergyApp(id: "/Applications/\(name).app", name: name, path: "/Applications/\(name).app", pids: [1], isSystem: system,
                  impact: impact, usedWh: nil, startedAt: nil, blockers: [])
    }

    func report(_ apps: [EnergyApp], onBattery: Bool = true) -> BatteryReport {
        BatteryReport(state: BatteryState(percent: 50, onBattery: onBattery, charging: false, remaining: nil), apps: apps, takenAt: Date(), problem: nil)
    }

    @Test func alertsAfterThreeHighChecksOnBatteryOncePerDay() throws {
        let dir = try TempDir()
        let watcher = BatteryWatcher(file: dir.url.appendingPathComponent("watch.json"))
        let start = Date(timeIntervalSince1970: 1_000_000)
        func at(_ n: Int) -> Date { start.addingTimeInterval(Double(n) * BatteryWatcher.interval) }
        let heavy = [app("Motrix", impact: 40), app("WindowServer", impact: 60, system: true), app("Notes", impact: 2)]

        #expect(watcher.check(report(heavy), now: at(0)).isEmpty)
        #expect(watcher.check(report(heavy), now: at(1)).isEmpty)
        #expect(watcher.check(report(heavy), now: at(2)).map(\.name) == ["Motrix"])
        #expect(BatteryWatcher.message(for: heavy[0]) == "Motrix has been using a lot of energy for 15 min.")
        // Not again the same day.
        #expect(watcher.check(report(heavy), now: at(3)).isEmpty)
    }

    @Test func pluggedInDropOrGapStartsOver() throws {
        let dir = try TempDir()
        let watcher = BatteryWatcher(file: dir.url.appendingPathComponent("watch.json"))
        let start = Date(timeIntervalSince1970: 2_000_000)
        func at(_ n: Double) -> Date { start.addingTimeInterval(n * BatteryWatcher.interval) }
        let heavy = [app("Motrix", impact: 40)]
        _ = watcher.check(report(heavy), now: at(0))
        _ = watcher.check(report(heavy), now: at(1))
        _ = watcher.check(report(heavy, onBattery: false), now: at(2))          // plugged in
        #expect(watcher.check(report(heavy), now: at(3)).isEmpty)
        _ = watcher.check(report([app("Motrix", impact: 3)]), now: at(4))       // calmed down
        _ = watcher.check(report(heavy), now: at(5))
        _ = watcher.check(report(heavy), now: at(6))
        #expect(watcher.check(report(heavy), now: at(10)).isEmpty, "a long gap (sleep) starts over")
    }

    @Test func workerNotifiesAndRecordsStatus() async throws {
        let dir = try TempDir()
        let watcher = BatteryWatcher(file: dir.url.appendingPathComponent("watch.json"))
        let status = BackgroundStatusStore(file: dir.url.appendingPathComponent("status.json"))
        let notifier = NotificationRecorder()
        let heavy = report([app("Motrix", impact: 40)])
        let start = Date(timeIntervalSince1970: 3_000_000)
        for n in 0..<3 {
            await BackgroundScanWorker.runBatteryWatch(settings: ScanSettings(), notifier: notifier, read: { heavy }, watcher: watcher,
                                                       status: status, logger: logger, now: start.addingTimeInterval(Double(n) * 300))
        }
        #expect(notifier.sent == [BackgroundNotification(title: "Using a lot of battery", body: "Motrix has been using a lot of energy for 15 min.", section: "battery")])
        #expect(status.load()[.battery]?.summary == "Alerted: Motrix" && status.load()[.battery]?.noteworthy == true)

        var off = ScanSettings()
        off.watchBattery = false
        await BackgroundScanWorker.runBatteryWatch(settings: off, notifier: notifier, read: { heavy }, watcher: watcher, status: status, logger: logger)
        #expect(status.load()[.battery]?.summary == "Skipped: turned off")
    }

    @Test func agentRunsEveryFiveMinutes() {
        let agent = BackgroundAgent(executable: URL(fileURLWithPath: "/Applications/MacScan.app/Contents/MacOS/MacScan"))
        #expect(agent.job(for: .battery, settings: ScanSettings())?["StartInterval"] as? Int == 300)
        var off = ScanSettings()
        off.watchBattery = false
        #expect(agent.job(for: .battery, settings: off) == nil)
    }
}
