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
        ])
        let outputs: [String: String] = [
            "batt": "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t60%; discharging; 3:00 remaining present: true",
            "assertions": Self.assertions,
            "top": "PID POWER %CPU COMMAND\n10 4.0 4.0 Code\n11 30.0 30.0 Code Helper\n20 12.0 12.0 WindowServer\n1144 0.2 0.2 Spotify\n743 1.0 1.0 coreaudiod\n",
        ]
        let scanner = BatteryScanner(run: { _, args in
            PostureCommandOutput(text: args.contains("batt") ? outputs["batt"]! : args.contains("assertions") ? outputs["assertions"]! : outputs["top"]!)
        }, processes: processes, usage: { pid in
            pid == 10 ? (3600, Date(timeIntervalSince1970: 100)) : pid == 11 ? (1800, Date(timeIntervalSince1970: 50)) : nil
        })
        let report = await scanner.scan()
        #expect(report.state.percent == 60 && report.state.onBattery)
        let code = try! #require(report.apps.first)
        #expect(code.name == "Code" && code.impact == 34 && code.level == .high && code.pids == [10, 11])
        #expect(code.usedWh == 1.5 && code.startedAt == Date(timeIntervalSince1970: 50))
        #expect(report.apps.first { $0.name == "WindowServer" }?.isSystem == true)
        #expect(report.apps.first { $0.name == "WindowServer" }?.level == .medium)
        // Audio held by coreaudiod counts for Spotify.
        #expect(report.apps.first { $0.name == "Spotify" }?.blockers.map(\.reason) == ["Playing or recording audio"])
        #expect(report.apps.first { $0.name == "coreaudiod" }?.blockers.isEmpty == true)
        // Not running in top's list but holding a blocker: still shown.
        #expect(report.apps.contains { $0.name == "Keynote" && $0.blockers.first?.keepsScreenOn == true })
        #expect(report.usingNow.map(\.name) == ["Code", "WindowServer", "coreaudiod"])
        #expect(report.usedMost.map(\.name) == ["Code"])
        #expect(report.heavy == 1)
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
