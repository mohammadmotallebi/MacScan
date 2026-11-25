import AppKit
import MacScanCore
import SwiftUI

/// Entry point. `--macscan-elevated-scan` runs the headless root scan worker (launched by an
/// administrator scan behind the password prompt) instead of the app, and `--macscan-background-scan`
/// runs one headless scheduled or Downloads scan (launched by launchd) and exits.
@main
enum MacScanMain {
    @MainActor
    static func main() {
        let args = CommandLine.arguments
        if args.count > 1, args[1] == ElevatedScanWorker.flag {
            exit(ElevatedScanWorker.main(arguments: Array(args.dropFirst(2))))
        }
        if args.count > 1, args[1] == BackgroundScanWorker.flag {
            exit(BackgroundScanWorker.main(arguments: Array(args.dropFirst(2)), notifier: UserNotifier()))
        }
        MacScanApp.main()
    }
}

struct MacScanApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var state = AppState()

    var body: some Scene {
        // A single window. Closing it quits the app; no MacScan process keeps running in the background.
        // (Optional background scans are started by launchd and exit when they finish.)
        Window("MacScan", id: "main") {
            ContentView()
                .environment(state)
                .frame(minWidth: 980, minHeight: 640)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Scan") {
                Button("Full Check") { state.scanFullCheck() }
                    .keyboardShortcut("f", modifiers: [.command, .shift])
                    .disabled(state.isScanning)
                Divider()
                Button("Scan Applications") { state.scanApplications() }
                    .keyboardShortcut("r", modifiers: [.command])
                    .disabled(state.isScanning)
                Button("Scan Startup Items") { state.scanStartupItems() }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
                    .disabled(state.isScanning)
                Button("Scan Running Processes") { state.scanRunningProcesses() }
                    .keyboardShortcut("p", modifiers: [.command, .shift])
                    .disabled(state.isScanning)
                Button("Scan Browser Extensions") { state.scanBrowserExtensions() }
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                    .disabled(state.isScanning)
                Button("Scan Folders") { state.scanCustomFolders() }
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                    .disabled(state.isScanning || state.customFolders.isEmpty)
                Button("Scan File or Folder…") { state.chooseAndScan() }
                    .keyboardShortcut("o", modifiers: [.command])
                    .disabled(state.isScanning)
                Divider()
                Button("Uninstall an App…") {
                    state.selectedSection = .uninstall
                    state.uninstall.chooseApp()
                }
                .keyboardShortcut("u", modifiers: [.command, .shift])
                Button("Find Big Folders and Files") {
                    state.selectedSection = .diskUsage
                    if state.diskUsage.report == nil { state.diskUsage.scan() }
                }
                .keyboardShortcut("d", modifiers: [.command, .shift])
                .disabled(state.diskUsage.isScanning)
                Button("Check Security Settings") {
                    state.selectedSection = .security
                    state.security.refresh()
                }
                .keyboardShortcut("k", modifiers: [.command, .shift])
                .disabled(state.security.isChecking)
                Button("Check Privacy Permissions") {
                    state.selectedSection = .privacy
                    state.privacy.refresh()
                }
                .keyboardShortcut("y", modifiers: [.command, .shift])
                .disabled(state.privacy.isChecking)
                Button("Check Network Activity") {
                    state.selectedSection = .network
                    state.network.refresh()
                }
                .keyboardShortcut("n", modifiers: [.command, .shift])
                .disabled(state.network.isChecking)
                Button("Install an App…") {
                    state.selectedSection = .install
                    state.installer.choose(state: state)
                }
                .keyboardShortcut("i", modifiers: [.command, .shift])
                .disabled(state.installer.isBusy)
                Button("Check Battery Usage") {
                    state.selectedSection = .battery
                    state.battery.refresh()
                }
                .keyboardShortcut("b", modifiers: [.command, .shift])
                .disabled(state.battery.isChecking)
                Divider()
                Button("Cancel Scan") { state.cancelScan() }
                    .keyboardShortcut(".", modifiers: [.command])
                    .disabled(!state.isScanning)
                Divider()
                Button("Update Virus Database") { state.updateDatabase() }
                    .disabled(state.isScanning || state.freshclam?.running == true)
            }
        }

        Settings {
            SettingsView()
                .environment(state)
        }

        // Only there when "Show MacScan in the menu bar" is on.

    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var windowObservers: [any NSObjectProtocol] = []

    /// With the menu bar icon on, closing the window keeps MacScan running in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !SettingsStore.load().showInMenuBar
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let center = NotificationCenter.default
        // Main window closed while living in the menu bar: hide the Dock icon too.
        windowObservers.append(center.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { note in
            nonisolated(unsafe) let window = note.object   // delivered on the main queue
            MainActor.assumeIsolated {
                guard Self.isMainWindow(window) else { return }
                if SettingsStore.load().showInMenuBar {
                    NSApp.setActivationPolicy(.accessory)
                    FileLogger.shared.info("Window closed: MacScan stays in the menu bar")
                }
            }
        })
        // Main window back: show the Dock icon again.
        windowObservers.append(center.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { note in
            nonisolated(unsafe) let window = note.object   // delivered on the main queue
            MainActor.assumeIsolated {
                guard Self.isMainWindow(window) else { return }
                if NSApp.activationPolicy() != .regular {
                    NSApp.setActivationPolicy(.regular)
                    FileLogger.shared.info("Window open again: Dock icon back")
                }
            }
        })
    }

    /// SwiftUI names the window after the scene id ("main"), sometimes with a suffix.
    @MainActor private static func isMainWindow(_ object: Any?) -> Bool {
        guard let window = object as? NSWindow else { return false }
        return window.identifier?.rawValue.hasPrefix("main") == true
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        // Must be set before launch finishes, or a click on a notification that started the app is lost.
        NotificationRouter.shared.install()
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Child processes (clamscan, yara, freshclam…) are not killed automatically when we exit.
        ProcessRegistry.shared.terminateAll()
        FileLogger.shared.info("MacScan quit")
        FileLogger.shared.flush()
    }
}
