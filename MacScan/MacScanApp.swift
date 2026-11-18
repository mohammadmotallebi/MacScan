import AppKit
import MacScanCore
import SwiftUI

/// Entry point. `--macscan-elevated-scan` runs the headless root scan worker (launched by an
/// administrator scan behind the password prompt) instead of the app.
@main
enum MacScanMain {
    @MainActor
    static func main() {
        let args = CommandLine.arguments
        if args.count > 1, args[1] == ElevatedScanWorker.flag {
            exit(ElevatedScanWorker.main(arguments: Array(args.dropFirst(2))))
        }
        MacScanApp.main()
    }
}

struct MacScanApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var state = AppState()

    var body: some Scene {
        // A single window. Closing it quits the app; nothing keeps running in the background.
        Window("MacScan", id: "main") {
            ContentView()
                .environment(state)
                .frame(minWidth: 980, minHeight: 640)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Scan") {
                Button("Scan Applications") { state.scanApplications() }
                    .keyboardShortcut("r", modifiers: [.command])
                    .disabled(state.isScanning)
                Button("Scan Startup Items") { state.scanStartupItems() }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
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
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Child processes (clamscan, yara, freshclam…) are not killed automatically when we exit.
        ProcessRegistry.shared.terminateAll()
        FileLogger.shared.info("MacScan quit")
        FileLogger.shared.flush()
    }
}
