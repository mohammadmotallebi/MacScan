import AppKit
import MacScanCore
import Observation

/// The menu bar icon and its menu, shown when "Show MacScan in the menu bar" is on.
/// Plain AppKit: SwiftUI's MenuBarExtra got stuck in an update loop here.
@MainActor
final class MenuBarController: NSObject, NSMenuDelegate {
    private unowned let state: AppState
    private var item: NSStatusItem?

    init(state: AppState) {
        self.state = state
        super.init()
    }

    /// Adds or removes the icon to match the setting.
    func update(visible: Bool) {
        if visible, item == nil {
            let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
            let menu = NSMenu()
            menu.delegate = self
            item.menu = menu
            self.item = item
            watchIcon()
        } else if !visible, let item {
            NSStatusBar.system.removeStatusItem(item)
            self.item = nil
        }
    }

    /// Redraws the icon now, and again whenever the last result or the scanning state changes.
    private func watchIcon() {
        guard let item else { return }
        let status = withObservationTracking {
            state.menuBarStatus
        } onChange: { [weak self] in
            Task { @MainActor in self?.watchIcon() }
        }
        let image = NSImage(systemSymbolName: status.symbol, accessibilityDescription: status.tooltip)
        image?.isTemplate = true
        item.button?.image = image
        item.button?.toolTip = status.tooltip
    }

    // MARK: - Menu (rebuilt each time it opens, so the times are current)

    func menuNeedsUpdate(_ menu: NSMenu) {
        let status = MenuBarStatus(history: state.history, isScanning: state.isScanning)
        item?.button?.toolTip = status.tooltip
        menu.removeAllItems()

        let title = add(menu, status.title, #selector(openLastResult))
        title.isEnabled = true
        if let detail = status.detail {
            let line = add(menu, detail, #selector(openLastResult))
            line.indentationLevel = 1
        }
        if state.isScanning, let progress = state.progress?.status, !progress.isEmpty {
            add(menu, progress, nil).indentationLevel = 1
        }

        menu.addItem(.separator())
        if state.isScanning {
            add(menu, "Cancel Scan", #selector(cancelScan))
        } else {
            add(menu, "Full Check", #selector(fullCheck))
        }
        add(menu, "Check Security Settings", #selector(checkSecurity))
        add(menu, "Check Network Activity", #selector(checkNetwork))

        menu.addItem(.separator())
        add(menu, "Open MacScan", #selector(openApp))
        add(menu, "Settings…", #selector(openSettings))
        menu.addItem(.separator())
        add(menu, "Quit MacScan", #selector(quit))
    }

    @discardableResult
    private func add(_ menu: NSMenu, _ title: String, _ action: Selector?) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = action == nil ? nil : self
        item.isEnabled = action != nil
        menu.addItem(item)
        return item
    }

    @objc private func openLastResult() {
        if let id = MenuBarStatus(history: state.history, isScanning: false).sessionID {
            state.showSession(id)
        } else {
            state.bringToFront()
        }
    }

    @objc private func fullCheck() { state.scanFullCheck() }
    @objc private func cancelScan() { state.cancelScan() }

    @objc private func checkSecurity() {
        state.selectedSection = .security
        state.security.refresh()
        state.bringToFront()
    }

    @objc private func checkNetwork() {
        state.selectedSection = .network
        state.network.refresh()
        state.bringToFront()
    }

    @objc private func openApp() { state.bringToFront() }

    @objc private func openSettings() {
        NSApp.activate()
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
    }

    @objc private func quit() { NSApp.terminate(nil) }
}
