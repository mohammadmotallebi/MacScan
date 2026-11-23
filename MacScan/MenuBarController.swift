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
            let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
            // A fixed name so macOS remembers this item by name, and ask for it to be shown:
            // macOS can keep an item hidden from an earlier run.
            item.autosaveName = "MacScanMenuBarIcon"
            item.isVisible = true
            FileLogger.shared.info("Menu bar icon added (visible: \(item.isVisible))")
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
        item.button?.image = Self.icon(badge: status.badgeSymbol, description: status.tooltip)
        item.button?.toolTip = status.tooltip
    }

    /// A one-color version of the app icon (a shield with a bug inside), with an optional mark in the
    /// bottom-right corner. One color so it fits light and dark menu bars.
    static func icon(badge: String?, description: String) -> NSImage {
        func symbol(_ name: String, _ size: CGFloat, _ weight: NSFont.Weight = .regular) -> NSImage? {
            NSImage(systemSymbolName: name, accessibilityDescription: nil)?
                .withSymbolConfiguration(.init(pointSize: size, weight: weight))
        }
        let image = NSImage(size: NSSize(width: 20, height: 18), flipped: false) { _ in
            if let shield = symbol("shield", 15, .medium) {
                let s = shield.size
                shield.draw(in: NSRect(x: 1, y: (18 - s.height) / 2, width: s.width, height: s.height))
                if let bug = symbol("ladybug.fill", 7.5) {
                    let b = bug.size
                    bug.draw(in: NSRect(x: 1 + (s.width - b.width) / 2, y: (18 - b.height) / 2 + 0.5, width: b.width, height: b.height))
                }
            }
            if let badge, let mark = symbol(badge, 8.5, .bold) {
                let m = mark.size
                let rect = NSRect(x: 20 - m.width, y: 0, width: m.width, height: m.height)
                // Cut a gap around the mark so it reads apart from the shield.
                NSGraphicsContext.current?.compositingOperation = .clear
                NSBezierPath(ovalIn: rect.insetBy(dx: -1.5, dy: -1.5)).fill()
                NSGraphicsContext.current?.compositingOperation = .sourceOver
                mark.draw(in: rect)
            }
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = description
        return image
    }

    // MARK: - Menu (rebuilt each time it opens, so the times are current)

    func menuNeedsUpdate(_ menu: NSMenu) {
        let status = MenuBarStatus(history: state.history, isScanning: state.isScanning)
        item?.button?.toolTip = status.tooltip
        menu.removeAllItems()

        let resultSymbol = switch status.level {
        case .unknown: "shield"
        case .clear: "checkmark.shield"
        case .attention: "exclamationmark.shield"
        case .threat: "exclamationmark.shield.fill"
        case .scanning: "hourglass"
        }
        add(menu, status.title, #selector(openLastResult), symbol: resultSymbol)
        if let detail = status.detail {
            add(menu, detail, #selector(openLastResult), symbol: "blank")
        }
        if state.isScanning, let progress = state.progress?.status, !progress.isEmpty {
            add(menu, progress, nil, symbol: "blank")
        }

        menu.addItem(.separator())
        if state.isScanning {
            add(menu, "Cancel Scan", #selector(cancelScan), symbol: "xmark.circle")
        } else {
            add(menu, "Full Check", #selector(fullCheck), symbol: "checkmark.shield")
        }
        add(menu, "Check Security Settings", #selector(checkSecurity), symbol: "lock.shield")
        add(menu, "Check Network Activity", #selector(checkNetwork), symbol: "network")

        menu.addItem(.separator())
        add(menu, "Open MacScan", #selector(openApp), symbol: "macwindow")
        add(menu, "Settings…", #selector(openSettings), symbol: "gearshape")
        menu.addItem(.separator())
        add(menu, "Quit MacScan", #selector(quit), symbol: "power")
    }

    @discardableResult
    private func add(_ menu: NSMenu, _ title: String, _ action: Selector?, symbol: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        // "blank" keeps the text lined up with the rows that have an icon.
        item.image = symbol == "blank"
            ? NSImage(size: NSSize(width: 16, height: 16))
            : NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        // macOS 27 hides menu icons unless asked to show them.
        if #available(macOS 27.0, *) { item.preferredImageVisibility = .visible }
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
