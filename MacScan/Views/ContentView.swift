import MacScanCore
import SwiftUI

struct ContentView: View {
    @Environment(AppState.self) private var state
    @State private var dropTargeted = false

    var body: some View {
        @Bindable var state = state
        NavigationSplitView {
            // The selection value (tag) must be the OUTERMOST modifier on each row:
            // a modifier applied after it (e.g. .badge) hides it, and clicks then select nothing.
            List(selection: $state.selectedSection) {
                Label("Scan", systemImage: "magnifyingglass")
                    .tag(AppSection.scan)
                Label("History", systemImage: "clock.arrow.circlepath")
                    .badge(state.history.count)
                    .tag(AppSection.history)
                Label("Uninstall", systemImage: "trash.square")
                    .tag(AppSection.uninstall)
                Label("Disk Usage", systemImage: "chart.bar.doc.horizontal")
                    .tag(AppSection.diskUsage)
                Label("Security", systemImage: "lock.shield")
                    .tag(AppSection.security)
                Label("Privacy", systemImage: "hand.raised")
                    .tag(AppSection.privacy)
                Label("Quarantine", systemImage: "archivebox")
                    .badge(state.quarantined.count)
                    .tag(AppSection.quarantine)
            }
            .navigationSplitViewColumnWidth(min: 150, ideal: 170, max: 220)
            .onChange(of: state.selectedSection) { _, newValue in
                // Clicking empty sidebar space deselects; keep a section selected.
                if newValue == nil { state.selectedSection = .scan }
            }
        } detail: {
            // The drop target lives on the detail area only: on macOS a drop destination that
            // covers the sidebar List can swallow its row clicks.
            Group {
                switch state.selectedSection ?? .scan {
                case .scan: ScanView()
                case .history: HistoryView()
                case .uninstall: UninstallView()
                case .diskUsage: DiskUsageView()
                case .security: SecurityView()
                case .privacy: PrivacyView()
                case .quarantine: QuarantineView()
                }
            }
            .dropDestination(for: URL.self) { urls, _ in
                guard !urls.isEmpty else { return false }
                // In the Uninstall section a dropped app opens in the uninstaller instead of being scanned.
                if state.selectedSection == .uninstall {
                    guard let app = urls.first(where: { $0.pathExtension.lowercased() == "app" }) else { return false }
                    state.uninstall.open(app)
                    return true
                }
                // In Disk Usage a dropped folder is measured.
                if state.selectedSection == .diskUsage {
                    guard !state.diskUsage.isScanning,
                          let folder = urls.first(where: { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }) else { return false }
                    state.diskUsage.scan(folder)
                    return true
                }
                // These sections have nothing to drop onto.
                if [.security, .privacy, .quarantine].contains(state.selectedSection) { return false }
                guard !state.isScanning else { return false }
                state.scan(urls: urls)
                return true
            } isTargeted: { dropTargeted = $0 }
            .overlay {
                if dropTargeted {
                    DropOverlay(isScanning: state.selectedSection == .diskUsage ? state.diskUsage.isScanning : state.isScanning,
                                uninstallMode: state.selectedSection == .uninstall,
                                measureMode: state.selectedSection == .diskUsage)
                }
            }
        }
        .sheet(item: $state.fdaPrompt) { prompt in
            FullDiskAccessSheet(paths: prompt.paths)
        }
        .sheet(item: $state.installHelp) { engine in
            InstallHelpSheet(engine: engine)
        }
        .sheet(isPresented: $state.showFreshclam) {
            FreshclamSheet()
        }
        .confirmationDialog(
            "Move to Trash?",
            isPresented: Binding(get: { state.pendingTrash != nil }, set: { if !$0 { state.pendingTrash = nil } }),
            presenting: state.pendingTrash
        ) { pending in
            Button("Move “\(pending.finding.fileName)” to Trash", role: .destructive) {
                state.confirmTrash(pending)
            }
            Button("Cancel", role: .cancel) {}
        } message: { pending in
            Text("\(pending.finding.path)\n\nThe item goes to the Trash, where you can restore it. MacScan never deletes anything permanently.")
        }
        .confirmationDialog(
            "Move to quarantine?",
            isPresented: Binding(get: { state.pendingQuarantine != nil }, set: { if !$0 { state.pendingQuarantine = nil } }),
            presenting: state.pendingQuarantine
        ) { pending in
            Button("Quarantine “\(pending.finding.fileName)”") {
                state.confirmQuarantine(pending)
            }
            Button("Cancel", role: .cancel) {}
        } message: { pending in
            Text("\(pending.finding.path)\n\nThe item is moved into MacScan's quarantine and locked, so it can't run or be opened. You can put it back exactly where it was from the Quarantine section.")
        }
        .confirmationDialog(
            "Delete permanently?",
            isPresented: Binding(get: { state.pendingQuarantineDelete != nil }, set: { if !$0 { state.pendingQuarantineDelete = nil } }),
            presenting: state.pendingQuarantineDelete
        ) { pending in
            Button(pending.items.count == 1 ? "Delete “\(pending.items[0].name)” Permanently" : "Delete \(pending.items.count) Items Permanently", role: .destructive) {
                state.confirmQuarantineDelete(pending)
            }
            Button("Cancel", role: .cancel) {}
        } message: { pending in
            Text(pending.items.count == 1
                 ? "\(pending.items[0].originalPath)\n\nThis can't be undone: the item does not go to the Trash."
                 : "Everything in quarantine is deleted. This can't be undone: the items do not go to the Trash.")
        }
        .confirmationDialog(
            "Remove orphaned startup item?",
            isPresented: Binding(get: { state.pendingOrphanRemoval != nil }, set: { if !$0 { state.pendingOrphanRemoval = nil } }),
            presenting: state.pendingOrphanRemoval
        ) { pending in
            Button("Stop and Move to Trash", role: .destructive) {
                state.confirmOrphanRemoval(pending)
            }
            Button("Cancel", role: .cancel) {}
        } message: { pending in
            Text("\(pending.item.displayName) starts a program that no longer exists:\n\(pending.item.missingProgram)\n\nMacScan stops it and moves \(pending.item.plist.lastPathComponent) to the Trash, where you can restore it.\(pending.item.requiresAdmin ? " macOS will ask for your administrator password." : "")")
        }
        .alert(
            state.alert?.title ?? "",
            isPresented: Binding(get: { state.alert != nil }, set: { if !$0 { state.alert = nil } }),
            presenting: state.alert
        ) { _ in
            Button("OK") {}
        } message: { alert in
            Text(alert.message)
        }
    }
}

struct DropOverlay: View {
    let isScanning: Bool
    var uninstallMode = false
    var measureMode = false

    private var blocked: Bool { isScanning && !uninstallMode }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 16)
                .fill(.background.opacity(0.85))
            RoundedRectangle(cornerRadius: 16)
                .strokeBorder(style: StrokeStyle(lineWidth: 3, dash: [10, 6]))
                .foregroundStyle(blocked ? Color.secondary : Color.accentColor)
            VStack(spacing: 12) {
                Image(systemName: blocked ? "hourglass" : (uninstallMode ? "trash.square" : (measureMode ? "chart.bar.doc.horizontal" : "arrow.down.doc")))
                    .font(.system(size: 48, weight: .light))
                Text(blocked ? (measureMode ? "Already measuring" : "A scan is already running")
                     : (uninstallMode ? "Drop an app to uninstall" : (measureMode ? "Drop a folder to measure" : "Drop to scan")))
                    .font(.title2.weight(.semibold))
            }
            .foregroundStyle(blocked ? Color.secondary : Color.accentColor)
        }
        .padding(24)
        .allowsHitTesting(false)
    }
}
