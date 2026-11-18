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
                guard !state.isScanning else { return false }
                state.scan(urls: urls)
                return true
            } isTargeted: { dropTargeted = $0 }
            .overlay {
                if dropTargeted { DropOverlay(isScanning: state.isScanning, uninstallMode: state.selectedSection == .uninstall) }
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

    private var blocked: Bool { isScanning && !uninstallMode }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 16)
                .fill(.background.opacity(0.85))
            RoundedRectangle(cornerRadius: 16)
                .strokeBorder(style: StrokeStyle(lineWidth: 3, dash: [10, 6]))
                .foregroundStyle(blocked ? Color.secondary : Color.accentColor)
            VStack(spacing: 12) {
                Image(systemName: blocked ? "hourglass" : (uninstallMode ? "trash.square" : "arrow.down.doc"))
                    .font(.system(size: 48, weight: .light))
                Text(blocked ? "A scan is already running" : (uninstallMode ? "Drop an app to uninstall" : "Drop to scan"))
                    .font(.title2.weight(.semibold))
            }
            .foregroundStyle(blocked ? Color.secondary : Color.accentColor)
        }
        .padding(24)
        .allowsHitTesting(false)
    }
}
