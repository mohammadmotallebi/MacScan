import MacScanCore
import SwiftUI

/// The Scan section before a result is open: how the Mac did last time, scan buttons and status cards.
struct HomeView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                if !state.fullDiskAccessLikelyGranted {
                    FullDiskAccessBanner()
                }
                HomeHero(status: state.menuBarStatus)
                ScanActionGrid()
                StatusCards()
                FoldersCard()
                Text("Tip: drop any file or folder onto this window to scan it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
            }
            .padding(24)
            .frame(maxWidth: 980)
            .frame(maxWidth: .infinity)
        }
        .background(HomeBackground(color: state.menuBarStatus.level.color))
    }
}

/// A soft wash of the status color behind the home screen, so the glass has something to show.
struct HomeBackground: View {
    let color: Color

    var body: some View {
        ZStack {
            Color(nsColor: .windowBackgroundColor)
            RadialGradient(colors: [color.opacity(0.22), .clear], center: .topLeading, startRadius: 40, endRadius: 620)
            RadialGradient(colors: [Color.purple.opacity(0.10), .clear], center: .bottomTrailing, startRadius: 40, endRadius: 700)
        }
        .ignoresSafeArea()
        .animation(.smooth(duration: 0.6), value: color)
    }
}

// MARK: - Hero

struct HomeHero: View {
    @Environment(AppState.self) private var state
    let status: MenuBarStatus

    var body: some View {
        HStack(spacing: 28) {
            StatusRing(color: status.level.color, symbol: status.level.symbol)
            VStack(alignment: .leading, spacing: 8) {
                Text(status.level.headline)
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                Text(status.title)
                    .font(.headline)
                    .foregroundStyle(.secondary)
                if let detail = status.detail {
                    Text(detail)
                        .font(.callout)
                        .foregroundStyle(status.level == .clear ? .secondary : status.level.color)
                }
                HStack(spacing: 10) {
                    Button {
                        state.scanFullCheck()
                    } label: {
                        Label("Run Full Check", systemImage: "checkmark.shield")
                            .font(.headline)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                    }
                    .buttonStyle(.glassProminent)
                    .controlSize(.extraLarge)
                    .help("Applications, startup items, running programs and browser extensions, plus security settings and privacy permissions.")

                    if let id = status.sessionID {
                        Button {
                            state.showSession(id)
                        } label: {
                            Label("See Last Result", systemImage: "list.bullet.rectangle")
                                .padding(.vertical, 4)
                        }
                        .buttonStyle(.glass)
                        .controlSize(.extraLarge)
                    }
                }
                .padding(.top, 8)
            }
            Spacer(minLength: 0)
        }
        .padding(28)
        .glassCard(tint: status.level == .unknown ? nil : status.level.color, radius: 26)
        .disabled(state.isScanning)
    }
}

// MARK: - Scan buttons

struct ScanActionGrid: View {
    @Environment(AppState.self) private var state

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle("Scan one area", trailing: AnyView(
                Toggle(isOn: Bindable(state).settings.elevatedScans) {
                    Label("As administrator", systemImage: "lock.open")
                        .font(.callout)
                }
                .toggleStyle(.switch)
                .controlSize(.small)
                .help("Asks for your password at the start of each scan, then reads files owned by other users and the system. Mail, Safari and other private data still need Full Disk Access.")))

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 210), spacing: 12)], spacing: 12) {
                ScanTile(title: "Applications", hint: "Every app on this Mac", symbol: "app.badge.checkmark", color: .blue) {
                    state.scanApplications()
                }
                ScanTile(title: "Startup Items", hint: "What starts on its own", symbol: "power", color: .orange) {
                    state.scanStartupItems()
                }
                ScanTile(title: "Running Programs", hint: "What's running right now", symbol: "cpu", color: .teal) {
                    state.scanRunningProcesses()
                }
                ScanTile(title: "Browser Extensions", hint: "Add-ons in your browsers", symbol: "puzzlepiece.extension.fill", color: .purple) {
                    state.scanBrowserExtensions()
                }
                ScanTile(title: "Saved Folders",
                         hint: state.customFolders.isEmpty ? "Add folders below first" : "\(state.customFolders.count) folder\(state.customFolders.count == 1 ? "" : "s")",
                         symbol: "folder.fill", color: .cyan) {
                    state.scanCustomFolders()
                }
                .disabled(state.customFolders.isEmpty)
                ScanTile(title: "File or Folder…", hint: "Pick anything to check", symbol: "doc.viewfinder", color: .gray) {
                    state.chooseAndScan()
                }
            }
        }
        .disabled(state.isScanning)
    }
}

struct ScanTile: View {
    let title: String
    let hint: String
    let symbol: String
    let color: Color
    let action: () -> Void
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                IconTile(symbol: symbol, color: isEnabled ? color : .gray, size: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.headline)
                    Text(hint).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.tertiary)
            }
            .padding(12)
            .contentShape(.rect(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .glassCard(radius: 16, interactive: true)
        .opacity(isEnabled ? 1 : 0.55)
    }
}

// MARK: - Status cards

struct StatusCards: View {
    @Environment(AppState.self) private var state
    @State private var showEngines = false

    private var lastFullCheck: FullCheckInfo? {
        state.history.first { $0.fullCheck != nil && $0.status == .completed }?.fullCheck
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle("Status")
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 12)], spacing: 12) {
                securityCard
                privacyCard
                networkCard
                StatusCard(title: "Quarantine", symbol: "archivebox.fill", color: .indigo,
                           value: state.quarantined.isEmpty ? "Empty" : "\(state.quarantined.count) item\(state.quarantined.count == 1 ? "" : "s")",
                           line: state.quarantined.isEmpty ? "Nothing locked away" : "Locked away safely") {
                    state.selectedSection = .quarantine
                }
                enginesCard
            }
        }
    }

    // Live result if the section was checked, else what the last Full Check saw.
    private var securityCard: some View {
        let live = state.security.checks
        let passed = live.isEmpty ? lastFullCheck?.security?.passed : state.security.count(.pass)
        let total = live.isEmpty ? lastFullCheck?.security?.total : live.count
        let color: Color = passed == nil ? .gray : passed == total ? .green : .orange
        return StatusCard(title: "Security", symbol: "lock.shield.fill", color: .blue,
                          value: passed.map { "\($0) of \(total ?? 0)" } ?? "Not checked",
                          line: passed == nil ? "Open to check" : passed == total ? "All settings pass" : "\((total ?? 0) - (passed ?? 0)) need a look",
                          lineColor: passed == nil || passed == total ? nil : .orange) {
            state.selectedSection = .security
            if live.isEmpty { state.security.refresh() }
        } accessory: {
            if let passed, let total, total > 0 { AnyView(DonutRing(good: passed, total: total, color: color)) } else { nil }
        }
    }

    private var privacyCard: some View {
        let summary = state.privacy.report.map(PrivacySummary.init(report:)) ?? lastFullCheck?.privacy
        let value: String
        let line: String
        var lineColor: Color?
        if let summary, summary.readable {
            value = "\(summary.apps) apps"
            if summary.warnings > 0 {
                line = "\(summary.warnings) risky permission\(summary.warnings == 1 ? "" : "s")"
                lineColor = .orange
            } else {
                line = summary.review > 0 ? "\(summary.review) worth a look" : "Nothing out of place"
            }
        } else if summary != nil {
            value = "Locked"
            line = "Needs Full Disk Access"
            lineColor = .orange
        } else {
            value = "Not checked"
            line = "Open to check"
        }
        return StatusCard(title: "Privacy", symbol: "hand.raised.fill", color: .pink,
                          value: value, line: line, lineColor: lineColor) {
            state.selectedSection = .privacy
            if state.privacy.report == nil { state.privacy.refresh() }
        }
    }

    private var networkCard: some View {
        let snapshot = state.network.snapshot
        let warnings = snapshot?.count(.warning) ?? 0
        return StatusCard(title: "Network", symbol: "network", color: .green,
                          value: snapshot.map { "\($0.apps.count) programs" } ?? "Not checked",
                          line: snapshot == nil ? "Open to check" : warnings > 0 ? "\(warnings) worth a look" : "Nothing odd",
                          lineColor: warnings > 0 ? .orange : nil) {
            state.selectedSection = .network
            if snapshot == nil { state.network.refresh() }
        }
    }

    private var enginesCard: some View {
        // VirusTotal is optional, so it doesn't count as needing setup.
        let engines: [EngineID] = [.clamav, .yara, .integrity, .persistence, .processes, .extensions]
        let problems = engines.filter {
            switch state.engineStatus[$0] {
            case .notInstalled, .needsSetup: true
            default: false
            }
        }.count
        let ready = engines.filter { state.engineStatus[$0]?.isAvailable == true }.count
        return StatusCard(title: "Engines", symbol: "gearshape.2.fill", color: .gray,
                          value: "\(ready) of \(engines.count) on",
                          line: problems == 0 ? "All ready" : "\(problems) need\(problems == 1 ? "s" : "") setup",
                          lineColor: problems == 0 ? nil : .orange) {
            showEngines.toggle()
        }
        .popover(isPresented: $showEngines, arrowEdge: .bottom) {
            EnginesPopover()
        }
    }
}

struct StatusCard: View {
    let title: String
    let symbol: String
    let color: Color
    let value: String
    let line: String
    var lineColor: Color?
    let action: () -> Void
    var accessory: () -> AnyView? = { nil }

    init(title: String, symbol: String, color: Color, value: String, line: String, lineColor: Color? = nil,
         action: @escaping () -> Void, accessory: @escaping () -> AnyView? = { nil }) {
        self.title = title
        self.symbol = symbol
        self.color = color
        self.value = value
        self.line = line
        self.lineColor = lineColor
        self.action = action
        self.accessory = accessory
    }

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top) {
                    IconTile(symbol: symbol, color: color, size: 30)
                    Spacer()
                    accessory()
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary).textCase(.uppercase)
                    Text(value).font(.title3.weight(.semibold)).lineLimit(1)
                    Text(line).font(.caption).foregroundStyle(lineColor.map { AnyShapeStyle($0) } ?? AnyShapeStyle(.secondary)).lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 104, alignment: .topLeading)
            .padding(14)
            .contentShape(.rect(cornerRadius: 18))
        }
        .buttonStyle(.plain)
        .glassCard(interactive: true)
    }
}

struct EnginesPopover: View {
    @Environment(AppState.self) private var state

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Engines").font(.headline)
            EngineStatusRow(engine: .clamav)
            Button {
                state.updateDatabase()
            } label: {
                Label(state.freshclam?.running == true ? "Updating…" : "Update virus database", systemImage: "arrow.down.circle")
            }
            .controlSize(.small)
            .disabled(state.isScanning)
            .padding(.leading, 22)
            Divider()
            ForEach([EngineID.yara, .integrity, .persistence, .processes, .extensions, .virustotal], id: \.self) {
                EngineStatusRow(engine: $0)
            }
        }
        .padding(16)
        .frame(width: 340)
    }
}

// MARK: - Folders and banner

struct FoldersCard: View {
    @Environment(AppState.self) private var state

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle("Saved folders", trailing: AnyView(
                Button {
                    state.addFolders()
                } label: {
                    Label("Add Folder…", systemImage: "plus")
                }
                .buttonStyle(.glass)
                .controlSize(.small)))
            VStack(alignment: .leading, spacing: 0) {
                if state.customFolders.isEmpty {
                    Text("No folders yet. Add the ones you want “Saved Folders” to check.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .padding(14)
                }
                ForEach(Array(state.customFolders.enumerated()), id: \.element) { index, url in
                    if index > 0 { Divider().padding(.leading, 52) }
                    HStack(spacing: 12) {
                        IconTile(symbol: "folder.fill", color: .cyan, size: 26)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(url.lastPathComponent).lineLimit(1)
                            Text((url.path as NSString).abbreviatingWithTildeInPath)
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        Button {
                            state.scan(urls: [url])
                        } label: {
                            Image(systemName: "play.fill")
                        }
                        .buttonStyle(.borderless)
                        .disabled(state.isScanning)
                        .help("Scan only this folder")
                        Button {
                            state.removeFolder(url)
                        } label: {
                            Image(systemName: "minus.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .help("Remove from the list (the folder isn't touched)")
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 9)
                    .contextMenu {
                        Button("Scan Only This Folder") { state.scan(urls: [url]) }
                        Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                        Divider()
                        Button("Remove from List") { state.removeFolder(url) }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassCard(radius: 16)
        }
    }
}

struct FullDiskAccessBanner: View {
    @Environment(AppState.self) private var state

    var body: some View {
        HStack(spacing: 12) {
            IconTile(symbol: "lock.trianglebadge.exclamationmark.fill", color: .orange, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text("Full Disk Access is off").font(.headline)
                Text("Some private folders (Mail, Safari, other apps' data) can't be checked.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Button("How to Turn It On…") { state.fdaPrompt = FDAPrompt(paths: []) }
                .buttonStyle(.glass)
        }
        .padding(14)
        .glassCard(tint: .orange, radius: 16)
    }
}
