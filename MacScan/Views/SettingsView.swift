import MacScanCore
import SwiftUI

/// Settings, laid out like System Settings: a sidebar of colored icons and a grouped form.
struct SettingsView: View {
    enum Pane: String, CaseIterable, Identifiable {
        case general = "General", engines = "Engines", background = "Background"
        case virusTotal = "VirusTotal", privacy = "Privacy", ignored = "Ignored"

        var id: String { rawValue }

        var symbol: String {
            switch self {
            case .general: "gearshape.fill"
            case .engines: "cpu.fill"
            case .background: "clock.arrow.circlepath"
            case .virusTotal: "globe"
            case .privacy: "hand.raised.fill"
            case .ignored: "eye.slash.fill"
            }
        }

        var color: Color {
            switch self {
            case .general: .gray
            case .engines: .blue
            case .background: .orange
            case .virusTotal: .indigo
            case .privacy: .pink
            case .ignored: .teal
            }
        }
    }

    @State private var pane: Pane = .general

    var body: some View {
        NavigationSplitView {
            List(Pane.allCases, selection: $pane) { pane in
                Label {
                    Text(pane.rawValue)
                } icon: {
                    IconTile(symbol: pane.symbol, color: pane.color, size: 22)
                }
                .tag(pane)
            }
            .navigationSplitViewColumnWidth(170)
            .toolbar(removing: .sidebarToggle)
        } detail: {
            Group {
                switch pane {
                case .general: GeneralSettingsView()
                case .engines: EngineSettingsView()
                case .background: BackgroundSettingsView()
                case .virusTotal: VirusTotalSettingsView()
                case .privacy: PrivacySettingsView()
                case .ignored: IgnoredSettingsView()
                }
            }
            .navigationTitle(pane.rawValue)
        }
        .frame(width: 780, height: 540)
    }
}

/// A form section title with a small colored icon.
struct SettingsHeader: View {
    let title: String
    let symbol: String
    let color: Color

    var body: some View {
        Label {
            Text(title).font(.headline).foregroundStyle(.primary)
        } icon: {
            IconTile(symbol: symbol, color: color, size: 20)
        }
        .textCase(nil)
    }
}

/// A short grey hint under a setting.
struct SettingsHint: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}

// MARK: - General

struct GeneralSettingsView: View {
    @Environment(AppState.self) private var state
    @State private var selectedExclusion: String?

    var body: some View {
        @Bindable var state = state
        Form {
            Section {
                Toggle("Show MacScan in the menu bar", isOn: $state.settings.showInMenuBar)
                SettingsHint("MacScan's icon shows the last Full Check, and its menu can start one. While this is on, closing the window keeps MacScan running in the menu bar, and only Quit MacScan (in that menu, or ⌘Q) closes it.")
            } header: {
                SettingsHeader(title: "Menu bar", symbol: "menubar.rectangle", color: .blue)
            }

            Section {
                HStack {
                    TextField("Maximum file size", value: $state.settings.maxFileSizeMB, format: .number)
                        .frame(width: 220)
                    Stepper("MB", value: $state.settings.maxFileSizeMB, in: 1...4096, step: 25)
                }
                SettingsHint("Larger files are skipped and counted in the scan details.")
                Toggle("Skip symbolic links", isOn: $state.settings.skipSymlinks)
                SettingsHint("When off, links to files are scanned at their destination. Linked folders are never followed.")
                Toggle("Applications scan: only executables and scripts (faster)", isOn: $state.settings.appScanExecutablesOnly)
                SettingsHint("When off, every file inside each .app bundle is scanned (images, resources, …).")
            } header: {
                SettingsHeader(title: "Limits", symbol: "gauge.with.dots.needle.50percent", color: .orange)
            }

            Section {
                List(selection: $selectedExclusion) {
                    ForEach(state.settings.excludedPaths, id: \.self) { path in
                        Text(path).font(.callout.monospaced()).tag(path)
                    }
                }
                .frame(minHeight: 100)
                HStack {
                    Button("Add…") { addExclusion() }
                    Button("Remove") {
                        if let s = selectedExclusion {
                            state.settings.excludedPaths.removeAll { $0 == s }
                            selectedExclusion = nil
                        }
                    }
                    .disabled(selectedExclusion == nil)
                }
            } header: {
                SettingsHeader(title: "Excluded paths", symbol: "nosign", color: .red)
            }
        }
        .formStyle(.grouped)
    }

    private func addExclusion() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Exclude"
        guard panel.runModal() == .OK else { return }
        for url in panel.urls where !state.settings.excludedPaths.contains(url.path) {
            state.settings.excludedPaths.append(url.path)
        }
    }
}

// MARK: - Engines

struct EngineSettingsView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        @Bindable var state = state
        Form {
            Section {
                engineToggle("ClamAV signature scanning", .clamav, $state.settings.enableClamAV)
                engineToggle("YARA rules", .yara, $state.settings.enableYara)
                engineToggle("App integrity (codesign, Gatekeeper, quarantine)", .integrity, $state.settings.enableIntegrity)
            } header: {
                SettingsHeader(title: "Engines", symbol: "cpu.fill", color: .blue)
            }

            Section {
                ToolPathField(title: "clamscan", tool: .clamscan, value: optionalBinding(\.clamscanPath))
                ToolPathField(title: "freshclam", tool: .freshclam, value: optionalBinding(\.freshclamPath))
                ToolPathField(title: "yara", tool: .yara, value: optionalBinding(\.yaraPath))
                ToolPathField(title: "yarac", tool: .yarac, value: optionalBinding(\.yaracPath))
                SettingsHint("Leave empty to auto-detect Homebrew locations (/opt/homebrew/bin, /usr/local/bin).")
            } header: {
                SettingsHeader(title: "Tool locations", symbol: "wrench.and.screwdriver.fill", color: .gray)
            }

            Section {
                LabeledContent("In use") {
                    Text(ClamAVDatabase.resolve(override: state.settings.clamDatabasePath).path)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                HStack {
                    TextField("Custom database folder (optional)", text: optionalBinding(\.clamDatabasePath))
                    Button("Choose…") {
                        if let url = chooseFolder() { state.settings.clamDatabasePath = url.path }
                    }
                }
            } header: {
                SettingsHeader(title: "ClamAV database", symbol: "cylinder.split.1x2.fill", color: .green)
            }

            Section {
                LabeledContent("Rules folder") {
                    Text(state.settings.yaraRulesFolder ?? "Bundled sample rules")
                        .font(.caption.monospaced())
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                HStack {
                    Button("Choose Folder…") {
                        if let url = chooseFolder() { state.settings.yaraRulesFolder = url.path }
                    }
                    Button("Use Bundled Sample Rules") { state.settings.yaraRulesFolder = nil }
                        .disabled(state.settings.yaraRulesFolder == nil)
                    Button("Show Sample Rules") {
                        if let url = YaraEngine.bundledRulesFolder {
                            NSWorkspace.shared.activateFileViewerSelecting([url])
                        }
                    }
                }
                Text("All .yar/.yara files in the folder (including subfolders) are compiled together. Optional meta fields: description, severity = \"threat\" | \"warning\".")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Also use Apple's XProtect rules", isOn: $state.settings.useXProtectRules)
                Text("macOS ships its own malware YARA rules (XProtect) and keeps them updated. MacScan reads them in place\(YaraEngine.xprotectRuleCount().map { " — currently \($0) rules" } ?? ""). A match is reported as a Threat.")
                    .font(.caption).foregroundStyle(.secondary)
            } header: {
                SettingsHeader(title: "YARA rules", symbol: "list.bullet.rectangle.fill", color: .purple)
            }
        }
        .formStyle(.grouped)
    }

    private func engineToggle(_ title: String, _ engine: EngineID, _ isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            HStack(spacing: 8) {
                Text(title)
                switch state.engineStatus[engine] {
                case .available: CountChip(symbol: "checkmark.circle.fill", text: "Ready", color: .green)
                case .notInstalled: CountChip(symbol: "xmark.circle.fill", text: "Not installed", color: .red)
                case .needsSetup: CountChip(symbol: "exclamationmark.circle.fill", text: "Needs setup", color: .orange)
                case .disabled, nil: EmptyView()
                }
            }
        }
    }

    private func optionalBinding(_ keyPath: WritableKeyPath<ScanSettings, String?>) -> Binding<String> {
        Binding(
            get: { state.settings[keyPath: keyPath] ?? "" },
            set: { state.settings[keyPath: keyPath] = $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0 }
        )
    }

    private func chooseFolder() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url : nil
    }
}

struct ToolPathField: View {
    let title: String
    let tool: ExternalTool
    @Binding var value: String

    var body: some View {
        let detected = ToolLocator.autodetect(tool)
        let resolved = ToolLocator.locate(tool, override: value)
        HStack {
            Text(title).frame(width: 70, alignment: .leading)
            TextField(detected ?? "not found", text: $value)
                .font(.callout.monospaced())
            Image(systemName: resolved != nil ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(resolved != nil ? .green : .red)
                .help(resolved?.path ?? "Not found")
            Button("Choose…") {
                let panel = NSOpenPanel()
                panel.canChooseFiles = true
                panel.canChooseDirectories = false
                panel.directoryURL = URL(fileURLWithPath: "/opt/homebrew/bin")
                if panel.runModal() == .OK, let url = panel.url { value = url.path }
            }
            Button("Detect") { value = "" }
                .help("Clear the override and auto-detect")
        }
    }
}

// MARK: - VirusTotal

struct VirusTotalSettingsView: View {
    @Environment(AppState.self) private var state
    @State private var keyInput = ""

    var body: some View {
        @Bindable var state = state
        Form {
            Section {
                if state.hasVirusTotalKey {
                    LabeledContent("Status") {
                        Label("Key saved in your login keychain", systemImage: "key.fill").foregroundStyle(.green)
                    }
                    Button("Remove Key", role: .destructive) { state.saveVirusTotalKey("") }
                } else {
                    SecureField("Paste your VirusTotal API key", text: $keyInput)
                    Button("Save Key") {
                        state.saveVirusTotalKey(keyInput)
                        keyInput = ""
                    }
                    .disabled(keyInput.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                Link("Get a free API key at virustotal.com", destination: URL(string: "https://www.virustotal.com/gui/my-apikey")!)
                    .font(.caption)
            } header: {
                SettingsHeader(title: "API key", symbol: "key.fill", color: .yellow)
            }
            Section {
                Toggle("Automatically look up flagged files after each scan", isOn: $state.settings.vtAutoLookupFlagged)
                    .disabled(!state.hasVirusTotalKey)
                Text("""
                Only the SHA-256 hash of a file is sent to VirusTotal. Files are never uploaded. \
                Free keys allow 4 lookups per minute, so MacScan spaces requests 15 seconds apart. \
                You can also look up any single result from its context menu.
                """)
                .font(.caption).foregroundStyle(.secondary)
            } header: {
                SettingsHeader(title: "Lookups", symbol: "magnifyingglass", color: .indigo)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Background scans

struct BackgroundSettingsView: View {
    @Environment(AppState.self) private var state

    /// 1 = Monday … 7 = Sunday, as stored in the settings.
    private func weekdayName(_ day: Int) -> String {
        Calendar.current.weekdaySymbols[day % 7]   // weekdaySymbols starts with Sunday
    }

    private var scheduleTime: Binding<Date> {
        Binding {
            Calendar.current.date(bySettingHour: state.settings.scheduleHour, minute: state.settings.scheduleMinute, second: 0, of: Date()) ?? Date()
        } set: { date in
            let parts = Calendar.current.dateComponents([.hour, .minute], from: date)
            state.settings.scheduleHour = parts.hour ?? 12
            state.settings.scheduleMinute = parts.minute ?? 0
        }
    }

    var body: some View {
        @Bindable var state = state
        Form {
            Section {
                Toggle("Scan on a schedule", isOn: $state.settings.scheduledScanEnabled)
                if state.settings.scheduledScanEnabled {
                    Picker("Repeat", selection: $state.settings.scheduleFrequency) {
                        ForEach(ScheduleFrequency.allCases) { Text($0.title).tag($0) }
                    }
                    if state.settings.scheduleFrequency == .weekly {
                        Picker("Day", selection: $state.settings.scheduleWeekday) {
                            ForEach(1...7, id: \.self) { Text(weekdayName($0)).tag($0) }
                        }
                    }
                    DatePicker("Time", selection: scheduleTime, displayedComponents: .hourAndMinute)
                    Picker("What to scan", selection: $state.settings.scheduledFullCheck) {
                        Text("Full Check").tag(true)
                        Text("Applications and Startup Items only").tag(false)
                    }
                }
                Text(state.settings.scheduledFullCheck
                     ? "Runs a Full Check (plus your scan folders) and tells you what changed since the last one: new apps, new permissions, settings that got worse. It runs while you're logged in; a scan missed while the Mac was asleep runs after it wakes."
                     : "Scans Applications, Startup Items and your scan folders. It runs while you're logged in; a scan missed while the Mac was asleep runs after it wakes.")
                    .font(.caption).foregroundStyle(.secondary)
            } header: {
                SettingsHeader(title: "Scheduled scan", symbol: "calendar.badge.clock", color: .orange)
            }

            Section {
                Toggle("Scan new downloads", isOn: $state.settings.watchDownloads)
                SettingsHint("When something new arrives in your Downloads folder, MacScan scans just that item. Items that are already there are not scanned.")
            } header: {
                SettingsHeader(title: "Downloads", symbol: "arrow.down.circle.fill", color: .blue)
            }

            Section {
                LabeledContent("Status") {
                    switch state.notificationPermission {
                    case .allowed: Label("Allowed", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    case .denied: Label("Turned off for MacScan", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    case .notAsked: Text("Not set up yet").foregroundStyle(.secondary)
                    }
                }
                HStack {
                    Button("Send Test Notification") { state.sendTestNotification() }
                        .disabled(state.testNotificationInFlight)
                    if state.notificationPermission == .denied {
                        Button("Open Notification Settings") {
                            if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") {
                                NSWorkspace.shared.open(url)
                            }
                        }
                    }
                }
                SettingsHint("A notification appears only when a background scan finds something new. Every background scan is also saved in History. MacScan never moves or deletes anything on its own.")
            } header: {
                SettingsHeader(title: "Notifications", symbol: "bell.badge.fill", color: .red)
            }

            Section {
                if let error = state.backgroundError {
                    Label(error, systemImage: "xmark.octagon.fill").foregroundStyle(.red).font(.callout)
                    Button("Try Again") { state.syncBackgroundAgent() }
                }
                SettingsHint("macOS starts MacScan for each background scan and MacScan exits when the scan ends, so nothing stays running in between. While either option is on, MacScan appears in System Settings › General › Login Items and in its own Startup Items scan. Turning both off removes its launch agents. Background scans never run as administrator.")
            } header: {
                SettingsHeader(title: "How it works", symbol: "info.circle.fill", color: .gray)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Privacy

struct PrivacySettingsView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        Form {
            Section {
                LabeledContent("Status") {
                    if state.fullDiskAccessLikelyGranted {
                        Label("Granted", systemImage: "checkmark.shield.fill").foregroundStyle(.green)
                    } else {
                        Label("Not granted", systemImage: "exclamationmark.shield.fill").foregroundStyle(.orange)
                    }
                }
                FullDiskAccessSteps()
                HStack {
                    Button("Open Full Disk Access Settings") { FullDiskAccess.openSettings() }
                    Button("Check Again") { state.refreshEngineStatus() }
                }
            } header: {
                SettingsHeader(title: "Full Disk Access", symbol: "lock.shield.fill", color: .pink)
            }
            Section {
                LabeledContent("Log file") {
                    Text(FileLogger.shared.fileURL.path).font(.caption.monospaced()).textSelection(.enabled)
                }
                Button("Show Log in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([FileLogger.shared.fileURL])
                }
            } header: {
                SettingsHeader(title: "Logs", symbol: "doc.text.fill", color: .gray)
            }
            Section {
                if state.settings.backgroundScansEnabled {
                    Text("Background scans are on (Settings › Background). macOS starts MacScan for each scan through MacScan's own launch agent, and MacScan exits when the scan ends. Nothing else runs in the background: no daemons, menu bar helpers or extensions.")
                        .font(.callout)
                } else {
                    Text("MacScan has no launch agents, daemons, login items, menu bar helpers or extensions. When you quit it, every scan and helper process stops. Scheduled scans and scanning new downloads are optional and off (Settings › Background).")
                        .font(.callout)
                }
            } header: {
                SettingsHeader(title: "Background activity", symbol: "moon.zzz.fill", color: .indigo)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Ignored

struct IgnoredSettingsView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if state.ignoreList.entries.isEmpty {
                SectionEmptyState(symbol: "eye.slash.fill", color: .teal, title: "Nothing ignored",
                                  message: "Choose Ignore on a scan result to hide it from future scans. It comes back if the file's contents change.")
            } else {
                Text("Ignored results are hidden from future scans until the file's contents change.")
                    .font(.callout).foregroundStyle(.secondary)
                Table(state.ignoreList.entries) {
                    TableColumn("Path") { e in
                        HStack(spacing: 6) {
                            FileIcon(path: e.path, size: 18)
                            Text(e.path).lineLimit(1).truncationMode(.middle).help(e.path)
                        }
                    }
                    TableColumn("Engine") { e in Text(e.engine.title) }.width(90)
                    TableColumn("Reason") { e in Text(e.reason).lineLimit(1).help(e.reason) }
                    TableColumn("") { e in
                        Button("Unignore") { state.unignore(e) }
                            .buttonStyle(.glass)
                            .controlSize(.small)
                    }
                    .width(90)
                }
            }
        }
        .padding()
    }
}
