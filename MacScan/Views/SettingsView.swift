import MacScanCore
import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem { Label("General", systemImage: "gearshape") }
            EngineSettingsView()
                .tabItem { Label("Engines", systemImage: "cpu") }
            VirusTotalSettingsView()
                .tabItem { Label("VirusTotal", systemImage: "network") }
            PrivacySettingsView()
                .tabItem { Label("Privacy", systemImage: "lock.shield") }
            IgnoredSettingsView()
                .tabItem { Label("Ignored", systemImage: "eye.slash") }
        }
        .frame(width: 640, height: 480)
    }
}

// MARK: - General

struct GeneralSettingsView: View {
    @Environment(AppState.self) private var state
    @State private var selectedExclusion: String?

    var body: some View {
        @Bindable var state = state
        Form {
            Section("Limits") {
                HStack {
                    TextField("Maximum file size", value: $state.settings.maxFileSizeMB, format: .number)
                        .frame(width: 220)
                    Stepper("MB", value: $state.settings.maxFileSizeMB, in: 1...4096, step: 25)
                }
                Text("Larger files are skipped and counted in the scan details.")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Skip symbolic links", isOn: $state.settings.skipSymlinks)
                Text("When off, links to files are scanned at their destination. Linked folders are never followed.")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Applications scan: only executables and scripts (faster)", isOn: $state.settings.appScanExecutablesOnly)
                Text("When off, every file inside each .app bundle is scanned (images, resources, …).")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Excluded paths") {
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
            Section("Enabled engines") {
                Toggle("ClamAV signature scanning", isOn: $state.settings.enableClamAV)
                Toggle("YARA rules", isOn: $state.settings.enableYara)
                Toggle("App integrity (codesign, Gatekeeper, quarantine)", isOn: $state.settings.enableIntegrity)
            }

            Section("Tool locations") {
                ToolPathField(title: "clamscan", tool: .clamscan, value: optionalBinding(\.clamscanPath))
                ToolPathField(title: "freshclam", tool: .freshclam, value: optionalBinding(\.freshclamPath))
                ToolPathField(title: "yara", tool: .yara, value: optionalBinding(\.yaraPath))
                ToolPathField(title: "yarac", tool: .yarac, value: optionalBinding(\.yaracPath))
                Text("Leave empty to auto-detect Homebrew locations (/opt/homebrew/bin, /usr/local/bin).")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("ClamAV database") {
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
            }

            Section("YARA rules") {
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
            }
        }
        .formStyle(.grouped)
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
            Section("API key") {
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
            }
            Section("Lookups") {
                Toggle("Automatically look up flagged files after each scan", isOn: $state.settings.vtAutoLookupFlagged)
                    .disabled(!state.hasVirusTotalKey)
                Text("""
                Only the SHA-256 hash of a file is sent to VirusTotal. Files are never uploaded. \
                Free keys allow 4 lookups per minute, so MacScan spaces requests 15 seconds apart. \
                You can also look up any single result from its context menu.
                """)
                .font(.caption).foregroundStyle(.secondary)
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
            Section("Full Disk Access") {
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
            }
            Section("Logs") {
                LabeledContent("Log file") {
                    Text(FileLogger.shared.fileURL.path).font(.caption.monospaced()).textSelection(.enabled)
                }
                Button("Show Log in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([FileLogger.shared.fileURL])
                }
            }
            Section("Background activity") {
                Text("MacScan has no launch agents, daemons, login items, menu bar helpers or extensions. When you quit it, every scan and helper process stops.")
                    .font(.callout)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Ignored

struct IgnoredSettingsView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        VStack(alignment: .leading) {
            Text("Ignored results are hidden from future scans until the file's contents change.")
                .font(.callout).foregroundStyle(.secondary)
            Table(state.ignoreList.entries) {
                TableColumn("Path") { e in Text(e.path).lineLimit(1).truncationMode(.middle).help(e.path) }
                TableColumn("Engine") { e in Text(e.engine.title) }.width(90)
                TableColumn("Reason") { e in Text(e.reason).lineLimit(1).help(e.reason) }
                TableColumn("") { e in
                    Button("Unignore") { state.unignore(e) }.controlSize(.small)
                }
                .width(80)
            }
            .overlay {
                if state.ignoreList.entries.isEmpty {
                    ContentUnavailableView("Nothing ignored", systemImage: "eye")
                }
            }
        }
        .padding()
    }
}
