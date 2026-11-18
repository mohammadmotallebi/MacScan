import MacScanCore
import SwiftUI

struct FullDiskAccessSteps: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("1. Open **System Settings › Privacy & Security › Full Disk Access**.")
            Text("2. Click **+**, choose **MacScan** (or drag MacScan.app into the list).")
            Text("3. Turn the switch next to MacScan **on**.")
            Text("4. Quit and reopen MacScan so the change takes effect.")
        }
        .font(.callout)
    }
}

struct FullDiskAccessSheet: View {
    @Environment(\.dismiss) private var dismiss
    let paths: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("MacScan needs Full Disk Access", systemImage: "lock.shield")
                .font(.title2.weight(.semibold))
            Text(paths.isEmpty
                 ? "macOS protects some folders (Mail, Messages, Safari, other apps' data). Without Full Disk Access MacScan can't read them."
                 : "macOS refused access to \(paths.count) location(s). Folders like Mail, Messages, Safari and other apps' containers are protected and can only be scanned with Full Disk Access.")
                .fixedSize(horizontal: false, vertical: true)

            GroupBox {
                FullDiskAccessSteps()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
            }

            HStack(spacing: 6) {
                Image(systemName: "info.circle").foregroundStyle(.secondary)
                Text("This copy of MacScan is at: ")
                    .foregroundStyle(.secondary)
                + Text(Bundle.main.bundlePath).font(.caption.monospaced())
            }
            .font(.caption)
            .textSelection(.enabled)

            if !paths.isEmpty {
                DisclosureGroup("Unreadable locations (\(paths.count))") {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(paths.prefix(200), id: \.self) { p in
                                Text(p).font(.caption.monospaced()).textSelection(.enabled)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 120)
                }
            }

            HStack {
                Button("Reveal MacScan in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
                }
                Spacer()
                Button("Not Now") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Open System Settings") {
                    FullDiskAccess.openSettings()
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 560)
    }
}

struct InstallHelpSheet: View {
    @Environment(\.dismiss) private var dismiss
    let engine: EngineID

    private var command: String {
        engine == .yara ? "brew install yara" : "brew install clamav"
    }

    private var text: String {
        engine == .yara ? YaraEngine.installInstructions : ClamAVEngine.installInstructions
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("\(engine.title) is not installed", systemImage: "shippingbox")
                .font(.title2.weight(.semibold))
            Text("MacScan uses the free, open-source \(engine.title) command-line tool. Other engines keep working without it.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Install it with Homebrew in Terminal:")
            HStack {
                Text(command)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(command, forType: .string)
                }
            }
            if engine == .clamav {
                Text("Then click **Update virus database** in MacScan to download the signatures (about 300 MB). MacScan never updates automatically.")
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Don't have Homebrew? See https://brew.sh. If the tool is installed in a custom location, set its path in Settings › Engines.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(text).hidden().frame(height: 0)
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 520)
    }
}

struct FreshclamSheet: View {
    @Environment(AppState.self) private var state
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let run = state.freshclam ?? FreshclamRun(running: false)
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Update virus database", systemImage: "arrow.down.circle")
                    .font(.title2.weight(.semibold))
                Spacer()
                if run.running { ProgressView().controlSize(.small) }
            }
            Text("Running freshclam to download the latest ClamAV signatures into MacScan's own folder.")
                .font(.callout)
                .foregroundStyle(.secondary)

            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(run.lines.enumerated()), id: \.offset) { i, line in
                            Text(line).font(.caption.monospaced()).id(i)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(8)
                }
                .frame(height: 240)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
                .onChange(of: run.lines.count) { _, count in
                    if count > 0 { proxy.scrollTo(count - 1, anchor: .bottom) }
                }
            }

            if run.succeeded {
                Label("Virus database is up to date.", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            } else if let error = run.error {
                Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }

            HStack {
                Spacer()
                if run.running {
                    Button("Cancel", role: .cancel) { state.cancelDatabaseUpdate() }
                    Button("Hide") { dismiss() }
                } else {
                    Button("Close") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(24)
        .frame(width: 620)
    }
}
