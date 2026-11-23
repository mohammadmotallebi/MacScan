import MacScanCore
import SwiftUI

struct FullDiskAccessSteps: View {
    private let steps: [LocalizedStringKey] = [
        "Open **System Settings › Privacy & Security › Full Disk Access**.",
        "Click **+**, choose **MacScan** (or drag MacScan.app into the list).",
        "Turn the switch next to MacScan **on**.",
        "Quit and reopen MacScan so the change takes effect.",
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(Array(steps.enumerated()), id: \.offset) { i, step in
                HStack(spacing: 10) {
                    Text("\(i + 1)")
                        .font(.callout.weight(.bold).monospacedDigit())
                        .foregroundStyle(.white)
                        .frame(width: 22, height: 22)
                        .background(Color.pink.gradient, in: Circle())
                    Text(step).font(.callout)
                    Spacer(minLength: 0)
                }
            }
        }
    }
}

struct FullDiskAccessSheet: View {
    @Environment(\.dismiss) private var dismiss
    let paths: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            SheetHeader(
                symbol: "lock.shield.fill", color: .pink, title: "MacScan needs Full Disk Access",
                subtitle: paths.isEmpty
                    ? "macOS protects some folders (Mail, Messages, Safari, other apps' data). Without Full Disk Access MacScan can't read them."
                    : "macOS refused access to \(paths.count) location(s). Folders like Mail, Messages, Safari and other apps' data can only be scanned with Full Disk Access.")

            FullDiskAccessSteps()
                .padding(14)
                .glassCard(radius: 16)

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
                .buttonStyle(.glass)
                Spacer()
                Button("Not Now") { dismiss() }
                    .buttonStyle(.glass)
                    .keyboardShortcut(.cancelAction)
                Button("Open System Settings") {
                    FullDiskAccess.openSettings()
                    dismiss()
                }
                .buttonStyle(.glassProminent)
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
            SheetHeader(symbol: "shippingbox.fill", color: .brown, title: "\(engine.title) is not installed",
                        subtitle: "MacScan uses the free, open-source \(engine.title) command-line tool. Other engines keep working without it.")
            Text("Install it with Homebrew in Terminal:")
            CodeBox {
                HStack {
                    Text("$ ").foregroundStyle(.green) + Text(command)
                    Spacer()
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(command, forType: .string)
                    } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.glass)
                    .controlSize(.small)
                }
                .textSelection(.enabled)
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
                Button("Done") { dismiss() }.buttonStyle(.glassProminent).keyboardShortcut(.defaultAction)
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
            SheetHeader(symbol: "arrow.down.circle.fill", color: run.succeeded ? .green : run.error != nil ? .orange : .blue,
                        title: run.running ? "Updating virus database…" : run.succeeded ? "Virus database updated" : "Update virus database",
                        subtitle: "freshclam downloads the latest ClamAV signatures into MacScan's own folder.",
                        isBusy: run.running)

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
                .foregroundStyle(.white.opacity(0.85))
                .frame(height: 240)
                .background(Color.black.opacity(0.78), in: .rect(cornerRadius: 12))
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
                    Button("Cancel", role: .cancel) { state.cancelDatabaseUpdate() }.buttonStyle(.glass)
                    Button("Hide") { dismiss() }.buttonStyle(.glass)
                } else {
                    Button("Close") { dismiss() }.buttonStyle(.glassProminent).keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(24)
        .frame(width: 620)
    }
}
