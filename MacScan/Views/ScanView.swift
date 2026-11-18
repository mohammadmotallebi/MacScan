import MacScanCore
import SwiftUI

struct ScanView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        HSplitView {
            ScanControlsPanel()
                .frame(minWidth: 280, idealWidth: 310, maxWidth: 380, maxHeight: .infinity, alignment: .top)
                .background(.background.secondary)

            VStack(spacing: 0) {
                if state.isScanning, let progress = state.progress {
                    ScanProgressView(progress: progress)
                        .padding()
                    Divider()
                }
                if let session = state.currentSession {
                    SessionSummaryBar(session: session)
                    Divider()
                    ResultsView(session: session)
                } else if !state.isScanning {
                    ContentUnavailableView {
                        Label("Ready to scan", systemImage: "checkmark.shield")
                    } description: {
                        Text("Scan your applications, your saved folders, or drop any file or folder onto this window.\nMacScan only runs while this window is open.")
                    }
                } else {
                    Spacer()
                }
            }
            .frame(minWidth: 520, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("MacScan")
    }
}

// MARK: - Left panel

struct ScanControlsPanel: View {
    @Environment(AppState.self) private var state

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox {
                    VStack(spacing: 8) {
                        Button {
                            state.scanApplications()
                        } label: {
                            Label("Scan Applications", systemImage: "app.badge.checkmark")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)

                        Button {
                            state.scanStartupItems()
                        } label: {
                            Label("Scan Startup Items", systemImage: "power.circle")
                                .frame(maxWidth: .infinity)
                        }
                        .controlSize(.large)
                        .help("Everything set to start automatically: launch agents & daemons, privileged helpers, shell startup files, plug-ins and cron jobs")

                        Button {
                            state.scanCustomFolders()
                        } label: {
                            Label("Scan Folders", systemImage: "folder.badge.gearshape")
                                .frame(maxWidth: .infinity)
                        }
                        .controlSize(.large)
                        .disabled(state.customFolders.isEmpty)
                        .help(state.customFolders.isEmpty ? "Add folders below first" : "Scan all saved folders")

                        Button {
                            state.chooseAndScan()
                        } label: {
                            Label("Scan File or Folder…", systemImage: "doc.viewfinder")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(state.isScanning)
                    .padding(4)
                } label: {
                    Text("Scan")
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        if state.customFolders.isEmpty {
                            Text("No folders yet. Add the folders you want “Scan Folders” to check.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        ForEach(state.customFolders, id: \.self) { url in
                            HStack(spacing: 6) {
                                Image(systemName: "folder")
                                    .foregroundStyle(.secondary)
                                Text(url.lastPathComponent)
                                    .lineLimit(1)
                                    .help(url.path)
                                Spacer()
                                Button {
                                    state.removeFolder(url)
                                } label: {
                                    Image(systemName: "minus.circle.fill")
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.borderless)
                                .help("Remove from list (does not touch the folder)")
                            }
                            .contextMenu {
                                Button("Scan Only This Folder") { state.scan(urls: [url]) }
                                Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                                Divider()
                                Button("Remove from List") { state.removeFolder(url) }
                            }
                        }
                        Button {
                            state.addFolders()
                        } label: {
                            Label("Add Folder…", systemImage: "plus")
                        }
                        .buttonStyle(.borderless)
                        .padding(.top, 2)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(4)
                } label: {
                    Text("Folders")
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
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
                        EngineStatusRow(engine: .yara)
                        EngineStatusRow(engine: .integrity)
                        EngineStatusRow(engine: .persistence)
                        EngineStatusRow(engine: .virustotal)
                    }
                    .padding(4)
                } label: {
                    Text("Engines")
                }

                if !state.fullDiskAccessLikelyGranted {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            Label("Full Disk Access not granted", systemImage: "lock.shield")
                                .font(.callout.weight(.semibold))
                                .foregroundStyle(.orange)
                            Text("Some protected folders (Mail, Safari, other apps' data) can't be scanned.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Button("How to grant access…") {
                                state.fdaPrompt = FDAPrompt(paths: [])
                            }
                            .controlSize(.small)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(4)
                    }
                }

                Text("Tip: drag files or folders onto the window to scan them.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }
}

struct EngineStatusRow: View {
    @Environment(AppState.self) private var state
    let engine: EngineID

    var body: some View {
        let status = state.engineStatus[engine]
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: icon(for: status))
                .foregroundStyle(color(for: status))
                .frame(width: 14)
            VStack(alignment: .leading, spacing: 2) {
                Text(engine.title).font(.callout.weight(.medium))
                Text(shortSummary(status))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                if case .notInstalled = status {
                    Button("How to install…") { state.installHelp = engine }
                        .controlSize(.small)
                        .buttonStyle(.link)
                }
            }
        }
    }

    private func shortSummary(_ s: EngineAvailability?) -> String {
        guard let s else { return "Checking…" }
        if case .notInstalled = s { return "Not installed" }
        return s.summary
    }

    private func icon(for s: EngineAvailability?) -> String {
        switch s {
        case .available: "checkmark.circle.fill"
        case .notInstalled: "xmark.circle.fill"
        case .needsSetup: "exclamationmark.circle.fill"
        case .disabled: "minus.circle"
        case nil: "circle.dotted"
        }
    }

    private func color(for s: EngineAvailability?) -> Color {
        switch s {
        case .available: .green
        case .notInstalled: .red
        case .needsSetup: .orange
        case .disabled, nil: .secondary
        }
    }
}

// MARK: - Progress

struct ScanProgressView: View {
    @Environment(AppState.self) private var state
    let progress: ScanProgress

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(progress.phase.rawValue).font(.headline)
                Spacer()
                if progress.itemsTotal > 0 {
                    Text("\(progress.itemsDone.formatted()) / \(progress.itemsTotal.formatted()) files")
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
                Button("Cancel", role: .cancel) { state.cancelScan() }
                    .keyboardShortcut(.cancelAction)
            }
            if let fraction = progress.fraction {
                ProgressView(value: fraction)
            } else {
                ProgressView().progressViewStyle(.linear)
            }
            Text(progress.status ?? progress.currentFile ?? " ")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(progress.currentFile ?? "")
        }
    }
}

// MARK: - Summary bar

struct SessionSummaryBar: View {
    @Environment(AppState.self) private var state
    let session: ScanSession
    @State private var showNotes = false

    var body: some View {
        HStack(spacing: 14) {
            SeverityCount(severity: .threat, count: session.count(.threat))
            SeverityCount(severity: .warning, count: session.count(.warning))
            SeverityCount(severity: .clean, count: session.count(.clean))
            Divider().frame(height: 18)
            Text("\(session.itemsScanned.formatted()) of \(session.itemsTotal.formatted()) items")
                .foregroundStyle(.secondary)
                .monospacedDigit()
            if session.status != .completed {
                Text(session.status == .cancelled ? "Cancelled" : "Failed")
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.orange.opacity(0.2), in: Capsule())
            }
            Spacer()
            if session.hasPermissionIssues {
                Button {
                    state.fdaPrompt = FDAPrompt(paths: session.issues.filter(\.isPermissionDenied).map(\.path))
                } label: {
                    Label("\(session.issues.filter(\.isPermissionDenied).count) unreadable", systemImage: "lock.fill")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.orange)
            }
            if !session.notes.isEmpty || session.skippedCount > 0 || session.ignoredCount > 0 || !session.issues.isEmpty {
                Button {
                    showNotes.toggle()
                } label: {
                    Label("Details", systemImage: "info.circle")
                }
                .buttonStyle(.borderless)
                .popover(isPresented: $showNotes, arrowEdge: .bottom) {
                    SessionNotesView(session: session)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

struct SessionNotesView: View {
    let session: ScanSession

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                Text("Scan details").font(.headline)
                Text("Started \(session.startedAt.formatted(date: .abbreviated, time: .standard))")
                if let end = session.finishedAt {
                    Text("Duration \(Duration.seconds(end.timeIntervalSince(session.startedAt)).formatted(.units(allowed: [.hours, .minutes, .seconds], width: .abbreviated)))")
                }
                Text("Engines: \(session.enginesUsed.map(\.title).joined(separator: ", "))")
                if session.skippedCount > 0 { Text("Skipped (over size limit): \(session.skippedCount)") }
                if session.ignoredCount > 0 { Text("Hidden by ignore list: \(session.ignoredCount)") }
                ForEach(Array(session.notes.enumerated()), id: \.offset) { _, note in
                    Label(note, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                }
                if !session.issues.isEmpty {
                    Divider()
                    Text("Could not read (\(session.issues.count))").font(.subheadline.weight(.semibold))
                    ForEach(Array(session.issues.prefix(100).enumerated()), id: \.offset) { _, issue in
                        Text("\(issue.path) — \(issue.message)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(width: 480, height: 320)
    }
}
