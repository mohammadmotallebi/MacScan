import MacScanCore
import SwiftUI

struct ScanView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        Group {
            if state.isScanning, let progress = state.progress {
                ScanningView(progress: progress)
                    .transition(.opacity)
            } else if let session = state.currentSession {
                VStack(spacing: 0) {
                    SessionSummaryBar(session: session)
                    Divider()
                    ResultsView(session: session)
                }
                .transition(.opacity)
            } else {
                HomeView()
                    .transition(.opacity)
            }
        }
        .animation(.smooth(duration: 0.35), value: state.isScanning)
        .animation(.smooth(duration: 0.35), value: state.currentSession?.id)
        .frame(minWidth: 620, maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("MacScan")
    }
}

// MARK: - Scanning

struct ScanningView: View {
    @Environment(AppState.self) private var state
    let progress: ScanProgress

    var body: some View {
        VStack(spacing: 26) {
            Spacer()
            StatusRing(color: .accentColor, symbol: "shield.lefthalf.filled", progress: progress.fraction, size: 190, pulse: true)
            VStack(spacing: 8) {
                Text(progress.phase.rawValue)
                    .font(.system(size: 26, weight: .bold, design: .rounded))
                if let fraction = progress.fraction {
                    Text(fraction.formatted(.percent.precision(.fractionLength(0))))
                        .font(.title2.weight(.semibold))
                        .monospacedDigit()
                        .foregroundStyle(.tint)
                        .contentTransition(.numericText())
                        .animation(.smooth, value: fraction)
                }
                if progress.itemsTotal > 0 {
                    Text("\(progress.itemsDone.formatted()) of \(progress.itemsTotal.formatted()) files")
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            }
            Text(progress.status ?? progress.currentFile ?? " ")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 520)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .glassCard(radius: 12)
                .help(progress.currentFile ?? "")
            Button(role: .cancel) {
                state.cancelScan()
            } label: {
                Label("Cancel Scan", systemImage: "xmark")
                    .padding(.horizontal, 8)
            }
            .buttonStyle(.glass)
            .controlSize(.large)
            .keyboardShortcut(.cancelAction)
            Spacer()
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(HomeBackground(color: .accentColor))
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

// MARK: - Summary bar

struct SessionSummaryBar: View {
    @Environment(AppState.self) private var state
    let session: ScanSession
    @State private var showNotes = false

    var body: some View {
        HStack(spacing: 10) {
            Button {
                state.currentSession = nil
            } label: {
                Label("Home", systemImage: "chevron.left")
            }
            .buttonStyle(.glass)
            .help("Back to the home screen")
            VStack(alignment: .leading, spacing: 1) {
                Text(session.title).font(.headline).lineLimit(1)
                Text("\(session.itemsScanned.formatted()) of \(session.itemsTotal.formatted()) items · \(session.startedAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            .padding(.trailing, 6)
            chip(.threat)
            chip(.warning)
            chip(.clean)
            if session.status != .completed {
                CountChip(symbol: "exclamationmark.circle", text: session.status == .cancelled ? "Cancelled" : "Failed", color: .orange)
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
        .padding(.vertical, 10)
    }

    private func chip(_ severity: Severity) -> some View {
        let n = session.count(severity)
        let word = severity == .clean ? "clean" : severity.title.lowercased() + (n == 1 ? "" : "s")
        return CountChip(symbol: severity.symbol, text: "\(n.formatted()) \(word)", color: severity.color, dimmed: n == 0 && severity != .clean)
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
