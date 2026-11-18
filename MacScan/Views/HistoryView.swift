import MacScanCore
import SwiftUI

struct HistoryView: View {
    @Environment(AppState.self) private var state
    @State private var selectedID: ScanSession.ID?
    @State private var pendingDelete: ScanSession?

    private var selected: ScanSession? {
        guard let selectedID else { return nil }
        return state.history.first { $0.id == selectedID }
    }

    var body: some View {
        HSplitView {
            List(selection: $selectedID) {
                ForEach(state.history) { session in
                    HistoryRow(session: session)
                        .tag(session.id)
                        .contextMenu {
                            Button("Export as JSON…") { state.export([session], format: .json) }
                            Button("Export as CSV…") { state.export([session], format: .csv) }
                            Divider()
                            Button("Delete from History…", role: .destructive) { pendingDelete = session }
                        }
                }
            }
            .frame(minWidth: 260, idealWidth: 300, maxWidth: 400, maxHeight: .infinity)
            .overlay {
                if state.history.isEmpty {
                    ContentUnavailableView("No scans yet", systemImage: "clock", description: Text("Completed scans appear here."))
                }
            }

            Group {
                if let session = selected {
                    VStack(spacing: 0) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(session.startedAt.formatted(date: .complete, time: .shortened)).font(.headline)
                                Text(session.targets.joined(separator: ", "))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            Spacer()
                            Button("Export JSON…") { state.export([session], format: .json) }
                            Button("Export CSV…") { state.export([session], format: .csv) }
                        }
                        .padding(12)
                        Divider()
                        SessionSummaryBar(session: session)
                        Divider()
                        ResultsView(session: session)
                            .id(session.id)
                    }
                } else {
                    ContentUnavailableView("Select a scan", systemImage: "list.bullet.rectangle", description: Text("Choose a past scan to see its results."))
                }
            }
            .frame(minWidth: 520, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("History")
        .toolbar {
            ToolbarItem {
                Menu {
                    Button("All Scans as JSON…") { state.export(state.history, format: .json) }
                    Button("All Scans as CSV…") { state.export(state.history, format: .csv) }
                } label: {
                    Label("Export All", systemImage: "square.and.arrow.up")
                }
                .disabled(state.history.isEmpty)
            }
        }
        .confirmationDialog(
            "Delete this scan from history?",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            presenting: pendingDelete
        ) { session in
            Button("Delete", role: .destructive) {
                if selectedID == session.id { selectedID = nil }
                state.deleteHistory(session)
            }
        } message: { _ in
            Text("Only the history record is deleted. No files are touched.")
        }
        .onAppear {
            if selectedID == nil { selectedID = state.history.first?.id }
        }
    }
}

struct HistoryRow: View {
    let session: ScanSession

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: session.worstSeverity.symbol)
                .foregroundStyle(session.worstSeverity.color)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(session.startedAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.callout.weight(.medium))
                Text(session.targets.joined(separator: ", "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack(spacing: 8) {
                    if session.count(.threat) > 0 { Text("\(session.count(.threat)) threats").foregroundStyle(.red) }
                    if session.count(.warning) > 0 { Text("\(session.count(.warning)) warnings").foregroundStyle(.orange) }
                    if session.status != .completed { Text(session.status.rawValue.capitalized).foregroundStyle(.secondary) }
                }
                .font(.caption2)
            }
        }
        .padding(.vertical, 2)
    }
}
