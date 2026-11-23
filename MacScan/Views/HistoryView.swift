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
                    SectionEmptyState(symbol: "clock.fill", color: .gray, title: "No scans yet", message: "Finished scans show up here.")
                }
            }

            Group {
                if let session = selected {
                    VStack(spacing: 0) {
                        SectionHeader(
                            title: session.title,
                            subtitle: session.startedAt.formatted(date: .complete, time: .shortened),
                            symbol: session.worstSeverity.symbol, color: session.worstSeverity.color
                        ) {
                            Menu {
                                Button("Export as JSON…") { state.export([session], format: .json) }
                                Button("Export as CSV…") { state.export([session], format: .csv) }
                            } label: {
                                Label("Export", systemImage: "square.and.arrow.up")
                            }
                            .fixedSize()
                        }
                        Divider()
                        SessionSummaryBar(session: session, showsHome: false)
                        Divider()
                        ResultsView(session: session)
                            .id(session.id)
                    }
                } else {
                    SectionEmptyState(symbol: "list.bullet.rectangle.fill", color: .gray, title: "Select a scan", message: "Choose a past scan to see its results.")
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
        .onChange(of: state.requestedHistorySelection, initial: true) { _, requested in
            guard let requested else { return }
            if state.history.contains(where: { $0.id == requested }) { selectedID = requested }
            state.requestedHistorySelection = nil
        }
    }
}

struct HistoryRow: View {
    let session: ScanSession

    var body: some View {
        HStack(spacing: 10) {
            IconTile(symbol: session.fullCheck != nil ? "checkmark.shield.fill" : session.worstSeverity.symbol,
                     color: session.worstSeverity.color, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(session.startedAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.callout.weight(.medium))
                Text(session.title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack(spacing: 8) {
                    if let trigger = session.trigger {
                        Label(trigger.title, systemImage: trigger == .scheduled ? "calendar.badge.clock" : "arrow.down.circle")
                            .labelStyle(.titleAndIcon)
                            .foregroundStyle(.secondary)
                    }
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
