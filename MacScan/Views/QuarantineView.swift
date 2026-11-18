import MacScanCore
import SwiftUI

/// The Quarantine section: items the user moved out of the way, with Restore and Delete Permanently.
struct QuarantineView: View {
    @Environment(AppState.self) private var state
    @State private var selection: QuarantinedItem.ID?

    private var selected: QuarantinedItem? { state.quarantined.first { $0.id == selection } }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(state.quarantined.isEmpty ? "Nothing in quarantine" : "\(state.quarantined.count) \(state.quarantined.count == 1 ? "item" : "items") in quarantine")
                    .font(.headline)
                Spacer()
                Button("Restore") { if let selected { state.restoreQuarantined(selected) } }
                    .disabled(selected == nil)
                    .help("Put the selected item back exactly where it was")
                Button("Delete Permanently…", role: .destructive) {
                    if let selected { state.pendingQuarantineDelete = PendingQuarantineDelete(items: [selected]) }
                }
                .disabled(selected == nil)
                Button("Delete All…", role: .destructive) {
                    state.pendingQuarantineDelete = PendingQuarantineDelete(items: state.quarantined)
                }
                .disabled(state.quarantined.isEmpty)
            }
            .padding(12)
            Divider()

            if state.quarantined.isEmpty {
                ContentUnavailableView {
                    Label("Quarantine is empty", systemImage: "archivebox")
                } description: {
                    Text("Choose Quarantine… on a scan result to move it here. Quarantined items are locked so they can't run or be opened, and can be put back exactly where they were.")
                }
            } else {
                Table(state.quarantined, selection: $selection) {
                    TableColumn("Item") { item in
                        VStack(alignment: .leading, spacing: 1) {
                            Label(item.name, systemImage: item.isDirectory ? "folder" : "doc")
                                .lineLimit(1)
                            Text((item.originalPath as NSString).deletingLastPathComponent)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        .help(item.originalPath)
                    }
                    .width(min: 220, ideal: 320)

                    TableColumn("Why") { item in
                        Text((item.engine.map { $0.title + ": " } ?? "") + item.reason)
                            .lineLimit(2)
                            .help(item.reason)
                    }
                    .width(min: 200, ideal: 320)

                    TableColumn("Quarantined") { item in
                        Text(item.date.formatted(date: .abbreviated, time: .shortened))
                    }
                    .width(min: 120, ideal: 150, max: 180)

                    TableColumn("Size") { item in
                        Text(item.size.map { ByteCountFormatter.string(fromByteCount: $0, countStyle: .file) } ?? "—")
                            .monospacedDigit()
                    }
                    .width(min: 60, ideal: 80, max: 100)
                }
                .contextMenu(forSelectionType: QuarantinedItem.ID.self) { ids in
                    if let id = ids.first, let item = state.quarantined.first(where: { $0.id == id }) {
                        Button("Restore to Original Location") { state.restoreQuarantined(item) }
                        Button("Copy Original Path") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(item.originalPath, forType: .string)
                        }
                        if let hash = item.sha256 {
                            Button("Copy SHA-256") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(hash, forType: .string)
                            }
                        }
                        Divider()
                        Button("Delete Permanently…", role: .destructive) {
                            state.pendingQuarantineDelete = PendingQuarantineDelete(items: [item])
                        }
                    }
                }
                Divider()
                Text("Quarantined items are locked and can't run. Restore puts an item back where it was; Delete Permanently can't be undone.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Quarantine")
    }
}
