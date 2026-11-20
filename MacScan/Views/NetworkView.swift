import MacScanCore
import SwiftUI

/// The Network section: which programs are talking to other computers right now, and which accept connections.
/// Nothing here blocks or closes a connection.
struct NetworkView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        @Bindable var model = state.network
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                if let snapshot = model.snapshot, snapshot.problem == nil {
                    summary(snapshot)
                } else {
                    Text(model.isChecking ? "Checking…" : model.snapshot == nil ? "Not checked yet" : "Couldn't check").foregroundStyle(.secondary)
                }
                Spacer()
                if model.isChecking { ProgressView().controlSize(.small) }
                if let date = model.snapshot?.takenAt {
                    Text("Taken \(date.formatted(date: .omitted, time: .standard))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Toggle("Flagged only", isOn: $model.flaggedOnly).toggleStyle(.checkbox)
                Toggle("Hide macOS", isOn: $model.hideApple)
                    .toggleStyle(.checkbox)
                    .help("Hide macOS's own programs (they are still shown if something about them is worth a look)")
                Button("Check Again") { model.refresh() }
                    .disabled(model.isChecking)
            }
            .padding(12)
            Divider()

            if let snapshot = model.snapshot {
                content(snapshot, model: model)
            } else {
                ContentUnavailableView {
                    Label("Network", systemImage: "network")
                } description: {
                    Text("Shows which programs are talking to other computers right now, and which accept connections.\nMacScan only looks; it never blocks anything.")
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Network")
        .task {
            if model.snapshot == nil { model.refresh() }
        }
    }

    @ViewBuilder
    private func content(_ snapshot: NetworkSnapshot, model: NetworkModel) -> some View {
        if let problem = snapshot.problem {
            ContentUnavailableView("Couldn't check the network", systemImage: "exclamationmark.triangle", description: Text(problem))
        } else {
            let shown = model.shown(snapshot)
            if shown.isEmpty {
                ContentUnavailableView(snapshot.apps.isEmpty ? "No network activity" : "Nothing flagged", systemImage: "checkmark.circle",
                                       description: Text(snapshot.apps.isEmpty ? "No program has a connection open." : "No program looks out of place."))
            } else {
                List(shown) { app in
                    NetworkRow(app: app, model: model)
                }
                .listStyle(.inset)
            }
            Divider()
            Text("A snapshot of this moment. Addresses are shown as numbers: MacScan doesn't look names up, so it never goes online."
                 + (snapshot.onlyOwnPrograms ? " Only your own programs are shown; services running as other users are not." : ""))
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
        }
    }

    @ViewBuilder
    private func summary(_ snapshot: NetworkSnapshot) -> some View {
        let warnings = snapshot.count(.warning)
        let review = snapshot.count(.review)
        Label(warnings > 0 ? "\(warnings) \(warnings == 1 ? "program needs" : "programs need") attention"
              : review > 0 ? "\(review) worth a look" : "Nothing looks out of place",
              systemImage: warnings > 0 ? "exclamationmark.triangle.fill" : review > 0 ? "eye.fill" : "checkmark.circle.fill")
            .font(.headline)
            .foregroundStyle(warnings > 0 ? .orange : review > 0 ? .blue : .green)
        let out = snapshot.apps.filter { $0.widestScope == .internet }.count
        Text("\(snapshot.apps.count) using the network · \(out) talking to the internet")
            .font(.callout)
            .foregroundStyle(.secondary)
    }
}

private struct NetworkRow: View {
    let app: NetworkApp
    let model: NetworkModel
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .top, spacing: 10) {
                Group {
                    if let path = app.path {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable()
                    } else {
                        Image(systemName: "questionmark.app.dashed").resizable().foregroundStyle(.secondary)
                    }
                }
                .frame(width: 26, height: 26)

                VStack(alignment: .leading, spacing: 3) {
                    Text(app.name).font(.body.weight(.medium))
                    Text(app.signer ?? "Program file not found")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    ForEach(app.reasons, id: \.self) { reason in
                        Label(reason, systemImage: app.risk == .warning ? "exclamationmark.triangle.fill" : "eye")
                            .font(.callout)
                            .foregroundStyle(app.risk == .warning ? .orange : .primary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 12)
                VStack(alignment: .trailing, spacing: 3) {
                    if let scope = app.widestScope {
                        badge("\(app.connections.count) out · \(scope.title)", color: scope == .internet ? .blue : .secondary)
                    }
                    if !app.listeners.isEmpty {
                        badge("\(app.listeners.count) listening" + (app.openToOthers ? " · open to network" : ""),
                              color: app.openToOthers ? .orange : .secondary)
                    }
                }
                Button {
                    withAnimation(.snappy(duration: 0.15)) { expanded.toggle() }
                } label: {
                    Image(systemName: "chevron.right")
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                        .frame(width: 16, height: 16)
                }
                .buttonStyle(.borderless)
                .help(expanded ? "Hide connections" : "Show connections")
            }
            if expanded {
                details.padding(.leading, 36)
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .help(app.path ?? "")
        .contextMenu {
            if app.path != nil { Button("Reveal in Finder") { model.reveal(app) } }
            if let path = app.path { Button("Copy Path") { model.copy(path) } }
            Button("Copy Connections") { model.copy(text) }
        }
    }

    private func badge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(app.listeners) { listener in
                Text("Listening  \(listener.proto) port \(listener.port) · " + (listener.allInterfaces ? "open to other computers" : "this Mac only"))
                    .foregroundStyle(listener.allInterfaces && listener.proto == "TCP" ? .orange : .secondary)
            }
            ForEach(app.connections) { connection in
                Text("→ \(connection.remoteAddress) port \(connection.remotePort) · \(connection.scope.title)" + (connection.state.map { " · \($0.lowercased())" } ?? ""))
                    .foregroundStyle(.secondary)
            }
            Text("Process ID\(app.pids.count == 1 ? "" : "s"): " + app.pids.map(String.init).joined(separator: ", "))
                .foregroundStyle(.tertiary)
        }
        .font(.caption.monospaced())
        .textSelection(.enabled)
    }

    private var text: String {
        var lines = [app.name + (app.path.map { " (\($0))" } ?? "")]
        lines += app.listeners.map { "listening \($0.proto) \($0.address):\($0.port)" }
        lines += app.connections.map { "\($0.proto) -> \($0.remoteAddress):\($0.remotePort) \($0.state ?? "")" }
        return lines.joined(separator: "\n")
    }
}
