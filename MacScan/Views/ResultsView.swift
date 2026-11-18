import MacScanCore
import SwiftUI

struct ResultsView: View {
    @Environment(AppState.self) private var state
    let session: ScanSession

    @State private var filter: SeverityFilter = .all
    @State private var search = ""
    @State private var selection: Set<Finding.ID> = []
    @State private var sortOrder = [KeyPathComparator(\Finding.severity, order: .reverse)]

    private var filtered: [Finding] {
        let query = search.trimmingCharacters(in: .whitespaces)
        return session.findings
            .filter { filter.matches($0.severity) }
            .filter { query.isEmpty || $0.path.localizedCaseInsensitiveContains(query) || $0.reason.localizedCaseInsensitiveContains(query) }
            .sorted(using: sortOrder)
    }

    private var selectedFinding: Finding? {
        guard selection.count == 1, let id = selection.first else { return nil }
        return session.findings.first { $0.id == id }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Show", selection: $filter) {
                    ForEach(SeverityFilter.allCases) { f in
                        Text(label(for: f)).tag(f)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 420)
                Spacer()
                TextField("Filter by path or reason", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 240)
            }
            .padding(8)

            Table(filtered, selection: $selection, sortOrder: $sortOrder) {
                TableColumn("Severity", value: \.severity) { f in
                    SeverityBadge(severity: f.severity)
                }
                .width(min: 80, ideal: 90, max: 110)

                TableColumn("Path", value: \.path) { f in
                    let trashed = state.trashedPaths.contains(f.path)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(f.fileName)
                            .strikethrough(trashed)
                            .lineLimit(1)
                        Text(trashed ? "Moved to Trash" : (f.path as NSString).deletingLastPathComponent)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .help(f.path)
                }
                .width(min: 200, ideal: 320)

                TableColumn("Engine", value: \.engine.title) { f in
                    Text(f.engine.title)
                }
                .width(min: 80, ideal: 100, max: 130)

                TableColumn("Reason", value: \.reason) { f in
                    HStack(spacing: 4) {
                        if state.vtLookupsInFlight.contains(f.id) {
                            ProgressView().controlSize(.mini)
                        }
                        Text(f.reason).lineLimit(2)
                    }
                    .help(f.detail ?? f.reason)
                }
                .width(min: 200, ideal: 340)
            }
            .contextMenu(forSelectionType: Finding.ID.self) { ids in
                if let id = ids.first, let f = session.findings.first(where: { $0.id == id }) {
                    FindingActions(finding: f, sessionID: session.id)
                }
            } primaryAction: { ids in
                if let id = ids.first, let f = session.findings.first(where: { $0.id == id }) {
                    state.reveal(f)
                }
            }

            if let f = selectedFinding {
                Divider()
                FindingDetailView(finding: f, sessionID: session.id)
            }
        }
    }

    private func label(for f: SeverityFilter) -> String {
        switch f {
        case .all: "All (\(session.findings.count))"
        case .threat: "Threats (\(session.count(.threat)))"
        case .warning: "Warnings (\(session.count(.warning)))"
        case .clean: "Clean (\(session.count(.clean)))"
        }
    }
}

/// Per-result actions. Every action is user-initiated; Trash always asks for confirmation.
struct FindingActions: View {
    @Environment(AppState.self) private var state
    let finding: Finding
    let sessionID: UUID

    var body: some View {
        Button("Reveal in Finder") { state.reveal(finding) }
        Button("Copy Path") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(finding.path, forType: .string)
        }
        Divider()
        Button("Look Up Hash on VirusTotal") { state.lookUpOnVirusTotal(finding, sessionID: sessionID) }
            .disabled(!state.hasVirusTotalKey || state.vtLookupsInFlight.contains(finding.id))
        Button("Ignore This Result") { state.ignore(finding, sessionID: sessionID) }
            .disabled(finding.severity == .clean)
        Divider()
        if let app = state.owningApp(of: finding) {
            Button("Uninstall “\(app.deletingPathExtension().lastPathComponent)” Completely…") { state.openUninstaller(for: app) }
        }
        Button("Move to Trash…", role: .destructive) { state.requestTrash(finding, sessionID: sessionID) }
            .disabled(state.trashedPaths.contains(finding.path))
    }
}

struct FindingDetailView: View {
    @Environment(AppState.self) private var state
    let finding: Finding
    let sessionID: UUID

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    SeverityBadge(severity: finding.severity)
                    Text(finding.reason).font(.headline).textSelection(.enabled)
                }
                Text(finding.path)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .lineLimit(2)
                if let detail = finding.detail, !detail.isEmpty {
                    Text(detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let hash = finding.sha256 {
                    Text("SHA-256: \(hash)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            VStack(alignment: .trailing, spacing: 6) {
                Button("Reveal in Finder") { state.reveal(finding) }
                Button("VirusTotal Lookup") { state.lookUpOnVirusTotal(finding, sessionID: sessionID) }
                    .disabled(!state.hasVirusTotalKey || state.vtLookupsInFlight.contains(finding.id))
                    .help(state.hasVirusTotalKey ? "Sends only the SHA-256 hash" : "Add your API key in Settings › VirusTotal")
                Button("Ignore") { state.ignore(finding, sessionID: sessionID) }
                    .disabled(finding.severity == .clean)
                if let app = state.owningApp(of: finding) {
                    Button("Uninstall App…") { state.openUninstaller(for: app) }
                        .help("Remove \(app.lastPathComponent) and everything that belongs to it")
                }
                Button("Move to Trash…", role: .destructive) { state.requestTrash(finding, sessionID: sessionID) }
                    .disabled(state.trashedPaths.contains(finding.path))
            }
            .controlSize(.small)
        }
        .padding(12)
        .frame(maxHeight: 200)
    }
}

struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Label(severity.title, systemImage: severity.symbol)
            .font(.caption.weight(.semibold))
            .foregroundStyle(severity.color)
            .labelStyle(.titleAndIcon)
    }
}

struct SeverityCount: View {
    let severity: Severity
    let count: Int

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: severity.symbol).foregroundStyle(severity.color)
            Text("\(count.formatted()) \(severity.title.lowercased())\(count == 1 || severity == .clean ? "" : "s")")
                .monospacedDigit()
        }
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .clean: .green
        case .warning: .orange
        case .threat: .red
        }
    }

    var symbol: String {
        switch self {
        case .clean: "checkmark.shield.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .threat: "xmark.octagon.fill"
        }
    }
}
