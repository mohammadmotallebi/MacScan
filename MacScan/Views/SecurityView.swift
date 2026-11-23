import MacScanCore
import SwiftUI

/// The Security section: whether macOS's own protections are on. Nothing here changes a setting.
struct SecurityView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        let model = state.security
        VStack(spacing: 0) {
            header(model)
            Divider()

            if model.checks.isEmpty {
                SectionEmptyState(
                    symbol: "lock.shield.fill", color: .indigo,
                    title: model.isChecking ? "Checking your settings…" : "Security settings",
                    message: "Checks whether the protections built into macOS are on, and looks for settings that adware changes. MacScan only reads them; it never changes a setting.",
                    isBusy: model.isChecking, buttonTitle: "Check Security", action: { model.refresh() })
            } else {
                List {
                    ForEach(PostureGroup.allCases) { group in
                        let checks = model.checks.filter { $0.group == group }
                        if !checks.isEmpty {
                            Section {
                                ForEach(checks) { check in
                                    PostureRow(check: check) { model.openSettings(for: check) }
                                }
                            } header: {
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text(group.title).font(.title3.weight(.semibold)).foregroundStyle(.primary)
                                    Text(group.explanation).font(.callout).foregroundStyle(.secondary)
                                }
                                .padding(.vertical, 2)
                            }
                        }
                    }
                }
                .listStyle(.inset)
                Divider()
                SectionFootnote(text: "MacScan only reads these settings. Change them yourself in System Settings.")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Security")
        .task {
            if model.checks.isEmpty { model.refresh() }
        }
    }

    private func header(_ model: SecurityModel) -> some View {
        let fails = model.count(.fail), warnings = model.count(.warning), unknown = model.count(.unknown)
        let attention = fails + warnings
        let color: Color = model.checks.isEmpty ? .indigo : fails > 0 ? .red : attention > 0 ? .orange : .green
        var subtitle = model.checks.isEmpty
            ? (model.isChecking ? "Checking…" : "Not checked yet")
            : attention == 0 ? "Everything checked is on." : "\(attention) \(attention == 1 ? "setting needs" : "settings need") a look."
        if let date = model.lastChecked { subtitle += " Checked \(date.formatted(date: .omitted, time: .shortened))." }
        var chips: [CountChip] = []
        if !model.checks.isEmpty {
            chips.append(CountChip(symbol: "checkmark.circle.fill", text: "\(model.count(.pass)) pass", color: .green))
            if warnings > 0 { chips.append(CountChip(symbol: "exclamationmark.triangle.fill", text: "\(warnings) warning\(warnings == 1 ? "" : "s")", color: .orange)) }
            if fails > 0 { chips.append(CountChip(symbol: "xmark.octagon.fill", text: "\(fails) off", color: .red)) }
            if unknown > 0 { chips.append(CountChip(symbol: "questionmark.circle", text: "\(unknown) unread", color: .secondary, dimmed: true)) }
        }
        return SectionHeader(title: "Security", subtitle: subtitle, symbol: "lock.shield.fill", color: color, chips: chips, isBusy: model.isChecking) {
            if !model.checks.isEmpty {
                DonutRing(good: model.count(.pass), total: model.checks.count, color: color, size: 58)
            }
        } actions: {
            Button {
                model.refresh()
            } label: {
                Label("Check Again", systemImage: "arrow.clockwise")
            }
            .disabled(model.isChecking)
        }
    }
}

private struct PostureRow: View {
    let check: PostureCheck
    let openSettings: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            IconTile(symbol: check.status.symbol, color: check.status == .unknown ? .gray : check.status.color, size: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(check.title).font(.body.weight(.medium))
                Text(check.summary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let advice = check.advice {
                    Text(advice)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
            Spacer(minLength: 12)
            if check.settingsURL != nil, check.status != .pass {
                Button("Open Settings", action: openSettings)
                    .buttonStyle(.glass)
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 5)
        .contextMenu {
            if check.settingsURL != nil { Button("Open in System Settings", action: openSettings) }
        }
    }
}

extension PostureGroup {
    var explanation: String {
        switch self {
        case .protections: "Whether the protections built into macOS are on."
        case .tampering: "Settings adware and malware change to redirect or watch your traffic."
        }
    }
}

extension PostureStatus {
    var color: Color {
        switch self {
        case .pass: .green
        case .warning: .orange
        case .fail: .red
        case .unknown: .secondary
        }
    }

    var symbol: String {
        switch self {
        case .pass: "checkmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .fail: "xmark.octagon.fill"
        case .unknown: "questionmark.circle"
        }
    }
}
