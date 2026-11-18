import MacScanCore
import SwiftUI

/// The Security section: whether macOS's own protections are on. Nothing here changes a setting.
struct SecurityView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        let model = state.security
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                if model.checks.isEmpty {
                    Text(model.isChecking ? "Checking…" : "Not checked yet").foregroundStyle(.secondary)
                } else {
                    summary(model)
                }
                Spacer()
                if model.isChecking { ProgressView().controlSize(.small) }
                if let date = model.lastChecked {
                    Text("Checked \(date.formatted(date: .omitted, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Button("Check Again") { model.refresh() }
                    .disabled(model.isChecking)
            }
            .padding(12)
            Divider()

            if model.checks.isEmpty {
                ContentUnavailableView {
                    Label("Security settings", systemImage: "lock.shield")
                } description: {
                    Text("Checks whether the protections built into macOS are turned on.\nMacScan only reads them; it never changes a setting.")
                }
            } else {
                List(model.checks) { check in
                    PostureRow(check: check) { model.openSettings(for: check) }
                }
                .listStyle(.inset)
                Divider()
                Text("MacScan only reads these settings. Change them yourself in System Settings.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Security")
        .task {
            if model.checks.isEmpty { model.refresh() }
        }
    }

    @ViewBuilder
    private func summary(_ model: SecurityModel) -> some View {
        let attention = model.count(.fail) + model.count(.warning)
        Label(attention == 0 ? "Everything checked is on" : "\(attention) \(attention == 1 ? "setting needs" : "settings need") attention",
              systemImage: attention == 0 ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
            .font(.headline)
            .foregroundStyle(model.count(.fail) > 0 ? .red : attention > 0 ? .orange : .green)
        if model.count(.unknown) > 0 {
            Text("\(model.count(.unknown)) couldn't be read")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }
}

private struct PostureRow: View {
    let check: PostureCheck
    let openSettings: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: check.status.symbol)
                .foregroundStyle(check.status.color)
                .font(.title3)
                .frame(width: 22)
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
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 5)
        .contextMenu {
            if check.settingsURL != nil { Button("Open in System Settings", action: openSettings) }
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
