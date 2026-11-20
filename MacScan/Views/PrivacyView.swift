import MacScanCore
import SwiftUI

/// The Privacy section: which apps can use the camera, microphone, screen and files. The only change it can
/// make is removing the permissions of apps that are no longer installed.
struct PrivacyView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        @Bindable var model = state.privacy
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                if let report = model.report, !report.grants.isEmpty {
                    summary(report)
                } else {
                    Text(model.isChecking ? "Checking…" : model.report == nil ? "Not checked yet" : "Nothing to show")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if model.isChecking { ProgressView().controlSize(.small) }
                if let date = model.lastChecked {
                    Text("Checked \(date.formatted(date: .omitted, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Toggle("Flagged only", isOn: $model.flaggedOnly)
                    .toggleStyle(.checkbox)
                    .disabled(model.report?.grants.isEmpty != false)
                if !model.leftovers.isEmpty {
                    Button("Remove Leftovers…") { model.pendingRemoval = model.leftovers }
                        .disabled(model.isChecking || model.isRemoving)
                        .help("Remove the permissions of apps that are no longer installed")
                }
                Button("Check Again") { model.refresh() }
                    .disabled(model.isChecking || model.isRemoving)
            }
            .padding(12)
            Divider()

            if let report = model.report {
                content(report, model: model)
            } else {
                ContentUnavailableView {
                    Label("Privacy permissions", systemImage: "hand.raised")
                } description: {
                    Text("Shows which apps can use your camera, microphone, screen and files.\nMacScan only reads the list.")
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Privacy")
        .confirmationDialog(
            model.pendingRemoval.count == 1 ? "Remove this permission?" : "Remove \(model.pendingRemoval.count) leftover permissions?",
            isPresented: Binding(get: { !model.pendingRemoval.isEmpty }, set: { if !$0 { model.pendingRemoval = [] } })
        ) {
            let grants = model.pendingRemoval
            Button(grants.count == 1 ? "Remove" : "Remove All", role: .destructive) { model.confirmRemoval(grants) }
            Button("Cancel", role: .cancel) {}
        } message: {
            let grants = model.pendingRemoval
            Text(grants.prefix(8).map { "\($0.permission.title): \($0.client)" }.joined(separator: "\n")
                 + (grants.count > 8 ? "\n…and \(grants.count - 8) more" : "")
                 + "\n\nThese apps are not on this Mac any more. If you install one again, macOS will ask for the permission again.")
        }
        .alert("Couldn't remove everything",
               isPresented: Binding(get: { model.removalError != nil }, set: { if !$0 { model.removalError = nil } })) {
            Button("OK") {}
        } message: {
            Text((model.removalError ?? "") + "\n\nYou can remove it yourself in System Settings: select the app in the list and click the minus button.")
        }
        .task {
            if model.report == nil { model.refresh() }
        }
    }

    @ViewBuilder
    private func content(_ report: PrivacyReport, model: PrivacyModel) -> some View {
        if report.grants.isEmpty {
            if report.needsFullDiskAccess {
                ContentUnavailableView {
                    Label("Full Disk Access needed", systemImage: "lock.shield")
                } description: {
                    Text("macOS keeps the list of permissions private.\nGive MacScan Full Disk Access, reopen it, and check again.")
                } actions: {
                    Button("Show Me How") { state.fdaPrompt = FDAPrompt(paths: []) }
                }
            } else {
                ContentUnavailableView {
                    Label("Couldn't read the permissions", systemImage: "questionmark.circle")
                } description: {
                    Text(problem(report) ?? "macOS's list of permissions is empty.")
                }
            }
        } else {
            let shown = model.flaggedOnly ? report.grants.filter { $0.risk != .none } : report.grants
            if report.needsFullDiskAccess || problem(report) != nil {
                Label(report.needsFullDiskAccess
                      ? "Part of the list couldn't be read. Give MacScan Full Disk Access to see everything."
                      : "Part of the list couldn't be read: \(problem(report) ?? "")",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                Divider()
            }
            if shown.isEmpty {
                ContentUnavailableView("Nothing flagged", systemImage: "checkmark.circle",
                                       description: Text("No app with a permission looks out of place."))
            } else {
                List {
                    ForEach(PrivacyPermission.allCases) { permission in
                        let grants = shown.filter { $0.permission == permission }
                        if !grants.isEmpty {
                            Section {
                                ForEach(grants) { grant in
                                    PrivacyRow(grant: grant,
                                               remove: grant.canRemove && !model.isRemoving ? { model.pendingRemoval = [grant] } : nil,
                                               reveal: { model.reveal(grant) },
                                               openSettings: { model.openSettings(for: permission) })
                                }
                            } header: {
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Label(permission.title, systemImage: permission.symbol)
                                        .font(.headline)
                                        .foregroundStyle(.primary)
                                    Text(permission.explanation)
                                        .font(.callout)
                                        .foregroundStyle(.secondary)
                                    Spacer()
                                    Button("Open Settings") { model.openSettings(for: permission) }
                                        .controlSize(.small)
                                }
                                .padding(.vertical, 2)
                            }
                        }
                    }
                }
                .listStyle(.inset)
            }
            Divider()
            Text("MacScan only reads these permissions, and can remove the ones of apps that are gone. Change the rest in System Settings › Privacy & Security.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
        }
    }

    /// Why a list couldn't be read, when the reason isn't Full Disk Access.
    private func problem(_ report: PrivacyReport) -> String? {
        for source in [report.user, report.system] {
            if case .failed(let why) = source { return why }
        }
        return nil
    }

    @ViewBuilder
    private func summary(_ report: PrivacyReport) -> some View {
        let warnings = report.count(.warning)
        let review = report.count(.review)
        let apps = Set(report.grants.filter { $0.decision != .denied }.map(\.client)).count
        Label(warnings > 0 ? "\(warnings) \(warnings == 1 ? "permission needs" : "permissions need") attention"
              : review > 0 ? "\(review) worth a look" : "Nothing looks out of place",
              systemImage: warnings > 0 ? "exclamationmark.triangle.fill" : review > 0 ? "eye.fill" : "checkmark.circle.fill")
            .font(.headline)
            .foregroundStyle(warnings > 0 ? .orange : review > 0 ? .blue : .green)
        Text("\(apps) \(apps == 1 ? "app has" : "apps have") a permission")
            .font(.callout)
            .foregroundStyle(.secondary)
    }
}

private struct PrivacyRow: View {
    let grant: PrivacyGrant
    /// Set for a leftover of an app that is gone.
    let remove: (() -> Void)?
    let reveal: () -> Void
    let openSettings: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Group {
                if let path = grant.path {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable()
                } else {
                    Image(systemName: "questionmark.app.dashed").resizable().foregroundStyle(.secondary)
                }
            }
            .frame(width: 26, height: 26)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(grant.name).font(.body.weight(.medium))
                    if let detail = grant.detail {
                        Text(detail).font(.callout).foregroundStyle(.secondary)
                    }
                }
                Text(grant.signer ?? grant.client)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                ForEach(grant.reasons, id: \.self) { reason in
                    Label(reason, systemImage: grant.risk == .warning ? "exclamationmark.triangle.fill" : "eye")
                        .font(.callout)
                        .foregroundStyle(grant.risk == .warning ? .orange : .primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            if let remove {
                Button("Remove…", action: remove)
                    .controlSize(.small)
            }
            Text(grant.decision.label)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(grant.decision.color.opacity(0.15), in: Capsule())
                .foregroundStyle(grant.decision.color)
        }
        .padding(.vertical, 4)
        .opacity(grant.decision == .denied ? 0.6 : 1)
        .help(grant.path ?? grant.client)
        .contextMenu {
            if grant.path != nil { Button("Reveal in Finder", action: reveal) }
            if let remove { Button("Remove Permission…", action: remove) }
            Button("Open in System Settings", action: openSettings)
            Button("Copy App ID") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(grant.client, forType: .string)
            }
        }
    }
}

extension PrivacyDecision {
    var label: String {
        switch self {
        case .allowed: "Allowed"
        case .limited: "Limited"
        case .denied: "Denied"
        }
    }

    var color: Color {
        switch self {
        case .allowed: .green
        case .limited: .blue
        case .denied: .secondary
        }
    }
}

extension PrivacyPermission {
    var symbol: String {
        switch self {
        case .camera: "camera"
        case .microphone: "mic"
        case .screenRecording: "rectangle.dashed.badge.record"
        case .accessibility: "accessibility"
        case .inputMonitoring: "keyboard"
        case .fullDiskAccess: "internaldrive"
        case .automation: "gearshape.2"
        case .filesAndFolders: "folder"
        case .contacts: "person.crop.circle"
        case .calendar: "calendar"
        case .reminders: "list.bullet"
        case .photos: "photo"
        case .appManagement: "square.grid.2x2"
        case .developerTools: "hammer"
        }
    }
}
