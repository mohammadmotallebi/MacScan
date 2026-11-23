import MacScanCore
import SwiftUI

/// The Privacy section: which apps can use the camera, microphone, screen and files. The only change it can
/// make is removing the permissions of apps that are no longer installed.
struct PrivacyView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        @Bindable var model = state.privacy
        VStack(spacing: 0) {
            header(model)
            Divider()

            if let report = model.report {
                content(report, model: model)
            } else {
                SectionEmptyState(
                    symbol: "hand.raised.fill", color: .pink,
                    title: model.isChecking ? "Reading permissions…" : "Privacy permissions",
                    message: "Shows which apps can use your camera, microphone, screen and files. MacScan only reads the list.",
                    isBusy: model.isChecking, buttonTitle: "Check Privacy", action: { model.refresh() })
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
                SectionEmptyState(
                    symbol: "lock.trianglebadge.exclamationmark.fill", color: .orange,
                    title: "Full Disk Access needed",
                    message: "macOS keeps the list of permissions private. Give MacScan Full Disk Access, reopen it, and check again.",
                    buttonTitle: "Show Me How", action: { state.fdaPrompt = FDAPrompt(paths: []) })
            } else {
                SectionEmptyState(
                    symbol: "questionmark.circle", color: .gray,
                    title: "Couldn't read the permissions",
                    message: problem(report) ?? "macOS's list of permissions is empty.")
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
                SectionEmptyState(symbol: "checkmark.circle.fill", color: .green, title: "Nothing flagged",
                                  message: "No app with a permission looks out of place.")
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
                                    Label {
                                        Text(permission.title).font(.title3.weight(.semibold)).foregroundStyle(.primary)
                                    } icon: {
                                        IconTile(symbol: permission.symbol, color: permission.color, size: 22)
                                    }
                                    .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 5 }
                                    Text(permission.explanation)
                                        .font(.callout)
                                        .foregroundStyle(.secondary)
                                    Spacer()
                                    Button("Open Settings") { model.openSettings(for: permission) }
                                        .buttonStyle(.glass)
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
            SectionFootnote(text: "MacScan only reads these permissions, and can remove the ones of apps that are gone. Change the rest in System Settings › Privacy & Security.")
        }
    }

    /// Why a list couldn't be read, when the reason isn't Full Disk Access.
    private func problem(_ report: PrivacyReport) -> String? {
        for source in [report.user, report.system] {
            if case .failed(let why) = source { return why }
        }
        return nil
    }

    private func header(_ model: PrivacyModel) -> some View {
        @Bindable var model = model
        let report = model.report
        let warnings = report?.count(.warning) ?? 0
        let review = report?.count(.review) ?? 0
        let apps = Set((report?.grants ?? []).filter { $0.decision != .denied }.map(\.client)).count
        let hasRows = report?.grants.isEmpty == false
        let color: Color = !hasRows ? .pink : warnings > 0 ? .orange : review > 0 ? .blue : .green
        var subtitle = !hasRows
            ? (model.isChecking ? "Checking…" : report == nil ? "Not checked yet" : "Nothing to show")
            : warnings > 0 ? "\(warnings) \(warnings == 1 ? "permission needs" : "permissions need") a look."
            : review > 0 ? "\(review) worth a look." : "Nothing looks out of place."
        if let date = model.lastChecked { subtitle += " Checked \(date.formatted(date: .omitted, time: .shortened))." }
        var chips: [CountChip] = []
        if hasRows {
            chips.append(CountChip(symbol: "app.fill", text: "\(apps) app\(apps == 1 ? "" : "s")", color: .pink))
            if warnings > 0 { chips.append(CountChip(symbol: "exclamationmark.triangle.fill", text: "\(warnings) risky", color: .orange)) }
            if review > 0 { chips.append(CountChip(symbol: "eye.fill", text: "\(review) to review", color: .blue)) }
            if !model.leftovers.isEmpty { chips.append(CountChip(symbol: "trash.fill", text: "\(model.leftovers.count) leftover\(model.leftovers.count == 1 ? "" : "s")", color: .gray)) }
        }
        return SectionHeader(title: "Privacy", subtitle: subtitle, symbol: "hand.raised.fill", color: color, chips: chips,
                             isBusy: model.isChecking || model.isRemoving) {
            Toggle("Flagged only", isOn: $model.flaggedOnly)
                .toggleStyle(.switch)
                .controlSize(.small)
                .disabled(!hasRows)
            if !model.leftovers.isEmpty {
                Button {
                    model.pendingRemoval = model.leftovers
                } label: {
                    Label("Remove Leftovers…", systemImage: "trash")
                }
                .disabled(model.isChecking || model.isRemoving)
                .help("Remove the permissions of apps that are no longer installed")
            }
            Button {
                model.refresh()
            } label: {
                Label("Check Again", systemImage: "arrow.clockwise")
            }
            .disabled(model.isChecking || model.isRemoving)
        }
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
    var color: Color {
        switch self {
        case .camera, .microphone: .green
        case .screenRecording: .red
        case .accessibility, .inputMonitoring: .blue
        case .fullDiskAccess, .appManagement: .gray
        case .automation, .developerTools: .indigo
        case .filesAndFolders: .cyan
        case .contacts: .brown
        case .calendar, .reminders: .orange
        case .photos: .pink
        }
    }

    var symbol: String {
        switch self {
        case .camera: "camera.fill"
        case .microphone: "mic.fill"
        case .screenRecording: "rectangle.dashed.badge.record"
        case .accessibility: "accessibility"
        case .inputMonitoring: "keyboard.fill"
        case .fullDiskAccess: "internaldrive.fill"
        case .automation: "gearshape.2.fill"
        case .filesAndFolders: "folder.fill"
        case .contacts: "person.crop.circle.fill"
        case .calendar: "calendar"
        case .reminders: "list.bullet"
        case .photos: "photo.fill"
        case .appManagement: "square.grid.2x2.fill"
        case .developerTools: "hammer.fill"
        }
    }
}
