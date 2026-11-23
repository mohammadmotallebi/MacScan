import MacScanCore
import SwiftUI

struct ResultsView: View {
    @Environment(AppState.self) private var state
    let session: ScanSession

    @State private var filter: SeverityFilter = .all
    @State private var search = ""
    @State private var changedOnly = false
    /// Set by clicking an area tile of a Full Check.
    @State private var areaFilter: ScanArea?
    @State private var selection: Set<Finding.ID> = []
    @State private var sortOrder = [KeyPathComparator(\Finding.severity, order: .reverse)]

    private var filtered: [Finding] {
        let query = search.trimmingCharacters(in: .whitespaces)
        return scoped
            .filter { filter.matches($0.severity) }
            .filter { !changedOnly || !hasChanges || $0.change != nil }
            .filter { query.isEmpty || $0.path.localizedCaseInsensitiveContains(query) || $0.reason.localizedCaseInsensitiveContains(query) }
            .sorted(using: sortOrder)
    }

    /// The results of the chosen area, or all of them.
    private var scoped: [Finding] {
        guard let areaFilter else { return session.findings }
        return session.findings.filter { $0.area == areaFilter }
    }

    /// Startup items that are new or changed since the previous Startup Items scan.
    private var hasChanges: Bool { scoped.contains { $0.change != nil } }

    private var selectedFinding: Finding? {
        guard selection.count == 1, let id = selection.first else { return nil }
        return session.findings.first { $0.id == id }
    }

    var body: some View {
        VStack(spacing: 0) {
            if let info = session.fullCheck {
                FullCheckSummaryView(session: session, info: info, areaFilter: $areaFilter)
                FullCheckChangesView(info: info)
                Divider()
            }
            HStack(spacing: 6) {
                ForEach(SeverityFilter.allCases) { f in
                    FilterCapsule(title: f.title, count: f == .all ? scoped.count : count(f.severity!),
                                  color: f.severity?.color ?? .accentColor, isOn: filter == f) {
                        filter = f
                    }
                }
                if hasChanges {
                    Toggle("New or changed (\(scoped.filter { $0.change != nil }.count))", isOn: $changedOnly)
                        .toggleStyle(.switch)
                        .controlSize(.small)
                        .padding(.leading, 8)
                        .help("Show only startup items or browser extensions that were added or changed since the previous scan of that kind")
                }
                Spacer()
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Filter by path or reason", text: $search)
                        .textFieldStyle(.plain)
                    if !search.isEmpty {
                        Button {
                            search = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .frame(maxWidth: 260)
                .glassCard(radius: 14)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Table(filtered, selection: $selection, sortOrder: $sortOrder) {
                TableColumn("Severity", value: \.severity) { f in
                    HStack(spacing: 6) {
                        IconTile(symbol: f.severity.symbol, color: f.severity.color, size: 20)
                        Text(f.severity.title)
                            .font(.callout.weight(.medium))
                            .foregroundStyle(f.severity.color)
                    }
                }
                .width(min: 90, ideal: 105, max: 120)

                TableColumn("Path", value: \.path) { f in
                    let quarantined = state.isQuarantined(f.path)
                    let trashed = state.trashedPaths.contains(f.path) || quarantined
                    HStack(spacing: 8) {
                        FileIcon(path: f.path, size: 22)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(f.fileName)
                                .fontWeight(.medium)
                                .strikethrough(trashed)
                                .lineLimit(1)
                            Text(quarantined ? "Moved to Quarantine" : trashed ? "Moved to Trash" : (f.path as NSString).deletingLastPathComponent)
                                .font(.caption)
                                .foregroundStyle(trashed ? AnyShapeStyle(Color.purple) : AnyShapeStyle(.secondary))
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    .opacity(trashed ? 0.6 : 1)
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
                        if let change = f.change { ChangeBadge(change: change) }
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
                FindingDetailView(finding: f, sessionID: session.id)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.smooth(duration: 0.25), value: selectedFinding?.id)
    }

    private func count(_ severity: Severity) -> Int {
        scoped.lazy.filter { $0.severity == severity }.count
    }
}

/// One tile per area of a Full Check, plus the macOS security settings and privacy permissions.
/// Clicking an area shows only its results.
struct FullCheckSummaryView: View {
    @Environment(AppState.self) private var state
    let session: ScanSession
    let info: FullCheckInfo
    @Binding var areaFilter: ScanArea?

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            ForEach(FullCheck.areas) { area in
                let summary = session.summary(of: area)
                Button {
                    areaFilter = areaFilter == area ? nil : area
                } label: {
                    FullCheckTile(
                        title: area.title, symbol: area.symbol,
                        color: summary.isEmpty ? .secondary : summary.worst.color,
                        line: Self.line(for: summary),
                        isSelected: areaFilter == area)
                }
                .buttonStyle(.plain)
                .help(areaFilter == area ? "Show all results" : "Show only \(area.title) results")
            }
            Button {
                state.selectedSection = .security
            } label: {
                FullCheckTile(
                    title: "Security Settings", symbol: "lock.shield",
                    color: securityColor, line: securityLine, isSelected: false)
            }
            .buttonStyle(.plain)
            .help(securityHelp)
            if let privacy = info.privacy {
                Button {
                    state.selectedSection = .privacy
                } label: {
                    FullCheckTile(
                        title: "Privacy", symbol: "hand.raised",
                        color: Self.color(for: privacy), line: Self.line(for: privacy), isSelected: false)
                }
                .buttonStyle(.plain)
                .help(Self.help(for: privacy))
            }
            if let network = info.network {
                Button {
                    state.selectedSection = .network
                    state.network.refresh()
                } label: {
                    FullCheckTile(
                        title: "Network", symbol: "network",
                        color: network.warnings > 0 ? .orange : network.review > 0 ? .blue : .green,
                        line: Self.line(for: network), isSelected: false)
                }
                .buttonStyle(.plain)
                .help("\(network.programs) programs used the network when this check ran; \(network.internet) talked to the internet and \(network.openToOthers) accepted connections from other computers. Open the Network section for now.")
            }
        }
        .padding(8)
    }

    static func line(for summary: AreaSummary) -> String {
        if summary.isEmpty { return "Nothing found to check" }
        var parts: [String] = []
        if summary.threats > 0 { parts.append("\(summary.threats) threat\(summary.threats == 1 ? "" : "s")") }
        if summary.warnings > 0 { parts.append("\(summary.warnings) warning\(summary.warnings == 1 ? "" : "s")") }
        return parts.isEmpty ? "No issues · \(summary.clean.formatted()) checked" : parts.joined(separator: " · ")
    }

    static func line(for network: NetworkSummary) -> String {
        var parts: [String] = []
        if network.warnings > 0 { parts.append("\(network.warnings) warning\(network.warnings == 1 ? "" : "s")") }
        if network.review > 0 { parts.append("\(network.review) worth a look") }
        return parts.isEmpty ? "Nothing odd · \(network.programs) programs" : parts.joined(separator: " · ")
    }

    static func color(for privacy: PrivacySummary) -> Color {
        guard privacy.readable else { return .secondary }
        return privacy.warnings > 0 ? .orange : privacy.review > 0 ? .blue : .green
    }

    static func line(for privacy: PrivacySummary) -> String {
        guard privacy.readable else { return "Needs Full Disk Access" }
        var parts: [String] = []
        if privacy.warnings > 0 { parts.append("\(privacy.warnings) warning\(privacy.warnings == 1 ? "" : "s")") }
        let others = privacy.review - privacy.leftovers
        if others > 0 { parts.append("\(others) worth a look") }
        if privacy.leftovers > 0 { parts.append("\(privacy.leftovers) leftover\(privacy.leftovers == 1 ? "" : "s")") }
        return parts.isEmpty ? "Nothing out of place · \(privacy.apps) apps" : parts.joined(separator: " · ")
    }

    static func help(for privacy: PrivacySummary) -> String {
        guard privacy.readable else { return "MacScan couldn't read the privacy permissions. Give it Full Disk Access, then open the Privacy section." }
        var text = "\(privacy.apps) \(privacy.apps == 1 ? "app had" : "apps had") a permission when this check ran."
        if privacy.leftovers > 0 { text += " \(privacy.leftovers) belonged to apps that are no longer installed; you can remove them there." }
        if privacy.partial { text += " Part of the list couldn't be read." }
        return text + " Open the Privacy section for the current state."
    }

    private var securityColor: Color {
        guard let security = info.security else { return .secondary }
        return security.problems.isEmpty ? .green : .orange
    }

    private var securityLine: String {
        guard let security = info.security else { return "Not checked" }
        return "\(security.passed) of \(security.total) pass"
    }

    private var securityHelp: String {
        guard let security = info.security else { return "The security settings could not be read. Open the Security section to check them." }
        let found = security.problems.isEmpty ? "Everything passed when this check ran." : "Not passing when this check ran: \(security.problems.joined(separator: ", "))."
        return found + " Open the Security section for the current state."
    }
}

/// "Since last Full Check": what is new or different from the previous one.
struct FullCheckChangesView: View {
    @Environment(AppState.self) private var state
    let info: FullCheckInfo
    @State private var expanded = true

    var body: some View {
        Group {
            if let changes = info.changes, let date = info.comparedWith {
                if changes.isEmpty {
                    Label("Nothing changed since the last Full Check (\(date.formatted(date: .abbreviated, time: .shortened))).",
                          systemImage: "checkmark.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    DisclosureGroup(isExpanded: $expanded) {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(changes) { change in
                                row(change)
                            }
                        }
                        .padding(.top, 4)
                    } label: {
                        let attention = changes.filter(\.needsAttention).count
                        Label("\(changes.count) change\(changes.count == 1 ? "" : "s") since the last Full Check (\(date.formatted(date: .abbreviated, time: .shortened)))",
                              systemImage: attention > 0 ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(attention > 0 ? .orange : .green)
                    }
                }
            } else if info.tracked == true {
                Label("First Full Check. Next time MacScan shows what changed since this one.", systemImage: "flag")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .glassCard(radius: 16)
        .padding(.horizontal, 8)
        .padding(.bottom, 8)
    }

    @ViewBuilder
    private func row(_ change: FullCheckChange) -> some View {
        HStack(alignment: .center, spacing: 8) {
            IconTile(symbol: change.kind.symbol, color: change.kind.color, size: 20)
            Text(change.kind.label).font(.caption.weight(.semibold)).foregroundStyle(change.kind.color)
                .frame(width: 92, alignment: .leading)
            Text(change.title).font(.callout.weight(.medium))
            Text(change.detail).font(.callout).foregroundStyle(.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            switch change.kind {
            case .newPermission:
                Button("Privacy") { state.selectedSection = .privacy }.controlSize(.small).buttonStyle(.glass)
            case .settingChanged, .settingFixed:
                Button("Security") { state.selectedSection = .security }.controlSize(.small).buttonStyle(.glass)
            case .newListener:
                Button("Network") { state.selectedSection = .network }.controlSize(.small).buttonStyle(.glass)
            case .newApp:
                if let path = change.path {
                    Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }.controlSize(.small).buttonStyle(.glass)
                }
            }
        }
    }
}

extension FullCheckChange.Kind {
    var label: String {
        switch self {
        case .newApp: "New app"
        case .newPermission: "New permission"
        case .settingChanged: "Setting changed"
        case .settingFixed: "Fixed"
        case .newListener: "New program online"
        }
    }

    var symbol: String {
        switch self {
        case .newApp: "app.badge.fill"
        case .newPermission: "hand.raised.fill"
        case .settingChanged: "exclamationmark.triangle.fill"
        case .settingFixed: "checkmark.circle.fill"
        case .newListener: "network"
        }
    }

    var color: Color {
        switch self {
        case .newApp: .blue
        case .newPermission, .settingChanged, .newListener: .orange
        case .settingFixed: .green
        }
    }
}

struct FullCheckTile: View {
    let title: String
    let symbol: String
    let color: Color
    let line: String
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 10) {
            IconTile(symbol: symbol, color: color == .secondary ? .gray : color, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                Text(line)
                    .font(.caption)
                    .foregroundStyle(color)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 9)
        .contentShape(.rect(cornerRadius: 14))
        .glassCard(tint: isSelected ? .accentColor : nil, radius: 14, interactive: true)
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(isSelected ? AnyShapeStyle(.tint) : AnyShapeStyle(.clear), lineWidth: 1.5))
    }
}

extension ScanArea {
    var symbol: String {
        switch self {
        case .applications: "app.badge.checkmark"
        case .startupItems: "power.circle"
        case .runningProcesses: "cpu"
        case .browserExtensions: "puzzlepiece.extension"
        case .files: "folder"
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
        if state.isOrphanedLaunchItem(finding) {
            Button("Remove Orphaned Startup Item…", role: .destructive) { state.requestOrphanRemoval(finding) }
                .disabled(state.orphanRemovalsInFlight.contains(finding.path))
        }
        Button("Quarantine…") { state.requestQuarantine(finding, sessionID: sessionID) }
            .disabled(state.isRemoved(finding.path))
        Button("Move to Trash…", role: .destructive) { state.requestTrash(finding, sessionID: sessionID) }
            .disabled(state.isRemoved(finding.path))
    }
}

struct FindingDetailView: View {
    @Environment(AppState.self) private var state
    let finding: Finding
    let sessionID: UUID

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                FileIcon(path: finding.path, size: 44)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(finding.fileName).font(.title3.weight(.semibold)).lineLimit(1).textSelection(.enabled)
                        CountChip(symbol: finding.severity.symbol, text: finding.severity.title, color: finding.severity.color)
                        if let change = finding.change { ChangeBadge(change: change) }
                    }
                    Text(finding.reason)
                        .font(.callout.weight(.medium))
                        .foregroundStyle(finding.severity == .clean ? AnyShapeStyle(.secondary) : AnyShapeStyle(finding.severity.color))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }

            ScrollView {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 5) {
                    fact("Found by", finding.engine.title)
                    fact("Path", finding.path, mono: true)
                    if let detail = finding.detail, !detail.isEmpty { fact("Details", detail) }
                    if let hash = finding.sha256 { fact("SHA-256", hash, mono: true) }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 110)

            HStack(spacing: 8) {
                Button {
                    state.reveal(finding)
                } label: {
                    Label("Reveal", systemImage: "folder")
                }
                Button {
                    state.lookUpOnVirusTotal(finding, sessionID: sessionID)
                } label: {
                    Label("VirusTotal", systemImage: "globe")
                }
                .disabled(!state.hasVirusTotalKey || state.vtLookupsInFlight.contains(finding.id))
                .help(state.hasVirusTotalKey ? "Sends only the SHA-256 hash" : "Add your API key in Settings › VirusTotal")
                Button {
                    state.ignore(finding, sessionID: sessionID)
                } label: {
                    Label("Ignore", systemImage: "eye.slash")
                }
                .disabled(finding.severity == .clean)
                if let app = state.owningApp(of: finding) {
                    Button {
                        state.openUninstaller(for: app)
                    } label: {
                        Label("Uninstall App…", systemImage: "trash.square")
                    }
                    .help("Remove \(app.lastPathComponent) and everything that belongs to it")
                }
                Spacer()
                if state.isOrphanedLaunchItem(finding) {
                    Button(role: .destructive) {
                        state.requestOrphanRemoval(finding)
                    } label: {
                        Label("Remove Startup Item…", systemImage: "trash")
                    }
                    .buttonStyle(.glassProminent)
                    .tint(.red)
                    .disabled(state.orphanRemovalsInFlight.contains(finding.path))
                    .help("Stops this leftover startup item and moves it to the Trash. Its program no longer exists.")
                } else {
                    Button {
                        state.requestQuarantine(finding, sessionID: sessionID)
                    } label: {
                        Label("Quarantine…", systemImage: "archivebox")
                    }
                    .disabled(state.isRemoved(finding.path))
                    .help("Moves the item into MacScan's locked quarantine. You can restore it later.")
                    Button(role: .destructive) {
                        state.requestTrash(finding, sessionID: sessionID)
                    } label: {
                        Label("Move to Trash…", systemImage: "trash")
                    }
                    .buttonStyle(.glassProminent)
                    .tint(.red)
                    .disabled(state.isRemoved(finding.path))
                }
            }
            .buttonStyle(.glass)
        }
        .padding(16)
        .glassCard(tint: finding.severity == .clean ? nil : finding.severity.color, radius: 20)
        .padding(12)
    }

    @ViewBuilder
    private func fact(_ label: String, _ value: String, mono: Bool = false) -> some View {
        GridRow {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value)
                .font(mono ? .caption.monospaced() : .callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// The Finder icon of a file, or a plain document icon if it's gone.
struct FileIcon: View {
    let path: String
    var size: CGFloat = 22

    var body: some View {
        Image(nsImage: NSWorkspace.shared.icon(forFile: path))
            .resizable()
            .interpolation(.high)
            .frame(width: size, height: size)
    }
}

/// A rounded filter button with a count, e.g. "Warnings 4".
struct FilterCapsule: View {
    let title: String
    let count: Int
    let color: Color
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Text(title).fontWeight(.medium)
                Text(count.formatted())
                    .monospacedDigit()
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background((isOn ? Color.white : color).opacity(isOn ? 0.25 : 0.15), in: Capsule())
            }
            .foregroundStyle(isOn ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(isOn ? AnyShapeStyle(color.gradient) : AnyShapeStyle(.clear), in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .glassEffect(isOn ? .regular.tint(color.opacity(0.4)).interactive() : .regular.interactive(), in: .capsule)
        .animation(.smooth(duration: 0.2), value: isOn)
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

/// Marks a startup item that is new or changed since the previous Startup Items scan.
struct ChangeBadge: View {
    let change: FindingChange

    var body: some View {
        Text(change.title.uppercased())
            .font(.caption2.weight(.bold))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(.blue.opacity(0.18), in: Capsule())
            .foregroundStyle(.blue)
            .fixedSize()
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
