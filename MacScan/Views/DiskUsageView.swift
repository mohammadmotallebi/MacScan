import MacScanCore
import SwiftUI

/// Find the folders and files that take the most space.
struct DiskUsageView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        @Bindable var model = state.diskUsage
        VStack(spacing: 0) {
            DiskUsageToolbar()
            Divider()
            Group {
                if model.isScanning {
                    DiskUsageProgressView(progress: model.progress, location: model.locationName)
                } else if let report = model.report {
                    DiskUsageReportView(report: report)
                } else {
                    SectionEmptyState(
                        symbol: "chart.pie.fill", color: .orange, title: "Find what takes up space",
                        message: "MacScan measures every folder in the location you choose and lists the biggest folders and files. Nothing is changed until you choose to move something to the Trash.",
                        buttonTitle: "Measure \(model.locationName)", action: { model.scan() })
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle("Disk Usage")
        .confirmationDialog("Move to Trash?",
                            isPresented: Binding(get: { model.pendingTrash != nil }, set: { if !$0 { model.pendingTrash = nil } }),
                            presenting: model.pendingTrash) { pending in
            Button("Move “\(pending.item.name)” to Trash", role: .destructive) { model.confirmTrash(pending) }
            Button("Cancel", role: .cancel) {}
        } message: { pending in
            Text("\(pending.item.path)\n\(pending.item.size.formatted(.byteCount(style: .file)))\(pending.item.isDirectory ? " in \(pending.item.fileCount.formatted()) files" : "")\n\nIt goes to the Trash, where you can restore it until you empty the Trash.")
        }
        .sheet(isPresented: $model.showingCleanupSheet) { CleanupSheet() }
        .confirmationDialog("Move all to Trash?",
                            isPresented: Binding(get: { model.pendingGroupTrash != nil }, set: { if !$0 { model.pendingGroupTrash = nil } }),
                            presenting: model.pendingGroupTrash) { pending in
            Button("Move \(pending.members.count) Folders to Trash", role: .destructive) { model.confirmTrashGroup(pending) }
            Button("Cancel", role: .cancel) {}
        } message: { pending in
            let total = pending.members.reduce(Int64(0)) { $0 + $1.item.size }
            Text("\(pending.title): \(pending.members.count) folders, \(total.formatted(.byteCount(style: .file)))\n\n"
                 + pending.members.prefix(8).map { "• " + $0.item.path.replacingOccurrences(of: AppPaths.home.path, with: "~") }.joined(separator: "\n")
                 + (pending.members.count > 8 ? "\n…and \(pending.members.count - 8) more" : "")
                 + "\n\n\(pending.members.first?.explanation ?? "")")
        }
        .confirmationDialog("Move contents to Trash?",
                            isPresented: Binding(get: { model.pendingEmpty != nil }, set: { if !$0 { model.pendingEmpty = nil } }),
                            presenting: model.pendingEmpty) { pending in
            Button("Move Everything in “\(pending.suggestion.item.name)” to Trash", role: .destructive) { model.confirmEmpty(pending) }
            Button("Cancel", role: .cancel) {}
        } message: { pending in
            Text("\(pending.suggestion.item.path)\n\(pending.suggestion.item.size.formatted(.byteCount(style: .file)))\n\n\(pending.suggestion.explanation)\n\nThe folder itself stays. Everything inside goes to the Trash, where you can restore it until you empty the Trash.")
        }
        .alert("How to clean this", isPresented: Binding(get: { model.infoMessage != nil }, set: { if !$0 { model.infoMessage = nil } })) {
            if let command = model.infoMessage.flatMap(CleanupSuggestionRow.command) {
                Button("Copy Command") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(command, forType: .string)
                }
            }
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.infoMessage ?? "")
        }
        .alert("Disk Usage", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }
}

struct DiskUsageToolbar: View {
    @Environment(AppState.self) private var state

    var body: some View {
        let model = state.diskUsage
        let report = model.isScanning ? nil : model.report
        let safe = model.suggestions.filter { $0.priority == .safe }.reduce(Int64(0)) { $0 + $1.item.size }
        var chips: [CountChip] = []
        if let report {
            chips.append(CountChip(symbol: "internaldrive.fill", text: report.totalSize.formatted(.byteCount(style: .file)), color: .orange))
            chips.append(CountChip(symbol: "doc.fill", text: "\(report.fileCount.formatted()) files", color: .gray))
            if safe > 0 { chips.append(CountChip(symbol: "sparkles", text: "\(safe.formatted(.byteCount(style: .file))) safe to clean", color: .green)) }
        }
        if let free = Self.freeSpace() {
            chips.append(CountChip(symbol: "externaldrive.fill", text: "\(free.formatted(.byteCount(style: .file))) free on disk", color: .blue))
        }
        return SectionHeader(
            title: "Disk Usage",
            subtitle: model.isScanning ? "Measuring \(model.locationName)…"
                : report == nil ? "See which folders and files take the most space." : "Biggest folders and files in \(model.locationName).",
            symbol: "chart.pie.fill", color: .orange, chips: chips, isBusy: model.isScanning
        ) {
            Menu {
                Button("Home Folder") { model.scan(AppPaths.home) }
                Button("Macintosh HD (whole disk)") { model.scan(URL(fileURLWithPath: "/")) }
                Divider()
                Button("Choose Folder…") { model.chooseLocation() }
            } label: {
                Label(model.locationName, systemImage: model.location.path == "/" ? "internaldrive" : "folder")
            }
            .fixedSize()
            .disabled(model.isScanning)
            .help("Choose what to measure")

            if model.isScanning {
                Button {
                    model.cancel()
                } label: {
                    Label("Cancel", systemImage: "xmark")
                }
            } else {
                Button {
                    model.scan()
                } label: {
                    Label(model.report == nil ? "Measure" : "Measure Again", systemImage: "arrow.clockwise")
                }
                .keyboardShortcut("r", modifiers: [.command, .option])
            }
        }
    }

    /// Free space on the startup disk.
    static func freeSpace() -> Int64? {
        let values = try? URL(fileURLWithPath: "/").resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values?.volumeAvailableCapacityForImportantUsage
    }
}

struct DiskUsageProgressView: View {
    let progress: DiskUsageProgress?
    let location: String

    var body: some View {
        VStack(spacing: 16) {
            SectionEmptyState(
                symbol: "chart.pie.fill", color: .orange, title: "Measuring \(location)…",
                message: progress.map { "\($0.filesScanned.formatted()) files · \($0.bytesCounted.formatted(.byteCount(style: .file)))" } ?? "Starting…",
                isBusy: true)
                .frame(maxHeight: 340)
            if let progress {
                Text(progress.currentFolder)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: 500)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .glassCard(radius: 12)
            }
        }
        .padding()
    }
}

struct DiskUsageReportView: View {
    @Environment(AppState.self) private var state
    let report: DiskUsageReport

    var body: some View {
        @Bindable var model = state.diskUsage
        VStack(spacing: 0) {
            if report.cancelled || report.unreadableCount > 0 {
                HStack(alignment: .firstTextBaseline) {
                    if report.cancelled {
                        Label("Measuring was cancelled; sizes are incomplete.", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    if report.unreadableCount > 0 {
                        Label("\(report.unreadableCount.formatted()) folder\(report.unreadableCount == 1 ? "" : "s") couldn't be read and aren't counted.",
                              systemImage: "lock.fill")
                            .foregroundStyle(.secondary)
                            .help(report.unreadable.prefix(20).joined(separator: "\n"))
                        Button("Full Disk Access…") { FullDiskAccess.openSettings() }
                            .controlSize(.small)
                    }
                    Spacer()
                }
                .font(.callout)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                Divider()
            }
            Picker("", selection: $model.tab) {
                ForEach(DiskUsageModel.Tab.allCases) { tab in
                    Text(tab == .cleanup && !model.suggestions.isEmpty ? "Cleanup (\(model.suggestions.count))" : tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .controlSize(.large)
            .fixedSize()
            .padding(10)

            switch model.tab {
            case .cleanup: CleanupList()
            case .folders: FolderBrowser(report: report)
            case .largestFiles: DiskItemList(items: report.largestFiles, scale: report.largestFiles.first?.size ?? 1, showFolder: true)
            case .largestFolders:
                let folders = report.largestFolders()
                DiskItemList(items: folders, scale: folders.first?.size ?? 1, showFolder: true)
            }
        }
    }
}

/// Drill-down list: the contents of one folder, biggest first.
struct FolderBrowser: View {
    @Environment(AppState.self) private var state
    let report: DiskUsageReport

    var body: some View {
        let model = state.diskUsage
        let current = model.currentFolder ?? report.root
        let folderSize = report.folder(current)?.size ?? report.totalSize
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(Array(model.breadcrumb.enumerated()), id: \.element.id) { index, crumb in
                        if index > 0 { Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary) }
                        Button(index == 0 ? (crumb.path == "/" ? "Macintosh HD" : crumb.name) : crumb.name) { model.open(crumb) }
                            .buttonStyle(.borderless)
                            .fontWeight(crumb.path == current ? .semibold : .regular)
                    }
                }
                .padding(.horizontal, 12)
            }
            .padding(.bottom, 6)
            Divider()
            DiskItemList(items: report.children(of: current), scale: max(folderSize, 1), showFolder: false)
        }
    }
}

/// A list of files/folders with size bars. Folders open on double-click.
struct DiskItemList: View {
    @Environment(AppState.self) private var state
    let items: [DiskItem]
    /// Size that a full-width bar stands for.
    let scale: Int64
    let showFolder: Bool
    @State private var selection: DiskItem.ID?

    var body: some View {
        let model = state.diskUsage
        List(selection: $selection) {
            ForEach(items) { item in
                DiskItemRow(item: item, fraction: Double(item.size) / Double(scale), showFolder: showFolder)
                    .tag(item.id)
                    .contextMenu {
                        if item.isDirectory && !item.isAggregate {
                            Button("Open") { model.open(item) }
                        }
                        Button("Reveal in Finder") { model.reveal(item) }
                        if !item.isAggregate {
                            Button("Copy Path") { model.copyPath(item) }
                            Divider()
                            Button("Move to Trash…", role: .destructive) { model.requestTrash(item) }
                                .disabled(model.trashRefusal(item) != nil)
                        }
                    }
            }
        }
        .contextMenu(forSelectionType: DiskItem.ID.self) { _ in } primaryAction: { ids in
            guard let id = ids.first, let item = items.first(where: { $0.id == id }) else { return }
            if item.isDirectory && !item.isAggregate { model.open(item) } else { model.reveal(item) }
        }
        .overlay {
            if items.isEmpty { ContentUnavailableView("Empty", systemImage: "folder", description: Text("Nothing here takes up space.")) }
        }
    }
}

struct DiskItemRow: View {
    @Environment(AppState.self) private var state
    let item: DiskItem
    let fraction: Double
    let showFolder: Bool

    var body: some View {
        HStack(spacing: 8) {
            Group {
                if item.isAggregate {
                    Image(systemName: "doc.on.doc").foregroundStyle(.secondary)
                } else {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: item.path)).resizable()
                }
            }
            .frame(width: 18, height: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.name).lineLimit(1).truncationMode(.middle)
                    .foregroundStyle(item.isAggregate ? .secondary : .primary)
                if showFolder {
                    Text((item.path as NSString).deletingLastPathComponent)
                        .font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                } else if item.isDirectory && !item.isAggregate {
                    Text("\(item.fileCount.formatted()) file\(item.fileCount == 1 ? "" : "s")")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .help(item.isAggregate ? "Files smaller than 1 MB in this folder, added together" : item.path)
            Spacer(minLength: 12)
            if let suggestion = state.diskUsage.suggestionByPath[item.path] {
                PriorityBadge(priority: suggestion.priority)
                    .help("\(suggestion.title): \(suggestion.explanation)")
            }
            SizeBar(fraction: fraction)
                .frame(width: 120, height: 6)
            Text(item.size.formatted(.byteCount(style: .file)))
                .font(.callout.monospacedDigit())
                .frame(width: 80, alignment: .trailing)
            if item.isDirectory && !item.isAggregate {
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            } else {
                Color.clear.frame(width: 8)
            }
        }
        .padding(.vertical, 2)
    }
}

struct SizeBar: View {
    let fraction: Double

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(.quaternary)
                Capsule().fill(LinearGradient(colors: [.orange.opacity(0.7), .orange], startPoint: .leading, endPoint: .trailing))
                    .frame(width: max(2, geo.size.width * min(1, max(0, fraction))))
            }
        }
    }
}

/// Folders and files that are usually safe or worthwhile to delete, with what that means and how.
struct CleanupList: View {
    @Environment(AppState.self) private var state

    var body: some View {
        let model = state.diskUsage
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                CleanupTotalCard(title: "Safe to clean", size: model.size(of: .safe), symbol: "checkmark.seal.fill", color: .green)
                CleanupTotalCard(title: "Review first", size: model.size(of: .review), symbol: "eye.fill", color: .orange)
                Spacer()
                if model.isCleaning { ProgressView().controlSize(.small); Text("Moving to Trash…").foregroundStyle(.secondary) }
                Button {
                    model.openCleanup()
                } label: {
                    Label("Clean Up…", systemImage: "sparkles")
                        .padding(.horizontal, 6)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
                .disabled(model.isCleaning || model.cleanableSuggestions.isEmpty)
                .help("Choose what to move to the Trash. \"Safe to clean\" items are ticked for you.")
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 10)
            Divider()
            List {
                ForEach(CleanupPriority.allCases, id: \.self) { priority in
                    let entries = model.entries.filter { $0.priority == priority }
                    if !entries.isEmpty {
                        Section {
                            ForEach(entries) { entry in
                                switch entry {
                                case .single(let s): CleanupSuggestionRow(suggestion: s)
                                case .group(let title, let members): CleanupGroupRow(title: title, members: members)
                                }
                            }
                        } header: {
                            Label {
                                Text(priority == .safe ? "Safe to clean" : "Review first").font(.title3.weight(.semibold)).foregroundStyle(.primary)
                                + Text(priority == .safe ? "  Rebuilt or downloaded again on its own" : "  Check before deleting").font(.callout).foregroundStyle(.secondary)
                            } icon: {
                                IconTile(symbol: priority == .safe ? "checkmark.seal.fill" : "eye.fill", color: priority == .safe ? .green : .orange, size: 22)
                            }
                            .padding(.vertical, 2)
                        }
                    }
                }
            }
            .overlay {
                if model.suggestions.isEmpty {
                    SectionEmptyState(symbol: "sparkles", color: .green, title: "Nothing obvious to clean",
                                      message: "No large caches, build leftovers or old downloads were found here. Check Largest Files and Largest Folders for anything you no longer need.")
                }
            }
        }
    }
}

struct CleanupTotalCard: View {
    let title: String
    let size: Int64
    let symbol: String
    let color: Color

    var body: some View {
        HStack(spacing: 10) {
            IconTile(symbol: symbol, color: color, size: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary).textCase(.uppercase)
                Text(size.formatted(.byteCount(style: .file))).font(.title3.weight(.semibold)).monospacedDigit()
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .glassCard(tint: color, radius: 14)
    }
}

struct CleanupSuggestionRow: View {
    @Environment(AppState.self) private var state
    let suggestion: CleanupSuggestion

    /// The first `command` in an instruction, for "Copy Command".
    static func command(in text: String) -> String? {
        let parts = text.split(separator: "`", omittingEmptySubsequences: false)
        return parts.count >= 3 ? String(parts[1]) : nil
    }

    private var actionTitle: String {
        switch suggestion.action {
        case .trashItem: "Move to Trash…"
        case .trashContents: "Clean…"
        case .manual: "How to Clean"
        }
    }

    var body: some View {
        let model = state.diskUsage
        HStack(alignment: .top, spacing: 10) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: suggestion.item.path))
                .resizable()
                .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(suggestion.title).font(.headline)
                    PriorityBadge(priority: suggestion.priority)
                }
                Text(suggestion.item.path.replacingOccurrences(of: AppPaths.home.path, with: "~"))
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
                Text(suggestion.explanation)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if case .manual(let how) = suggestion.action {
                    Label(how, systemImage: "info.circle")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            VStack(alignment: .trailing, spacing: 6) {
                Text(suggestion.item.size.formatted(.byteCount(style: .file)))
                    .font(.title3.monospacedDigit().weight(.semibold))
                HStack(spacing: 6) {
                    Button("Reveal") { model.reveal(suggestion.item) }
                    Button(actionTitle, role: suggestion.action == .trashItem || suggestion.action == .trashContents ? .destructive : nil) {
                        model.clean(suggestion)
                    }
                    .disabled(model.isCleaning || (suggestion.action == .trashItem && model.trashRefusal(suggestion.item) != nil))
                }
                .controlSize(.small)
            }
        }
        .padding(.vertical, 4)
        .contextMenu {
            Button("Reveal in Finder") { model.reveal(suggestion.item) }
            Button("Copy Path") { model.copyPath(suggestion.item) }
            if suggestion.item.isDirectory { Button("Show in Folders") { model.open(suggestion.item) } }
        }
    }
}

struct PriorityBadge: View {
    let priority: CleanupPriority

    var body: some View {
        Text(priority.title)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background((priority == .safe ? Color.green : Color.orange).opacity(0.22), in: Capsule())
            .foregroundStyle(priority == .safe ? Color.green : Color.orange)
    }
}

/// "Clean Up": pick suggestions (safe ones are ticked), confirm once, watch progress, see what was freed.
struct CleanupSheet: View {
    @Environment(AppState.self) private var state
    @Environment(\.dismiss) private var dismiss
    @State private var confirming = false

    var body: some View {
        let model = state.diskUsage
        let selected = model.selectedForCleanup
        let selectedSize = selected.reduce(Int64(0)) { $0 + $1.item.size }
        let reviewCount = selected.filter { $0.priority == .review }.count
        VStack(alignment: .leading, spacing: 12) {
            if let summary = model.cleanupSummary {
                CleanupSummaryView(summary: summary)
            } else if let progress = model.cleanupProgress {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Cleaning Up…").font(.title2.weight(.semibold))
                    ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1)))
                    Text(progress.current.isEmpty ? "Finishing…" : "\(progress.done + 1) of \(progress.total): \(progress.current)")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 160, alignment: .topLeading)
            } else {
                Text("Clean Up").font(.title2.weight(.semibold))
                Text("Ticked items move to the Trash, where you can restore them until you empty it. \"Safe to clean\" items are rebuilt or re-downloaded automatically; check \"Review first\" items before ticking them.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Safe Items Only") { model.selectForCleanup(.safe) }
                    Button("All") { model.selectForCleanup(nil) }
                    Button("None") { model.cleanupSelection = [] }
                }
                .controlSize(.small)
                List {
                    ForEach(CleanupPriority.allCases, id: \.self) { priority in
                        let entries = model.entries.filter { $0.priority == priority }
                        if !entries.isEmpty {
                            Section(priority.title) {
                                ForEach(entries) { entry in
                                    switch entry {
                                    case .single(let s): CleanupPickRow(suggestion: s)
                                    case .group(let title, let members): CleanupGroupPickRow(title: title, members: members)
                                    }
                                }
                            }
                        }
                    }
                }
                .frame(minHeight: 320)
            }

            HStack {
                if model.cleanupSummary == nil && model.cleanupProgress == nil {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(selected.count) selected · \(selectedSize.formatted(.byteCount(style: .file)))").monospacedDigit()
                        if reviewCount > 0 {
                            Text("Includes \(reviewCount) \"Review first\" item\(reviewCount == 1 ? "" : "s")").font(.caption).foregroundStyle(.orange)
                        }
                    }
                }
                Spacer()
                if model.cleanupSummary != nil {
                    Button("Open Trash") { NSWorkspace.shared.open(AppPaths.home.appendingPathComponent(".Trash")) }
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                } else if model.cleanupProgress == nil {
                    Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Move to Trash…", role: .destructive) { confirming = true }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                        .disabled(selected.isEmpty)
                }
            }
        }
        .padding(20)
        .frame(width: 620)
        .interactiveDismissDisabled(model.isCleaning)
        .confirmationDialog("Move \(selected.count) item\(selected.count == 1 ? "" : "s") to the Trash?", isPresented: $confirming) {
            Button("Move \(selectedSize.formatted(.byteCount(style: .file))) to Trash", role: .destructive) { model.runCleanup(selected) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(selected.map { "• \($0.title)\($0.action == .trashContents ? " (contents)" : ""): \($0.item.size.formatted(.byteCount(style: .file)))" }
                .prefix(12).joined(separator: "\n")
                + (selected.count > 12 ? "\n…and \(selected.count - 12) more" : "")
                + "\n\nQuit the apps that use these files first. Nothing is deleted permanently until you empty the Trash.")
        }
    }
}

struct CleanupPickRow: View {
    @Environment(AppState.self) private var state
    let suggestion: CleanupSuggestion

    var body: some View {
        let model = state.diskUsage
        let manual: String? = { if case .manual(let how) = suggestion.action { how } else { nil } }()
        HStack(alignment: .top, spacing: 8) {
            Toggle("", isOn: Binding(
                get: { model.cleanupSelection.contains(suggestion.id) },
                set: { on in if on { model.cleanupSelection.insert(suggestion.id) } else { model.cleanupSelection.remove(suggestion.id) } }
            ))
            .labelsHidden()
            .toggleStyle(.checkbox)
            .disabled(manual != nil)
            VStack(alignment: .leading, spacing: 2) {
                Text(suggestion.title + (suggestion.action == .trashContents ? " (contents)" : ""))
                Text(suggestion.item.path.replacingOccurrences(of: AppPaths.home.path, with: "~"))
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
                if let manual {
                    Text("Clean this yourself: \(manual)").font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .help(suggestion.explanation)
            Spacer()
            Text(suggestion.item.size.formatted(.byteCount(style: .file)))
                .monospacedDigit()
                .foregroundStyle(manual == nil ? .primary : .secondary)
        }
        .opacity(manual == nil ? 1 : 0.7)
    }
}

struct CleanupSummaryView: View {
    let summary: DiskUsageModel.CleanupSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(summary.failures.isEmpty ? "Cleaned up" : "Partly cleaned up",
                  systemImage: summary.failures.isEmpty ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .font(.title2.weight(.semibold))
                .foregroundStyle(summary.failures.isEmpty ? .green : .orange)
            Text("Moved \(summary.freed.formatted(.byteCount(style: .file))) to the Trash (\(summary.cleaned) item\(summary.cleaned == 1 ? "" : "s") fully cleaned). Empty the Trash to free the space.")
            if !summary.failures.isEmpty {
                Text("Not moved (\(summary.failures.count))").font(.headline)
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(summary.failures.sorted(by: { $0.key < $1.key }), id: \.key) { path, reason in
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(path.replacingOccurrences(of: AppPaths.home.path, with: "~")).font(.caption.monospaced()).textSelection(.enabled)
                                    Text(reason).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
                                    .controlSize(.small)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 200)
                Text("Files in use can't be moved: quit the apps that use them and run Clean Up again.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 160, alignment: .topLeading)
    }
}

/// One row for many suggestions of the same kind (e.g. every project's node_modules), expandable.
struct CleanupGroupRow: View {
    @Environment(AppState.self) private var state
    let title: String
    let members: [CleanupSuggestion]
    @State private var expanded = false

    var body: some View {
        let model = state.diskUsage
        let total = members.reduce(Int64(0)) { $0 + $1.item.size }
        DisclosureGroup(isExpanded: $expanded) {
            ForEach(members) { CleanupSuggestionRow(suggestion: $0) }
        } label: {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "folder.fill.badge.gearshape")
                    .font(.system(size: 22))
                    .foregroundStyle(.secondary)
                    .frame(width: 28, height: 28)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(title).font(.headline)
                        PriorityBadge(priority: members.first?.priority ?? .review)
                    }
                    Text("\(members.count) folders in your projects")
                        .font(.caption).foregroundStyle(.secondary)
                    Text(members.first?.explanation ?? "")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 12)
                VStack(alignment: .trailing, spacing: 6) {
                    Text(total.formatted(.byteCount(style: .file)))
                        .font(.title3.monospacedDigit().weight(.semibold))
                    HStack(spacing: 6) {
                        Button(expanded ? "Hide" : "Show \(members.count)") { withAnimation { expanded.toggle() } }
                        Button("Move All to Trash…", role: .destructive) { model.requestTrashGroup(title, members) }
                            .disabled(model.isCleaning)
                    }
                    .controlSize(.small)
                }
            }
            .padding(.vertical, 4)
        }
    }
}

/// A group in the Clean Up sheet: one checkbox for all members (mixed when only some are ticked), expandable.
struct CleanupGroupPickRow: View {
    @Environment(AppState.self) private var state
    let title: String
    let members: [CleanupSuggestion]
    @State private var expanded = false

    var body: some View {
        let model = state.diskUsage
        let ids = Set(members.map(\.id))
        let ticked = members.filter { model.cleanupSelection.contains($0.id) }
        let all = ticked.count == members.count
        let tickedSize = ticked.reduce(Int64(0)) { $0 + $1.item.size }
        let total = members.reduce(Int64(0)) { $0 + $1.item.size }
        DisclosureGroup(isExpanded: $expanded) {
            ForEach(members) { CleanupPickRow(suggestion: $0) }
        } label: {
            HStack(spacing: 8) {
                Button {
                    if all { model.cleanupSelection.subtract(ids) } else { model.cleanupSelection.formUnion(ids) }
                } label: {
                    Image(systemName: all ? "checkmark.square.fill" : (ticked.isEmpty ? "square" : "minus.square.fill"))
                        .foregroundStyle(ticked.isEmpty ? Color.secondary : Color.accentColor)
                        .font(.system(size: 14))
                }
                .buttonStyle(.plain)
                .help(all ? "Untick all" : "Tick all")
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(title) (\(members.count) folders)")
                    Text(ticked.isEmpty || all ? "Expand to choose individual folders" : "\(ticked.count) of \(members.count) ticked · \(tickedSize.formatted(.byteCount(style: .file)))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(total.formatted(.byteCount(style: .file))).monospacedDigit()
            }
        }
    }
}
