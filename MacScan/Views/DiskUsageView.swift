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
                    ContentUnavailableView {
                        Label("Find what takes up space", systemImage: "chart.bar.doc.horizontal")
                    } description: {
                        Text("MacScan measures every folder in the location you choose and lists the biggest folders and files. Nothing is changed until you choose to move something to the Trash.")
                    } actions: {
                        Button("Measure \(model.locationName)") { model.scan() }
                            .buttonStyle(.borderedProminent)
                    }
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
        HStack(spacing: 10) {
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
                Button("Cancel") { model.cancel() }
            } else {
                Button(model.report == nil ? "Measure" : "Measure Again") { model.scan() }
                    .keyboardShortcut("r", modifiers: [.command, .option])
            }
            Spacer()
            if let report = model.report, !model.isScanning {
                Text("\(report.totalSize.formatted(.byteCount(style: .file))) in \(report.fileCount.formatted()) files")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .padding(10)
    }
}

struct DiskUsageProgressView: View {
    let progress: DiskUsageProgress?
    let location: String

    var body: some View {
        VStack(spacing: 10) {
            ProgressView()
            Text("Measuring \(location)…").font(.headline)
            if let progress {
                Text("\(progress.filesScanned.formatted()) files · \(progress.bytesCounted.formatted(.byteCount(style: .file)))")
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                Text(progress.currentFolder)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: 500)
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
            .fixedSize()
            .padding(8)

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
                Capsule().fill(Color.accentColor.opacity(0.8))
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
            HStack(spacing: 16) {
                Label("\(model.size(of: .safe).formatted(.byteCount(style: .file))) safe to clean", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                Label("\(model.size(of: .review).formatted(.byteCount(style: .file))) to review", systemImage: "eye.fill")
                    .foregroundStyle(.orange)
                Spacer()
                if model.isCleaning { ProgressView().controlSize(.small); Text("Moving to Trash…").foregroundStyle(.secondary) }
            }
            .font(.callout.weight(.medium))
            .padding(.horizontal, 12)
            .padding(.bottom, 6)
            Divider()
            List {
                ForEach(CleanupPriority.allCases, id: \.self) { priority in
                    let items = model.suggestions.filter { $0.priority == priority }
                    if !items.isEmpty {
                        Section(priority == .safe ? "Safe to clean: rebuilt or re-downloaded automatically" : "Review first: check before deleting") {
                            ForEach(items) { CleanupSuggestionRow(suggestion: $0) }
                        }
                    }
                }
            }
            .overlay {
                if model.suggestions.isEmpty {
                    ContentUnavailableView("Nothing obvious to clean", systemImage: "sparkles",
                                           description: Text("No large caches, build leftovers or old downloads were found here. Check Largest Files and Largest Folders for anything you no longer need."))
                }
            }
        }
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
