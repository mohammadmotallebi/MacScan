import MacScanCore
import UniformTypeIdentifiers
import SwiftUI

struct UninstallView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        @Bindable var model = state.uninstall
        HSplitView {
            // App list
            VStack(spacing: 0) {
                TextField("Search apps", text: $model.search)
                    .textFieldStyle(.roundedBorder)
                    .padding(8)
                List(selection: $model.selectedAppID) {
                    Section("Applications") {
                        ForEach(model.filteredApps) { app in AppRow(app: app) }
                    }
                    if !model.filteredTrashApps.isEmpty {
                        Section("In the Trash") {
                            ForEach(model.filteredTrashApps) { app in AppRow(app: app) }
                        }
                    }
                    if !model.filteredRemovedApps.isEmpty {
                        Section("Already Removed") {
                            ForEach(model.filteredRemovedApps) { app in AppRow(app: app) }
                        }
                    }
                }
                .overlay {
                    if model.isLoadingApps && model.apps.isEmpty { ProgressView("Loading apps…") }
                }
                Divider()
                HStack {
                    Button("Choose App…") { model.chooseApp() }
                    Button("Already Removed App…") { model.showingRemovedAppSheet = true }
                        .help("Find the leftovers of an app you've already deleted, by its bundle ID or name")
                    Spacer()
                    Button {
                        model.loadApps()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .help("Reload the list of apps")
                }
                .buttonStyle(.borderless)
                .padding(8)
            }
            .frame(minWidth: 240, idealWidth: 280, maxWidth: 360, maxHeight: .infinity)

            // Plan
            Group {
                if let app = model.selectedApp {
                    if let reason = app.protectionReason {
                        SectionEmptyState(symbol: "lock.fill", color: .gray, title: "Can't uninstall \(app.name)",
                                          message: "\(reason). MacScan won't remove it.")
                    } else if model.isFinding {
                        SectionEmptyState(symbol: "magnifyingglass", color: .red, title: "Looking for \(app.name)'s files…",
                                          message: "Startup items, helpers, settings, caches and everything else it put on this Mac.", isBusy: true)
                    } else if let plan = model.plan {
                        UninstallPlanView(plan: plan)
                    } else {
                        Color.clear
                    }
                } else {
                    SectionEmptyState(
                        symbol: "trash.fill", color: .red, title: "Uninstall an app",
                        message: "Choose an app on the left, or drop one here. MacScan finds the app, its startup items, helpers, settings, caches and other files, and moves the ones you choose to the Trash.",
                        buttonTitle: "Choose App…", action: { model.chooseApp() })
                }
            }
            .frame(minWidth: 520, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Uninstall")
        .onAppear { if model.apps.isEmpty { model.loadApps() } }
        .onChange(of: model.selectedAppID) { _, _ in model.findLeftovers() }
        .sheet(item: $model.result) { result in
            UninstallReportSheet(report: result.report)
        }
        .sheet(isPresented: $model.showingRemovedAppSheet) {
            RemovedAppSheet()
        }
        .alert("Uninstall", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }
}

struct AppRow: View {
    let app: InstalledApp

    var body: some View {
        HStack(spacing: 8) {
            Image(nsImage: app.icon)
                .resizable()
                .frame(width: 24, height: 24)
                .opacity(app.isMissing ? 0.5 : 1)
            VStack(alignment: .leading, spacing: 1) {
                Text(app.name).lineLimit(1)
                Text(app.isMissing ? "Already removed\(app.bundleID.map { " · \($0)" } ?? "")"
                     : app.isInTrash ? "In the Trash" : (app.version.map { "Version \($0)" } ?? (app.bundleID ?? "")))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if app.isProtected {
                Image(systemName: "lock.fill").foregroundStyle(.secondary).help(app.protectionReason ?? "")
            }
        }
        .padding(.vertical, 2)
    }
}

struct UninstallPlanView: View {
    @Environment(AppState.self) private var state
    let plan: UninstallPlan
    @State private var confirming = false

    private var model: UninstallModel { state.uninstall }

    private var groups: [(LeftoverCategory, [Leftover])] {
        LeftoverCategory.allCases.compactMap { cat in
            let items = plan.leftovers.filter { $0.category == cat }
            return items.isEmpty ? nil : (cat, items)
        }
    }

    var body: some View {
        let chosen = model.selectedLeftovers
        let chosenSize = chosen.reduce(Int64(0)) { $0 + $1.size }
        let adminCount = chosen.filter { $0.requiresAdmin || $0.launchDomain == .system }.count
        let deleting = chosen.filter { model.willDelete($0) }.count

        VStack(spacing: 0) {
            // Header
            HStack(spacing: 16) {
                Image(nsImage: plan.app.icon)
                    .resizable()
                    .frame(width: 64, height: 64)
                    .shadow(color: .black.opacity(0.2), radius: 6, y: 2)
                    .opacity(plan.app.isMissing ? 0.5 : 1)
                VStack(alignment: .leading, spacing: 4) {
                    Text(plan.app.name).font(.system(size: 22, weight: .bold, design: .rounded))
                    Text([plan.app.version.map { "Version \($0)" }, plan.app.bundleID].compactMap { $0 }.joined(separator: " · "))
                        .font(.caption).foregroundStyle(.secondary)
                    Text(plan.app.isMissing ? "The app is already removed. These are the files it left behind."
                                            : CodeSigning.status(of: plan.app.url).description)
                        .font(.caption).foregroundStyle(.secondary)
                    HStack(spacing: 6) {
                        CountChip(symbol: "doc.on.doc.fill", text: "\(plan.leftovers.count) items", color: .red)
                        CountChip(symbol: "internaldrive.fill", text: plan.totalSize.formatted(.byteCount(style: .file)), color: .gray)
                        if !plan.launchJobs.isEmpty {
                            CountChip(symbol: "gearshape.2.fill", text: "\(plan.launchJobs.count) background", color: .orange)
                        }
                    }
                    .padding(.top, 2)
                }
                Spacer()
            }
            .padding(18)
            .glassCard(tint: .red, radius: 22)
            .padding(12)
            .background(SectionWash(color: .red))

            if plan.app.isInTrash {
                Label("This app is already in the Trash. Its items will be deleted permanently.", systemImage: "trash.fill")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)
            }
            if !plan.launchJobs.isEmpty {
                Label("Registered background items: \(plan.launchJobs.map(\.label).joined(separator: ", ")). They will be stopped and unregistered.", systemImage: "gearshape.2")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)
            }
            if plan.leftovers.isEmpty {
                Label("Nothing found for \(plan.app.name). Check the bundle ID or try the app's name.", systemImage: "magnifyingglass")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)
            }
            if plan.leftovers.contains(where: \.protectedByMacOS) {
                HStack(alignment: .firstTextBaseline) {
                    Label("Some items are in other apps' protected containers. macOS blocks removing them, even with your password, unless MacScan has Full Disk Access.",
                          systemImage: "hand.raised.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Full Disk Access…") { FullDiskAccess.openSettings() }
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 8)
            }
            if !plan.processes.isEmpty {
                Label("\(plan.app.name) is running (\(plan.processes.count) process\(plan.processes.count == 1 ? "" : "es")). It will be quit first.", systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)
            }
            Divider()

            // Checklist
            List {
                ForEach(groups, id: \.0) { category, items in
                    Section {
                        ForEach(items) { item in
                            LeftoverRow(item: item, isOn: Binding(
                                get: { model.selection.contains(item.path) },
                                set: { model.setSelected(item, $0) }
                            ))
                        }
                    } header: {
                        Text(category.title).font(.headline).foregroundStyle(.primary)
                    }
                }
            }

            Divider()
            // Footer
            HStack(spacing: 12) {
                Button("All") { model.selectAll() }
                    .buttonStyle(.glass)
                Button("None") { model.selectNone() }
                    .buttonStyle(.glass)
                Divider().frame(height: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text("\(chosen.count) of \(plan.leftovers.count) selected · \(chosenSize.formatted(.byteCount(style: .file)))")
                    if adminCount > 0 {
                        Label("\(adminCount) need your administrator password", systemImage: "lock.fill")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Toggle("Delete permanently", isOn: Binding(get: { model.deletePermanently }, set: { model.deletePermanently = $0 }))
                    .toggleStyle(.checkbox)
                    .help("Delete instead of moving to the Trash. macOS keeps listing an app's background items in Login Items while the app is still in the Trash.")
                if model.isUninstalling {
                    ProgressView().controlSize(.small)
                    Text(model.status ?? "").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Button(role: .destructive) {
                    confirming = true
                } label: {
                    Label("Uninstall…", systemImage: "trash")
                }
                .buttonStyle(.glassProminent)
                .tint(.red)
                .controlSize(.large)
                .disabled(chosen.isEmpty || model.isUninstalling)
            }
            .padding(12)
        }
        .confirmationDialog("Uninstall \(plan.app.name)?", isPresented: $confirming) {
            Button(deleting == chosen.count ? "Delete \(chosen.count) Items Permanently" : (deleting > 0 ? "Remove \(chosen.count) Items" : "Move \(chosen.count) Items to Trash"),
                   role: .destructive) { model.uninstall() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(confirmationText(chosen: chosen, adminCount: adminCount, deleting: deleting))
        }
    }

    private func confirmationText(chosen: [Leftover], adminCount: Int, deleting: Int) -> String {
        var lines: [String] = []
        if !plan.processes.isEmpty { lines.append("• Quit \(plan.app.name)") }
        let launch = Set(chosen.compactMap(\.launchLabel) + plan.launchJobs.map(\.label)).count
        if launch > 0 { lines.append("• Stop and unregister \(launch) background item\(launch == 1 ? "" : "s")") }
        let moving = chosen.count - deleting
        if moving > 0 { lines.append("• Move \(moving) item\(moving == 1 ? "" : "s") to the Trash") }
        if deleting > 0 { lines.append("• DELETE \(deleting) item\(deleting == 1 ? "" : "s") permanently") }
        if adminCount > 0 { lines.append("• macOS will ask for your password for \(adminCount) system item\(adminCount == 1 ? "" : "s")") }
        lines.append(deleting > 0
            ? "\nPermanently deleted items can't be restored."
            : "\nNothing is deleted permanently. You can restore items from the Trash until you empty it.")
        return lines.joined(separator: "\n")
    }
}

struct LeftoverRow: View {
    let item: Leftover
    @Binding var isOn: Bool

    var body: some View {
        HStack(spacing: 8) {
            Toggle("", isOn: $isOn).labelsHidden().toggleStyle(.checkbox)
            Image(nsImage: NSWorkspace.shared.icon(forFile: item.path))
                .resizable()
                .frame(width: 18, height: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.url.lastPathComponent).lineLimit(1).truncationMode(.middle)
                Text((item.path as NSString).deletingLastPathComponent)
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            .help("\(item.path)\n\(item.matchedBy)")
            Spacer()
            if !item.selectedByDefault {
                Text("shared?")
                    .font(.caption2)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(.orange.opacity(0.25), in: Capsule())
                    .help(item.matchedBy)
            } else if item.matchedByNameOnly {
                Text("name match")
                    .font(.caption2)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(.yellow.opacity(0.25), in: Capsule())
                    .help("Matched only because it has the app's name — check it belongs to this app")
            }
            if item.protectedByMacOS {
                Image(systemName: "hand.raised.fill").foregroundStyle(.orange)
                    .help("Protected by macOS privacy protection. MacScan needs Full Disk Access to remove this; an administrator password doesn't help.")
            } else if item.requiresAdmin || item.launchDomain == .system {
                Image(systemName: "lock.fill").foregroundStyle(.secondary).help("Needs your administrator password")
            }
            Text(item.size > 0 ? item.size.formatted(.byteCount(style: .file)) : "—")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 70, alignment: .trailing)
        }
        .contentShape(Rectangle())
        .contextMenu {
            Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([item.url]) }
            Button("Copy Path") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(item.path, forType: .string)
            }
        }
    }
}

struct UninstallReportSheet: View {
    @Environment(\.dismiss) private var dismiss
    let report: UninstallReport

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SheetHeader(symbol: report.failures.isEmpty ? "checkmark.circle.fill" : "exclamationmark.triangle.fill",
                        color: report.failures.isEmpty ? .green : .orange,
                        title: report.failures.isEmpty ? "\(report.appName) was uninstalled" : "\(report.appName) was partly uninstalled",
                        subtitle: "\(report.freedBytes.formatted(.byteCount(style: .file))) removed.")
            HStack(spacing: 6) {
                if report.movedCount > 0 {
                    CountChip(symbol: "trash.fill", text: "\(report.movedCount) moved to Trash", color: .green)
                }
                if report.deletedCount > 0 {
                    CountChip(symbol: "xmark.bin.fill", text: "\(report.deletedCount) deleted", color: .green)
                }
                if !report.failures.isEmpty {
                    CountChip(symbol: "exclamationmark.triangle.fill", text: "\(report.failures.count) not removed", color: .red)
                }
            }
            if !report.quitProcesses.isEmpty {
                Text("Quit: \(Set(report.quitProcesses).sorted().joined(separator: ", "))").font(.callout).foregroundStyle(.secondary)
            }
            if !report.stoppedLaunchItems.isEmpty {
                Text("Stopped background items: \(report.stoppedLaunchItems.joined(separator: ", "))").font(.callout).foregroundStyle(.secondary)
            }

            if !report.failures.isEmpty {
                Text("Not removed").font(.headline)
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(report.failures.enumerated()), id: \.offset) { _, entry in
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(entry.leftover.path).font(.caption.monospaced()).textSelection(.enabled)
                                    Text(describe(entry.outcome)).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if FileManager.default.fileExists(atPath: entry.leftover.path) {
                                    Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([entry.leftover.url]) }
                                        .controlSize(.small)
                                }
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 160)
                if !report.blockedByMacOS.isEmpty {
                    HStack {
                        Text("Give MacScan Full Disk Access, quit and reopen it, then uninstall again. Or drag the items to the Trash in Finder.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer()
                        Button("Full Disk Access…") { FullDiskAccess.openSettings() }
                    }
                }
            }

            ForEach(Array(report.notes.enumerated()), id: \.offset) { _, note in
                Label(note, systemImage: "info.circle").font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Open Trash") {
                    NSWorkspace.shared.open(AppPaths.home.appendingPathComponent(".Trash"))
                }
                .buttonStyle(.glass)
                Button("Login Items Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
                }
                .buttonStyle(.glass)
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(.glassProminent).keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 560)
    }

    private func describe(_ outcome: UninstallReport.Outcome) -> String {
        switch outcome {
        case .movedToTrash: "Moved to Trash"
        case .deleted: "Deleted"
        case .failed(let why): "Failed: \(why)"
        case .skipped(let why): "Skipped: \(why)"
        case .blockedByMacOS: "Blocked by macOS privacy protection (needs Full Disk Access)"
        }
    }
}

/// Asks for the bundle ID and/or name of an app that's already deleted.
struct RemovedAppSheet: View {
    @Environment(AppState.self) private var state
    @Environment(\.dismiss) private var dismiss
    @State private var bundleID = ""
    @State private var name = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SheetHeader(symbol: "magnifyingglass", color: .red, title: "Find leftovers of a removed app",
                        subtitle: "Deleted apps often leave settings, caches, helpers and background items behind. Enter what you know about the app, and MacScan lists those files for you to review. Nothing is removed until you confirm.")
            Form {
                TextField("Bundle ID", text: $bundleID, prompt: Text("com.vendor.AppName"))
                TextField("Name", text: $name, prompt: Text("App name, e.g. CleanMyMac_5"))
            }
            .formStyle(.columns)
            Text("The bundle ID gives the most reliable results. It's often the name of a folder in ~/Library/Application Support or ~/Library/Preferences. Without it, MacScan matches by name only, so check each item.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill").font(.callout).foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.buttonStyle(.glass).keyboardShortcut(.cancelAction)
                Button("Find Leftovers") {
                    if let message = state.uninstall.addRemovedApp(bundleID: bundleID, name: name) {
                        error = message
                    } else {
                        dismiss()
                    }
                }
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(bundleID.trimmingCharacters(in: .whitespaces).isEmpty && name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 480)
    }
}

extension InstalledApp {
    /// The app's icon, or the generic app icon when the app is already removed.
    var icon: NSImage {
        isMissing ? NSWorkspace.shared.icon(for: .application) : NSWorkspace.shared.icon(forFile: url.path)
    }
}
