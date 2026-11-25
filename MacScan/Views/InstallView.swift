import MacScanCore
import SwiftUI

/// The Install section: check an app or installer before it goes into Applications.
struct InstallView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        @Bindable var model = state.installer
        VStack(spacing: 0) {
            header(model)
            Divider()
            switch model.phase {
            case .idle:
                PickInstallerView()
            case .opening, .checking:
                checking(model)
            case .ready, .installing, .installed:
                InstallReportView()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Install")
        .task { model.refreshRecent() }
        .confirmationDialog("Install anyway?", isPresented: Binding(get: { model.pendingRisky != nil }, set: { if !$0 { model.pendingRisky = nil } }),
                            presenting: model.pendingRisky) { candidate in
            Button("Install “\(candidate.name)” Anyway", role: .destructive) {
                model.install(candidate, state: state, confirmedRisk: true)
            }
            Button("Cancel", role: .cancel) {}
        } message: { candidate in
            Text((candidate.concerns.filter { $0.level == .danger }.map(\.text) + model.findings(for: candidate).prefix(3).map(\.reason))
                .map { "• " + $0 }.joined(separator: "\n") + "\n\nOnly install it if you trust where it came from.")
        }
        .confirmationDialog("Quit the app first?", isPresented: Binding(get: { model.mustQuit != nil }, set: { if !$0 { model.mustQuit = nil } }),
                            presenting: model.mustQuit) { app in
            if let candidate = model.candidates.first(where: { $0.existing?.path == app.bundleURL?.standardizedFileURL.path }) {
                Button("Quit \(app.localizedName ?? "App") and Install") { model.quitAndInstall(candidate, state: state) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { app in
            Text("\(app.localizedName ?? "The app") is open. It has to quit before the new copy can replace it.")
        }
        .alert("Install", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    private func checking(_ model: InstallModel) -> some View {
        VStack(spacing: 16) {
            StatusRing(color: .teal, symbol: "magnifyingglass", progress: model.progress?.fraction, size: 110, pulse: true)
            Text(model.phase == .opening ? "Opening \(model.source?.lastPathComponent ?? "")…" : "Checking what's inside…")
                .font(.title3.weight(.semibold))
            if let file = model.progress?.currentFile {
                Text((file as NSString).lastPathComponent).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Text("Nothing inside is opened or run.").font(.callout).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func header(_ model: InstallModel) -> some View {
        let subtitle: String = switch model.phase {
        case .idle: "Check an app before it goes into Applications. MacScan installs it only after you agree."
        case .opening, .checking: "Checking \(model.source?.lastPathComponent ?? "")…"
        case .ready: model.kind == .package ? "Checked. Apple's Installer does the install." : "Checked. Look it over, then install."
        case .installing: "Installing…"
        case .installed(let url): "Installed in \((url.deletingLastPathComponent().path as NSString).abbreviatingWithTildeInPath)."
        }
        var chips: [CountChip] = []
        if model.phase == .ready || model.phase == .installing || { if case .installed = model.phase { true } else { false } }() {
            let flagged = model.flagged.count
            chips.append(CountChip(symbol: flagged == 0 ? "checkmark.seal.fill" : "exclamationmark.triangle.fill",
                                   text: flagged == 0 ? "No threats found" : "\(flagged) flagged", color: flagged == 0 ? .green : .red))
            if let kind = model.kind { chips.append(CountChip(symbol: "shippingbox.fill", text: kind.title, color: .teal)) }
        }
        return SectionHeader(title: "Install", subtitle: subtitle, symbol: "square.and.arrow.down.fill", color: .teal,
                             chips: chips, isBusy: model.isBusy) {
            if model.phase != .idle {
                Button {
                    model.reset()
                    model.refreshRecent()
                } label: {
                    Label("Start Over", systemImage: "arrow.uturn.backward")
                }
                .disabled(model.isBusy)
            }
            Button {
                model.choose(state: state)
            } label: {
                Label("Choose…", systemImage: "folder")
            }
            .disabled(model.isBusy)
        }
    }
}

/// Start: drop a file, choose one, or pick a recent download.
private struct PickInstallerView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        let model = state.installer
        ScrollView {
            VStack(spacing: 22) {
                VStack(spacing: 14) {
                    ZStack {
                        Circle().fill(Color.teal.opacity(0.12).gradient)
                        Circle().strokeBorder(Color.teal.opacity(0.25), style: StrokeStyle(lineWidth: 2, dash: [6, 5]))
                        Image(systemName: "arrow.down.app.fill").font(.system(size: 44, weight: .semibold)).foregroundStyle(Color.teal.gradient)
                    }
                    .frame(width: 110, height: 110)
                    Text("Drop an app or installer here").font(.title2.weight(.bold))
                    Text("A .dmg, .zip, .app or .pkg. MacScan opens it without running anything, checks every app inside, and shows you what it found.")
                        .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 460)
                    Button {
                        model.choose(state: state)
                    } label: {
                        Text("Choose App or Installer…").padding(.horizontal, 8)
                    }
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                }
                .padding(.top, 20)

                if !model.recent.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionTitle("Recent downloads")
                        VStack(spacing: 0) {
                            ForEach(Array(model.recent.enumerated()), id: \.element) { index, url in
                                if index > 0 { Divider().padding(.leading, 52) }
                                RecentInstallerRow(url: url) { model.load(url, state: state) }
                            }
                        }
                        .glassCard(radius: 16)
                    }
                    .frame(maxWidth: 640)
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity)
        }
        .background(RadialGradient(colors: [Color.teal.opacity(0.10), .clear], center: .top, startRadius: 20, endRadius: 520))
    }
}

private struct RecentInstallerRow: View {
    let url: URL
    let check: () -> Void

    var body: some View {
        let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .totalFileAllocatedSizeKey])
        HStack(spacing: 12) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: url.path)).resizable().frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(url.lastPathComponent).lineLimit(1).truncationMode(.middle)
                Text([InstallerKind.of(url)?.title,
                      values?.contentModificationDate?.formatted(.relative(presentation: .named)),
                      values?.totalFileAllocatedSize.map { Int64($0).formatted(.byteCount(style: .file)) }]
                    .compactMap { $0 }.joined(separator: " · "))
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Check", action: check).buttonStyle(.glass)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }
}

/// After the check: one card per app (or the package), with its install button.
private struct InstallReportView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        let model = state.installer
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if model.kind == .package, let review = model.package {
                    PackageCard(review: review)
                }
                ForEach(model.candidates) { candidate in
                    CandidateCard(candidate: candidate, packageOnly: model.kind == .package)
                }
                if case .installed = model.phase, model.kind != .app {
                    HStack {
                        Label("Done with the installer?", systemImage: "trash").font(.callout)
                        Spacer()
                        Button("Move \(model.source?.lastPathComponent ?? "Installer") to Trash") { model.trashInstaller() }
                            .buttonStyle(.glass)
                    }
                    .padding(14)
                    .glassCard(radius: 16)
                }
            }
            .padding(20)
            .frame(maxWidth: 900)
            .frame(maxWidth: .infinity)
        }
    }
}

private struct PackageCard: View {
    @Environment(AppState.self) private var state
    let review: PackageReview

    var body: some View {
        let model = state.installer
        let risky = !model.flagged.isEmpty || review.signer == nil || review.scripts.contains { !$0.concerns.isEmpty }
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: model.source?.path ?? "")).resizable().frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.source?.lastPathComponent ?? "Package").font(.title3.weight(.semibold))
                    Label(review.signer ?? "Not signed", systemImage: review.signer == nil ? "xmark.seal.fill" : "checkmark.seal.fill")
                        .font(.callout).foregroundStyle(review.signer == nil ? .red : .secondary)
                    Label(review.notarized ? "Notarized by Apple" : "Not notarized by Apple",
                          systemImage: review.notarized ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                        .font(.callout).foregroundStyle(review.notarized ? .green : .orange)
                }
                Spacer()
                Button {
                    model.openInInstaller()
                } label: {
                    Label(risky ? "Open in Installer Anyway" : "Open in Installer", systemImage: "shippingbox")
                }
                .buttonStyle(.glassProminent)
                .tint(risky ? .red : .teal)
            }
            if review.scripts.isEmpty {
                Text("No install scripts.").font(.callout).foregroundStyle(.secondary)
            } else {
                Text("Install scripts run as administrator:").font(.callout.weight(.semibold))
                ForEach(review.scripts, id: \.path) { script in
                    ScriptLine(script: script)
                }
            }
            FindingLines(findings: model.flagged.filter { finding in !model.candidates.contains { finding.path.hasPrefix($0.url.path) } })
            Text("MacScan never runs a package itself. Apple's Installer will ask for your password.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(16)
        .glassCard(tint: risky ? .orange : .teal, radius: 18)
    }
}

private struct ScriptLine: View {
    let script: PackageReview.Script

    var body: some View {
        let clean = script.concerns.isEmpty
        let text: String = clean ? script.name : script.name + ": " + script.concerns.joined(separator: ", ")
        Label(text, systemImage: clean ? "doc.text" : "exclamationmark.triangle.fill")
            .font(.callout)
            .foregroundStyle(clean ? Color.secondary : Color.orange)
    }
}

private struct CandidateCard: View {
    @Environment(AppState.self) private var state
    let candidate: InstallCandidate
    /// Inside a package: shown for information, installed by the package.
    let packageOnly: Bool

    var body: some View {
        let model = state.installer
        let findings = model.findings(for: candidate)
        let risky = model.isRisky(candidate)
        let installed: URL? = if case .installed(let url) = model.phase, url.lastPathComponent == candidate.url.lastPathComponent { url } else { nil }
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: candidate.url.path)).resizable().frame(width: 56, height: 56)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(candidate.name).font(.title3.weight(.semibold))
                        if let version = candidate.version { Text(version).font(.callout).foregroundStyle(.secondary) }
                    }
                    Label(signerText, systemImage: candidate.signing.teamID == nil ? "xmark.seal.fill" : "checkmark.seal.fill")
                        .font(.callout).foregroundStyle(candidate.signing.teamID == nil ? .orange : .secondary)
                    if let g = candidate.gatekeeper {
                        Label(g.accepted ? (g.source ?? "Allowed by macOS") : "macOS would block it",
                              systemImage: g.accepted ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                            .font(.callout).foregroundStyle(g.accepted ? .green : .orange)
                    }
                    Text(versionLine + " · " + candidate.size.formatted(.byteCount(style: .file)))
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if !packageOnly { action(model: model, risky: risky, installed: installed) }
            }
            ForEach(candidate.concerns, id: \.self) { concern in
                Label(concern.text, systemImage: concern.level == .danger ? "xmark.octagon.fill" : concern.level == .warning ? "exclamationmark.triangle.fill" : "info.circle")
                    .font(.callout)
                    .foregroundStyle(concern.level == .danger ? .red : concern.level == .warning ? .orange : .secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            FindingLines(findings: findings)
            if findings.isEmpty && candidate.concerns.allSatisfy({ $0.level == .info }) {
                Label("No problems found.", systemImage: "checkmark.circle.fill").font(.callout).foregroundStyle(.green)
            }
        }
        .padding(16)
        .glassCard(tint: risky ? .red : installed != nil ? .green : .teal, radius: 18)
    }

    @ViewBuilder
    private func action(model: InstallModel, risky: Bool, installed: URL?) -> some View {
        if let installed {
            VStack(alignment: .trailing, spacing: 6) {
                Label("Installed", systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.headline)
                HStack {
                    Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([installed]) }
                    Button("Open") { NSWorkspace.shared.open(installed) }
                }
                .buttonStyle(.glass)
            }
        } else {
            Button {
                model.install(candidate, state: state)
            } label: {
                Label(risky ? "Install Anyway…" : candidate.existing == nil ? "Install" : "Replace",
                      systemImage: risky ? "exclamationmark.triangle" : "square.and.arrow.down")
                    .padding(.horizontal, 6)
            }
            .buttonStyle(.glassProminent)
            .tint(risky ? .red : .green)
            .controlSize(.large)
            .disabled(model.phase != .ready)
        }
    }

    private var signerText: String {
        switch candidate.signing {
        case .signed(_, let team, let authority):
            (authority?.replacingOccurrences(of: "Developer ID Application: ", with: "") ?? "Signed") + (team.map { " (\($0))" } ?? "")
        case .unsigned: "Not signed"
        case .adhoc: "Signed only by itself"
        case .selfSigned: "Home-made certificate"
        case .unreadable: "Signature unreadable"
        }
    }

    private var versionLine: String {
        switch candidate.versionChange {
        case .new: "New to this Mac"
        case .newer: "Update from \(candidate.existingVersion ?? "?")"
        case .same: "Same version as installed"
        case .older: "Older than installed (\(candidate.existingVersion ?? "?"))"
        case .unknown: "Replaces the copy in Applications"
        }
    }
}

private struct FindingLines: View {
    let findings: [Finding]

    var body: some View {
        ForEach(findings.prefix(6)) { finding in
            Label("\(finding.reason) · \((finding.path as NSString).lastPathComponent)",
                  systemImage: finding.severity == .threat ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(finding.severity == .threat ? .red : .orange)
                .fixedSize(horizontal: false, vertical: true)
        }
        if findings.count > 6 {
            Text("…and \(findings.count - 6) more. See History for the full list.").font(.caption).foregroundStyle(.secondary)
        }
    }
}
