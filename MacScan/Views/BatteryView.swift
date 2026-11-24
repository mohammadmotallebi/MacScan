import MacScanCore
import SwiftUI

/// The Battery section: which apps and services use energy now, which used the most, and what keeps the Mac awake.
/// It only looks; nothing is quit or slowed.
struct BatteryView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        let model = state.battery
        VStack(spacing: 0) {
            header(model)
            Divider()
            if let report = model.report {
                content(report, model: model)
            } else {
                SectionEmptyState(
                    symbol: "battery.75percent", color: .yellow,
                    title: model.isChecking ? "Measuring energy use…" : "Battery",
                    message: "Shows which apps and services use the most energy, and what keeps your Mac awake. MacScan only looks; it never quits anything.",
                    isBusy: model.isChecking, buttonTitle: "Check Battery", action: { model.refresh() })
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Battery")
        .task {
            if model.report == nil { model.refresh() }
        }
    }

    @ViewBuilder
    private func content(_ report: BatteryReport, model: BatteryModel) -> some View {
        if let problem = report.problem {
            SectionEmptyState(symbol: "exclamationmark.triangle.fill", color: .orange, title: "Couldn't measure energy use",
                              message: problem, buttonTitle: "Try Again", action: { model.refresh() })
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    let now = model.shown(report.usingNow)
                    let maxNow = max(now.first?.impact ?? 1, 1)
                    card("Using energy now", hint: "Measured over 2 seconds, like Activity Monitor's Energy tab.") {
                        if now.isEmpty {
                            emptyLine("Nothing is using much energy right now.")
                        }
                        ForEach(Array(now.prefix(25).enumerated()), id: \.element.id) { index, app in
                            if index > 0 { Divider().padding(.leading, 50) }
                            EnergyRow(app: app, model: model, fraction: app.impact / maxNow) {
                                LevelTag(level: app.level, impact: app.impact)
                            }
                        }
                    }

                    let most = model.shown(report.usedMost)
                    let maxUsed = most.first?.usedWh ?? 1
                    card("Most energy since opened", hint: "Your own apps only. macOS doesn't share this for its services or other users' programs.") {
                        if most.isEmpty {
                            emptyLine("No numbers yet. This needs a Mac with Apple silicon.")
                        }
                        ForEach(Array(most.prefix(15).enumerated()), id: \.element.id) { index, app in
                            if index > 0 { Divider().padding(.leading, 50) }
                            EnergyRow(app: app, model: model, fraction: (app.usedWh ?? 0) / maxUsed, barColor: .yellow) {
                                VStack(alignment: .trailing, spacing: 1) {
                                    Text(Self.wattHours(app.usedWh ?? 0)).font(.callout.weight(.semibold)).monospacedDigit()
                                    if let started = app.startedAt {
                                        Text("since \(started.formatted(.relative(presentation: .named)))")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }

                    let awake = report.blockers
                    card("Keeping your Mac awake", hint: "These stop your Mac or its screen from going to sleep, which drains the battery.") {
                        if awake.isEmpty {
                            emptyLine("Nothing is keeping your Mac awake.")
                        }
                        ForEach(Array(awake.enumerated()), id: \.element.id) { index, app in
                            if index > 0 { Divider().padding(.leading, 50) }
                            EnergyRow(app: app, model: model, fraction: nil,
                                      detail: app.blockers.map { "\($0.reason) · for \(Self.held($0.held))" }.joined(separator: "\n")) {
                                Label(app.blockers.contains(where: \.keepsScreenOn) ? "Screen on" : "Awake",
                                      systemImage: app.blockers.contains(where: \.keepsScreenOn) ? "display" : "moon.zzz")
                                    .font(.caption.weight(.medium))
                                    .padding(.horizontal, 8).padding(.vertical, 3)
                                    .background(Color.purple.opacity(0.15), in: Capsule())
                                    .foregroundStyle(.purple)
                            }
                        }
                    }
                }
                .padding(20)
            }
            Divider()
            SectionFootnote(text: "A snapshot of this moment. MacScan only looks; to stop an app, quit it yourself.")
        }
    }

    private func card<Content: View>(_ title: String, hint: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title3.weight(.semibold))
                Text(hint).font(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 4)
            VStack(alignment: .leading, spacing: 0) { content() }
                .frame(maxWidth: .infinity, alignment: .leading)
                .glassCard(radius: 16)
        }
    }

    private func emptyLine(_ text: String) -> some View {
        Text(text).font(.callout).foregroundStyle(.secondary).padding(14)
    }

    static func wattHours(_ wh: Double) -> String {
        wh >= 10 ? String(format: "%.0f Wh", wh) : wh >= 1 ? String(format: "%.1f Wh", wh) : String(format: "%.0f mWh", wh * 1000)
    }

    /// "00:03:27" → "3 min".
    static func held(_ text: String) -> String {
        let parts = text.split(separator: ":").compactMap { Int($0) }
        guard parts.count == 3 else { return text }
        if parts[0] > 0 { return "\(parts[0]) h \(parts[1]) min" }
        if parts[1] > 0 { return "\(parts[1]) min" }
        return "\(parts[2]) s"
    }

    private func header(_ model: BatteryModel) -> some View {
        @Bindable var model = model
        let report = model.report.flatMap { $0.problem == nil ? $0 : nil }
        let battery = report?.state
        let heavy = report.map { model.shown($0.usingNow).filter { $0.level == .high }.count } ?? 0
        let awake = report?.blockers.count ?? 0
        var subtitle: String
        if let battery, let percent = battery.percent {
            subtitle = "\(percent)% · " + (battery.onBattery ? "On battery" + (battery.remaining.map { ", about \($0) left" } ?? "")
                                         : battery.charging ? "Charging" : "Plugged in")
            subtitle += "."
        } else if battery != nil {
            subtitle = "This Mac has no battery, but energy use still matters for heat and fan noise."
        } else {
            subtitle = model.isChecking ? "Measuring…" : model.report == nil ? "Not checked yet" : "Couldn't check"
        }
        if let date = report?.takenAt { subtitle += " Taken \(date.formatted(date: .omitted, time: .standard))." }
        var chips: [CountChip] = []
        if let report {
            chips.append(CountChip(symbol: "bolt.fill", text: "\(heavy) heavy now", color: heavy > 0 ? .orange : .green))
            chips.append(CountChip(symbol: "moon.zzz.fill", text: "\(awake) keeping awake", color: .purple, dimmed: awake == 0))
            if let top = model.shown(report.usingNow).first, top.level != .low {
                chips.append(CountChip(symbol: "flame.fill", text: "Top: \(top.name)", color: .red))
            }
        }
        let symbol = battery?.percent.map { $0 > 75 ? "battery.100percent" : $0 > 40 ? "battery.75percent" : $0 > 15 ? "battery.25percent" : "battery.0percent" } ?? "bolt.fill"
        return SectionHeader(title: "Battery", subtitle: subtitle, symbol: battery?.charging == true ? "battery.100percent.bolt" : symbol,
                             color: heavy > 0 ? .orange : .yellow, chips: chips, isBusy: model.isChecking) {
            Toggle("Hide macOS", isOn: $model.hideSystem)
                .toggleStyle(.switch)
                .controlSize(.small)
                .help("Hide macOS's own services")
            Button {
                model.refresh()
            } label: {
                Label("Check Again", systemImage: "arrow.clockwise")
            }
            .disabled(model.isChecking)
        }
    }
}

/// High / Medium / Low with the energy number.
private struct LevelTag: View {
    let level: EnergyLevel
    let impact: Double

    var body: some View {
        let (text, color): (String, Color) = switch level {
        case .high: ("High", .red)
        case .medium: ("Medium", .orange)
        case .low: ("Low", .green)
        }
        HStack(spacing: 6) {
            Text(String(format: "%.1f", impact)).font(.callout.weight(.semibold)).monospacedDigit()
            Text(text)
                .font(.caption.weight(.semibold))
                .frame(minWidth: 52)
                .padding(.vertical, 3)
                .background(color.opacity(0.15), in: Capsule())
                .foregroundStyle(color)
        }
        .help("Energy impact \(String(format: "%.1f", impact)). Around 1 is one percent of a CPU core.")
    }
}

private struct EnergyRow<Trailing: View>: View {
    let app: EnergyApp
    let model: BatteryModel
    /// Bar length from 0 to 1; nil for no bar.
    let fraction: Double?
    var barColor: Color = .orange
    var detail: String?
    @ViewBuilder var trailing: Trailing

    init(app: EnergyApp, model: BatteryModel, fraction: Double?, barColor: Color = .orange, detail: String? = nil,
         @ViewBuilder trailing: () -> Trailing) {
        self.app = app
        self.model = model
        self.fraction = fraction
        self.barColor = barColor
        self.detail = detail
        self.trailing = trailing()
    }

    var body: some View {
        HStack(spacing: 12) {
            Group {
                if let path = app.path {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable()
                } else {
                    Image(systemName: app.isSystem ? "gearshape.fill" : "questionmark.app.dashed").resizable().scaledToFit()
                        .padding(3).foregroundStyle(.secondary)
                }
            }
            .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(app.name).font(.body.weight(.medium)).lineLimit(1)
                    if app.isSystem { tag("macOS", .secondary) }
                    if model.runsHidden(app) { tag("No window", .blue) }
                }
                if let line = detail ?? app.hint {
                    Text(line).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                if let fraction {
                    GeometryReader { geo in
                        Capsule().fill(.quaternary)
                            .overlay(alignment: .leading) {
                                Capsule().fill(barColor.gradient).frame(width: max(4, geo.size.width * min(1, fraction)))
                            }
                    }
                    .frame(height: 5)
                    .frame(maxWidth: 260)
                }
            }
            Spacer(minLength: 12)
            trailing
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .contentShape(Rectangle())
        .help(app.path ?? app.name)
        .contextMenu {
            if app.path != nil { Button("Reveal in Finder") { model.reveal(app) } }
            Button("Copy Process IDs") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(app.pids.map(String.init).joined(separator: " "), forType: .string)
            }
            .disabled(app.pids.isEmpty)
        }
    }

    private func tag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}
