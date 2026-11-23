import Charts
import MacScanCore
import SwiftUI

// Shared look for MacScan's screens: glass cards, colored icon tiles and status rings.

/// A rounded glass card. `tint` adds a light wash of color.
struct GlassCard: ViewModifier {
    var tint: Color?
    var radius: CGFloat = 18
    var interactive = false

    func body(content: Content) -> some View {
        var glass = Glass.regular
        if let tint { glass = glass.tint(tint.opacity(0.22)) }
        if interactive { glass = glass.interactive() }
        return content
            .glassEffect(glass, in: .rect(cornerRadius: radius))
    }
}

extension View {
    func glassCard(tint: Color? = nil, radius: CGFloat = 18, interactive: Bool = false) -> some View {
        modifier(GlassCard(tint: tint, radius: radius, interactive: interactive))
    }
}

/// A colored rounded square with a white symbol, like the icons in System Settings.
struct IconTile: View {
    let symbol: String
    let color: Color
    var size: CGFloat = 32

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.5, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(color.gradient, in: .rect(cornerRadius: size * 0.26))
            .shadow(color: color.opacity(0.35), radius: 3, y: 1)
    }
}

/// Small heading above a group of cards.
struct SectionTitle: View {
    let title: String
    var trailing: AnyView?

    init(_ title: String, trailing: AnyView? = nil) {
        self.title = title
        self.trailing = trailing
    }

    var body: some View {
        HStack {
            Text(title)
                .font(.title3.weight(.semibold))
            Spacer()
            trailing
        }
        .padding(.horizontal, 4)
    }
}

/// A donut showing how many of `total` are fine.
struct DonutRing: View {
    let good: Int
    let total: Int
    let color: Color
    var size: CGFloat = 44

    var body: some View {
        Chart {
            SectorMark(angle: .value("Fine", good), innerRadius: .ratio(0.68), angularInset: 1)
                .foregroundStyle(color.gradient)
            SectorMark(angle: .value("Not fine", max(0, total - good)), innerRadius: .ratio(0.68), angularInset: 1)
                .foregroundStyle(.quaternary)
        }
        .chartLegend(.hidden)
        .frame(width: size, height: size)
        .overlay {
            Text("\(good)")
                .font(.system(size: size * 0.3, weight: .bold, design: .rounded))
                .monospacedDigit()
        }
    }
}

/// The big status ring on the home and scanning screens. `progress` nil = spins.
struct StatusRing: View {
    let color: Color
    let symbol: String
    var progress: Double? = 1
    var size: CGFloat = 132
    var pulse = false

    @State private var spin = false

    var body: some View {
        ZStack {
            Circle()
                .stroke(color.opacity(0.15), lineWidth: size * 0.08)
            Circle()
                .trim(from: 0, to: progress ?? 0.25)
                .stroke(
                    AngularGradient(colors: [color.opacity(0.5), color], center: .center),
                    style: StrokeStyle(lineWidth: size * 0.08, lineCap: .round))
                .rotationEffect(.degrees(-90 + (progress == nil && spin ? 360 : 0)))
                .animation(progress == nil ? .linear(duration: 1.2).repeatForever(autoreverses: false) : .smooth, value: spin)
                .animation(.smooth, value: progress)
            Circle()
                .fill(color.opacity(0.12).gradient)
                .padding(size * 0.14)
            Image(systemName: symbol)
                .font(.system(size: size * 0.34, weight: .semibold))
                .foregroundStyle(color.gradient)
                .symbolEffect(.pulse, options: .repeating, isActive: pulse)
                .contentTransition(.symbolEffect(.replace))
        }
        .frame(width: size, height: size)
        .shadow(color: color.opacity(0.25), radius: 12)
        .onAppear { spin = true }
    }
}

/// A rounded count chip, e.g. "3 warnings".
struct CountChip: View {
    let symbol: String
    let text: String
    let color: Color
    var dimmed = false

    var body: some View {
        Label(text, systemImage: symbol)
            .font(.callout.weight(.medium))
            .monospacedDigit()
            .foregroundStyle(dimmed ? AnyShapeStyle(.secondary) : AnyShapeStyle(color))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background((dimmed ? Color.secondary : color).opacity(0.13), in: Capsule())
    }
}

/// The top of a section: a big colored icon, the title, one line of summary, count chips and buttons.
struct SectionHeader<Accessory: View, Actions: View>: View {
    let title: String
    let subtitle: String
    let symbol: String
    let color: Color
    var chips: [CountChip] = []
    var isBusy = false
    @ViewBuilder var accessory: Accessory
    @ViewBuilder var actions: Actions

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            IconTile(symbol: symbol, color: color, size: 52)
                .symbolEffect(.pulse, options: .repeating, isActive: isBusy)
            VStack(alignment: .leading, spacing: 6) {
                Text(title)
                    .font(.system(size: 22, weight: .bold, design: .rounded))
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                if !chips.isEmpty {
                    HStack(spacing: 6) {
                        ForEach(Array(chips.enumerated()), id: \.offset) { $0.element }
                    }
                    .padding(.top, 2)
                }
            }
            Spacer(minLength: 12)
            accessory
            HStack(spacing: 8) {
                if isBusy { ProgressView().controlSize(.small) }
                actions
            }
            .buttonStyle(.glass)
        }
        .padding(18)
        .glassCard(tint: color, radius: 22)
        .padding(12)
        .background(SectionWash(color: color))
    }
}

extension SectionHeader where Accessory == EmptyView {
    init(title: String, subtitle: String, symbol: String, color: Color, chips: [CountChip] = [], isBusy: Bool = false,
         @ViewBuilder actions: () -> Actions) {
        self.init(title: title, subtitle: subtitle, symbol: symbol, color: color, chips: chips, isBusy: isBusy,
                  accessory: { EmptyView() }, actions: actions)
    }
}

/// A soft color wash behind a section header.
struct SectionWash: View {
    let color: Color

    var body: some View {
        LinearGradient(colors: [color.opacity(0.16), color.opacity(0.03)], startPoint: .topLeading, endPoint: .bottomTrailing)
    }
}

/// A big friendly empty or loading state with one main button.
struct SectionEmptyState: View {
    let symbol: String
    let color: Color
    let title: String
    let message: String
    var isBusy = false
    var buttonTitle: String?
    var action: (() -> Void)?

    var body: some View {
        VStack(spacing: 16) {
            ZStack {
                Circle().fill(color.opacity(0.12).gradient)
                Circle().strokeBorder(color.opacity(0.25), lineWidth: 2)
                Image(systemName: symbol)
                    .font(.system(size: 44, weight: .semibold))
                    .foregroundStyle(color.gradient)
                    .symbolEffect(.pulse, options: .repeating, isActive: isBusy)
            }
            .frame(width: 110, height: 110)
            .shadow(color: color.opacity(0.2), radius: 12)
            Text(title)
                .font(.title2.weight(.bold))
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 440)
            if isBusy {
                ProgressView().controlSize(.small)
            } else if let buttonTitle, let action {
                Button(action: action) {
                    Text(buttonTitle).padding(.horizontal, 8)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
            }
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(RadialGradient(colors: [color.opacity(0.10), .clear], center: .center, startRadius: 20, endRadius: 420))
    }
}

/// A plain note line at the bottom of a section.
struct SectionFootnote: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "info.circle")
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
    }
}

extension MenuBarStatus.Level {
    var color: Color {
        switch self {
        case .unknown: .accentColor
        case .clear: .green
        case .attention: .orange
        case .threat: .red
        case .scanning: .accentColor
        }
    }

    var symbol: String {
        switch self {
        case .unknown: "shield"
        case .clear: "checkmark.shield.fill"
        case .attention: "exclamationmark.shield.fill"
        case .threat: "xmark.shield.fill"
        case .scanning: "shield.lefthalf.filled"
        }
    }

    /// The big line on the home screen.
    var headline: String {
        switch self {
        case .unknown: "Let's check your Mac"
        case .clear: "Your Mac looks good"
        case .attention: "A few things need a look"
        case .threat: "Threats found"
        case .scanning: "Scanning…"
        }
    }
}
