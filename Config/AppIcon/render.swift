import AppKit

// usage: render <svg> <outdir> [--background]
let args = CommandLine.arguments
let svg = URL(fileURLWithPath: args[1])
let outDir = URL(fileURLWithPath: args[2])
let withBackground = args.contains("--background")
guard let image = NSImage(contentsOf: svg) else { fatalError("cannot load svg") }

func render(_ px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: px, height: px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current?.imageInterpolation = .high
    let s = CGFloat(px)
    if withBackground {
        // macOS icon grid: 824/1024 body, ~185/1024 corner radius, soft shadow.
        let inset = s * 100 / 1024
        let body = NSRect(x: inset, y: inset * 1.1, width: s - inset * 2, height: s - inset * 2)
        let path = NSBezierPath(roundedRect: body, xRadius: s * 185 / 1024, yRadius: s * 185 / 1024)
        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = NSColor.black.withAlphaComponent(0.22)
        shadow.shadowBlurRadius = s * 18 / 1024
        shadow.shadowOffset = NSSize(width: 0, height: -s * 8 / 1024)
        shadow.set()
        NSGradient(starting: NSColor(calibratedRed: 1.0, green: 0.99, blue: 0.97, alpha: 1),
                   ending: NSColor(calibratedRed: 0.93, green: 0.87, blue: 0.79, alpha: 1))!.draw(in: path, angle: -90)
        NSGraphicsContext.restoreGraphicsState()
        let glyph = body.insetBy(dx: body.width * 0.10, dy: body.height * 0.10)
        image.draw(in: glyph, from: .zero, operation: .sourceOver, fraction: 1)
    } else {
        image.draw(in: NSRect(x: 0, y: 0, width: s, height: s), from: .zero, operation: .sourceOver, fraction: 1)
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
if args.contains("--preview") {
    try render(512).write(to: outDir.appendingPathComponent("preview.png"))
} else {
    for (pt, scale) in [(16,1),(16,2),(32,1),(32,2),(128,1),(128,2),(256,1),(256,2),(512,1),(512,2)] {
        let name = "icon_\(pt)x\(pt)\(scale == 2 ? "@2x" : "").png"
        try render(pt * scale).write(to: outDir.appendingPathComponent(name))
    }
}
