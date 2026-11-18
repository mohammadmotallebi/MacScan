// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MacScanCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MacScanCore", targets: ["MacScanCore"]),
    ],
    targets: [
        .target(
            name: "MacScanCore",
            resources: [.copy("Resources/SampleRules")]
        ),
        .testTarget(
            name: "MacScanCoreTests",
            dependencies: ["MacScanCore"]
        ),
    ]
)
