// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "AgentReins",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "AgentReins",
            path: "Sources/AgentReins",
            swiftSettings: [ .swiftLanguageMode(.v5) ]
        )
    ]
)
