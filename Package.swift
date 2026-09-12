// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "AgentReins",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "AgentReins", targets: ["AgentReins"]),
        .executable(name: "AgentReinsNativeHost", targets: ["AgentReinsNativeHost"])
    ],
    targets: [
        .executableTarget(
            name: "AgentReins",
            path: "Sources/AgentReins",
            swiftSettings: [ .swiftLanguageMode(.v5) ],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .executableTarget(
            name: "AgentReinsNativeHost",
            path: "Sources/AgentReinsNativeHost",
            swiftSettings: [ .swiftLanguageMode(.v5) ]
        ),
        .testTarget(
            name: "AgentReinsTests",
            dependencies: ["AgentReins"],
            path: "Tests/AgentReinsTests"
        )
    ]
)
