// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "AgentReins",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "AgentReins", targets: ["AgentReins"]),
        .executable(name: "agentreins_v2", targets: ["AgentReins"]),
        .executable(name: "AgentReinsNativeHost", targets: ["AgentReinsNativeHost"]),
        .executable(name: "AgentReinsHook", targets: ["AgentReinsHook"]),
        .executable(name: "AgentReinsAlertsBridge", targets: ["AgentReinsAlertsBridge"]),
        .executable(name: "AgentReinsMCP", targets: ["AgentReinsMCP"]),
        .executable(name: "AgentReinsKeychainHelper", targets: ["AgentReinsKeychainHelper"])
    ],
    targets: [
        .executableTarget(
            name: "AgentReins",
            path: "Sources/AgentReins",
            resources: [.copy("Resources")],
            swiftSettings: [ .swiftLanguageMode(.v5) ],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .executableTarget(
            name: "AgentReinsNativeHost",
            path: "Sources/AgentReinsNativeHost",
            swiftSettings: [ .swiftLanguageMode(.v5) ]
        ),
        .executableTarget(name: "AgentReinsHook", path: "Sources/AgentReinsHook",
                          swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(
            name: "AgentReinsAlertsBridge",
            path: "Sources/AgentReinsAlertsBridge",
            swiftSettings: [ .swiftLanguageMode(.v5) ]
        ),
        .executableTarget(
            name: "AgentReinsMCP",
            path: "Sources/AgentReinsMCP",
            swiftSettings: [ .swiftLanguageMode(.v5) ]
        ),
        .executableTarget(
            name: "AgentReinsKeychainHelper",
            path: "Sources/AgentReinsKeychainHelper",
            swiftSettings: [ .swiftLanguageMode(.v5) ]
        ),
        .testTarget(
            name: "AgentReinsTests",
            dependencies: ["AgentReins"],
            path: "Tests/AgentReinsTests"
        )
    ]
)
