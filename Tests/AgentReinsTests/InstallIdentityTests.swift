import Foundation
import XCTest
@testable import AgentReins

final class InstallIdentityTests: XCTestCase {
    func testLabelKeepsRealVersionAndDropsUnsafeText() {
        XCTAssertNil(InstallIdentity.label(version: nil, build: nil))
        XCTAssertNil(InstallIdentity.label(version: "  ", build: " "))
        XCTAssertNil(InstallIdentity.label(version: "1.1.0<script>", build: "176 build"))
        XCTAssertEqual(
            InstallIdentity.label(version: " 1.1.0 ", build: "176"),
            InstallIdentity.Label(version: "1.1.0", build: "176")
        )
        XCTAssertEqual(
            InstallIdentity.label(version: "1.1.0", build: nil),
            InstallIdentity.Label(version: "1.1.0", build: nil)
        )
        XCTAssertEqual(
            InstallIdentity.label(version: nil, build: "ui-v2-20261108.1713"),
            InstallIdentity.Label(version: nil, build: "ui-v2-20261108.1713")
        )
    }

    func testPageScriptAssignsOnlySanitizedFields() {
        let both = InstallIdentity.pageScript(for: InstallIdentity.label(version: "1.1.0", build: "176"))
        XCTAssertEqual(both, #"window.agentreinsInstall={"version":"1.1.0","build":"176"};"#)
        let versionOnly = InstallIdentity.pageScript(for: InstallIdentity.label(version: "1.1.0", build: "bad build"))
        XCTAssertEqual(versionOnly, #"window.agentreinsInstall={"version":"1.1.0"};"#)
        XCTAssertEqual(InstallIdentity.pageScript(for: nil), "window.agentreinsInstall=null;")
        XCTAssertEqual(InstallIdentity.pageScript(for: InstallIdentity.Label(version: nil, build: nil)), "window.agentreinsInstall=null;")
        XCTAssertFalse(both.contains("<"))
    }

    func testLabelReadsInfoPlist() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("AgentReinsIdentity-\(UUID().uuidString).app", isDirectory: true)
        let contents = root.appendingPathComponent("Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>CFBundleIdentifier</key><string>com.agentspec.agentreins.identity-test</string>
        <key>CFBundleName</key><string>AgentReins</string>
        <key>CFBundlePackageType</key><string>APPL</string>
        <key>CFBundleShortVersionString</key><string>1.1.0</string>
        <key>CFBundleVersion</key><string>176</string>
        </dict></plist>
        """
        try plist.write(to: contents.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        let bundle = try XCTUnwrap(Bundle(url: root))
        XCTAssertEqual(InstallIdentity.label(from: bundle), InstallIdentity.Label(version: "1.1.0", build: "176"))
        XCTAssertEqual(
            InstallIdentity.pageScript(bundle: bundle),
            #"window.agentreinsInstall={"version":"1.1.0","build":"176"};"#
        )
    }
}
