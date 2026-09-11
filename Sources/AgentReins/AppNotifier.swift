import Foundation
import UserNotifications

/// Single notification boundary for every protection engine.
/// Keeping delivery here avoids each sensor depending on deprecated AppKit APIs.
enum AppNotifier {
    static func requestAuthorization() {
        guard canDeliver else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func send(title: String, body: String) {
        guard canDeliver else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    /// UserNotifications requires an application bundle. Collectors are also
    /// exercised by command-line benchmarks and XCTest, where asking for the
    /// singleton raises an Objective-C assertion instead of returning an error.
    private static var canDeliver: Bool {
        Bundle.main.bundleURL.pathExtension.lowercased() == "app"
    }
}
