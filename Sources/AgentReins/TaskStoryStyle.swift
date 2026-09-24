import AppKit
import SwiftUI

/// Tokens taken from the approved task-story-v2 prototype.
enum TaskStoryStyle {
    private static func adaptive(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let value = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: Double((value >> 16) & 255) / 255,
                           green: Double((value >> 8) & 255) / 255,
                           blue: Double(value & 255) / 255, alpha: 1)
        })
    }
    static let background = adaptive(0xf4f6f8, 0x0e1720)
    static let panel = adaptive(0xffffff, 0x17232e)
    static let text = adaptive(0x172632, 0xe3edf4)
    static let muted = adaptive(0x596a78, 0xa2b3c1)
    static let border = adaptive(0xdce3e8, 0x31424e)
    static let accent = adaptive(0x08796e, 0x70dccb)
    static let soft = adaptive(0xe8f5f1, 0x193c39)
}

extension View {
    func storyPanel() -> some View {
        padding(20)
            .background(TaskStoryStyle.panel, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(TaskStoryStyle.border))
    }
}
