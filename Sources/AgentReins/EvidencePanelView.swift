import SwiftUI

/// Common shell for network, file, memory, tool, code, and timeline evidence.
struct EvidencePanelView<Content: View>: View {
    let title: String
    let subtitle: String
    let stacked: Bool
    let content: Content

    init(_ title: String, subtitle: String, stacked: Bool = false,
         @ViewBuilder content: () -> Content) {
        self.title = title
        self.subtitle = subtitle
        self.stacked = stacked
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundStyle(cyan)
                Text(subtitle).font(.system(size: 13)).foregroundStyle(.secondary)
            }
            if stacked { VStack(spacing: 8) { content } }
            else { content }
        }
        .padding(13)
        .background(panel, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(border))
    }

    private let panel = Color(red: 8/255, green: 27/255, blue: 45/255)
    private let border = Color(red: 27/255, green: 66/255, blue: 96/255)
    private let cyan = Color(red: 48/255, green: 211/255, blue: 229/255)
}
