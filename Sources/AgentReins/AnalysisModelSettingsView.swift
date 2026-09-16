import SwiftUI

struct AnalysisModelSettingsView: View {
    @EnvironmentObject private var analyzer: SemanticAnalyzer
    @Environment(\.dismiss) private var dismiss
    @State private var baseURL = ""
    @State private var model = ""
    @State private var apiKey = ""

    private let panel = Color(red: 8/255, green: 27/255, blue: 45/255)
    private let raised = Color(red: 13/255, green: 36/255, blue: 59/255)
    private let cyan = Color(red: 48/255, green: 211/255, blue: 229/255)
    private let green = Color(red: 57/255, green: 214/255, blue: 117/255)
    private let amber = Color(red: 255/255, green: 177/255, blue: 45/255)

    private var endpointHost: String? { SemanticAnalyzer.chatCompletionsURL(baseURL: baseURL)?.host }
    private var route: NetworkDestinationAssessment {
        NetworkDestinationAssessment.assess(domain: endpointHost, host: endpointHost)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Analysis Model").font(.title2.bold())
                    Text("Use any OpenAI-compatible API. Credentials stay in macOS Keychain.")
                        .font(.system(size: 13)).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(.bordered)
            }

            VStack(alignment: .leading, spacing: 13) {
                input("BASE URL", "https://api.openai.com/v1", text: $baseURL)
                input("MODEL", "gpt-4o-mini", text: $model)
                VStack(alignment: .leading, spacing: 5) {
                    Text("API KEY").font(.system(size: 12, weight: .bold)).foregroundStyle(.secondary)
                    SecureField(analyzer.configured ? "Enter a new key to replace the saved key" : "sk-…", text: $apiKey)
                        .textFieldStyle(.plain).padding(10).background(raised, in: RoundedRectangle(cornerRadius: 8))
                }
            }

            HStack(alignment: .top, spacing: 9) {
                Circle().fill(route.kind == .modelProvider ? green : amber).frame(width: 8, height: 8).padding(.top, 4)
                VStack(alignment: .leading, spacing: 3) {
                    Text(endpointHost ?? "Invalid endpoint").font(.system(size: 13, weight: .semibold, design: .monospaced))
                    Text(route.kind.rawValue.uppercased()).font(.system(size: 12, weight: .bold))
                        .foregroundStyle(route.kind == .modelProvider ? green : amber)
                    Text(route.reason).font(.system(size: 13)).foregroundStyle(.secondary)
                }
            }.padding(12).background(raised, in: RoundedRectangle(cornerRadius: 9))

            if let error = analyzer.lastError {
                Label(error, systemImage: "exclamationmark.triangle.fill").font(.system(size: 12)).foregroundStyle(amber)
            }

            HStack {
                if analyzer.configured {
                    Button("Remove configuration", role: .destructive) {
                        analyzer.removeConfiguration()
                        apiKey = ""
                    }
                }
                Spacer()
                Button("Save") {
                    if analyzer.configure(baseURL: baseURL, key: apiKey, model: model) { dismiss() }
                }
                .buttonStyle(.borderedProminent).tint(cyan)
                .disabled(!analyzer.configured && apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(22).frame(width: 620)
        .background(panel).environment(\.colorScheme, .dark)
        .onAppear {
            baseURL = analyzer.baseURL
            model = analyzer.model
        }
    }

    private func input(_ title: String, _ placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 12, weight: .bold)).foregroundStyle(.secondary)
            TextField(placeholder, text: text).textFieldStyle(.plain)
                .font(.system(size: 13, design: .monospaced))
                .padding(10).background(raised, in: RoundedRectangle(cornerRadius: 8))
        }
    }
}
