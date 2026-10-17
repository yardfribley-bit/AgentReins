import SwiftUI

struct AnalysisModelSettingsView: View {
    private enum Provider: String, CaseIterable, Identifiable {
        case openRouter = "OpenRouter"
        case custom = "其他兼容服务"
        var id: String { rawValue }
    }

    @EnvironmentObject private var analyzer: SemanticAnalyzer
    @Environment(\.dismiss) private var dismiss
    @StateObject private var catalog = OpenRouterModelCatalog()
    @State private var provider: Provider = .openRouter
    @State private var baseURL = ""
    @State private var model = ""
    @State private var apiKey = ""
    @State private var search = ""

    private let panel = Color(red: 8/255, green: 27/255, blue: 45/255)
    private let raised = Color(red: 13/255, green: 36/255, blue: 59/255)
    private let cyan = Color(red: 48/255, green: 211/255, blue: 229/255)
    private let green = Color(red: 57/255, green: 214/255, blue: 117/255)
    private let amber = Color(red: 255/255, green: 177/255, blue: 45/255)

    private var effectiveBaseURL: String {
        provider == .openRouter ? "https://openrouter.ai/api/v1" : baseURL
    }
    private var endpointHost: String? { SemanticAnalyzer.chatCompletionsURL(baseURL: effectiveBaseURL)?.host }
    private var route: NetworkDestinationAssessment {
        NetworkDestinationAssessment.assess(domain: endpointHost, host: endpointHost)
    }
    private var filteredModels: [OpenRouterModel] {
        let value = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !value.isEmpty else { return Array(catalog.models.prefix(80)) }
        return catalog.models.filter { $0.name.lowercased().contains(value) || $0.id.lowercased().contains(value) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("规则理解模型").font(.title2.bold())
                    Text("选择服务、粘贴密钥、选择模型，测试后保存。密钥保存在本机钥匙串。")
                        .font(.system(size: 13)).foregroundStyle(.secondary)
                }
                Spacer()
                Button("完成") { dismiss() }.buttonStyle(.bordered)
            }

            Picker("服务", selection: $provider) {
                ForEach(Provider.allCases) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented)

            VStack(alignment: .leading, spacing: 11) {
                if provider == .custom {
                    input("接口地址", "https://your-provider.example/v1", text: $baseURL)
                    input("模型名称（也可手动填写）", "provider/model-name", text: $model)
                }
                VStack(alignment: .leading, spacing: 5) {
                    Text("API 密钥").font(.system(size: 12, weight: .bold)).foregroundStyle(.secondary)
                    SecureField(analyzer.configured ? "密钥已保存；更换时填写新密钥" : "粘贴服务提供的 API 密钥", text: $apiKey)
                        .textFieldStyle(.plain).padding(10).background(raised, in: RoundedRectangle(cornerRadius: 8))
                }
            }

            openRouterModels

            HStack(alignment: .top, spacing: 9) {
                Circle().fill(route.kind == .modelProvider || route.kind == .modelRelay ? green : amber)
                    .frame(width: 8, height: 8).padding(.top, 4)
                VStack(alignment: .leading, spacing: 3) {
                    Text(endpointHost ?? "Invalid endpoint").font(.system(size: 13, weight: .semibold, design: .monospaced))
                    Text(route.kind.rawValue.uppercased()).font(.system(size: 12, weight: .bold))
                        .foregroundStyle(route.kind == .modelProvider || route.kind == .modelRelay ? green : amber)
                    Text(provider == .openRouter
                         ? "OpenRouter is a model relay and can receive the evidence submitted for AI analysis."
                         : route.reason)
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }.padding(11).background(raised, in: RoundedRectangle(cornerRadius: 9))

            if let error = analyzer.lastError ?? catalog.error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12)).foregroundStyle(amber)
            }
            if analyzer.connectionVerified {
                Label("连接已验证 · \(analyzer.model)", systemImage: "checkmark.seal.fill")
                    .font(.system(size: 12, weight: .semibold)).foregroundStyle(green)
            }

            HStack {
                if analyzer.configured {
                    Button("删除配置", role: .destructive) {
                        analyzer.removeConfiguration(); apiKey = ""
                    }
                }
                Spacer()
                Button(analyzer.testingConnection ? "正在测试…" : "测试并保存") {
                    Task {
                        if await analyzer.configureAndTest(baseURL: effectiveBaseURL, key: apiKey, model: model) {
                            apiKey = ""
                        }
                    }
                }
                .buttonStyle(.borderedProminent).tint(cyan)
                .disabled(analyzer.testingConnection || model.isEmpty
                          || (!analyzer.configured && apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty))
            }
        }
        .padding(22).frame(width: 760, height: 720)
        .background(panel).environment(\.colorScheme, .dark)
        .onAppear {
            baseURL = analyzer.baseURL
            model = analyzer.model
            provider = analyzer.baseURL.lowercased().contains("openrouter.ai") ? .openRouter : .custom
            if provider == .openRouter { Task { await catalog.load(apiKey: nil) } }
        }
        .onChange(of: provider) { value in
            model = ""; search = ""; apiKey = ""
        }
    }

    private var openRouterModels: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("选择模型").font(.system(size: 12, weight: .bold)).foregroundStyle(.secondary)
                Spacer()
                if catalog.loading { ProgressView().controlSize(.small) }
                Button("获取 / 刷新模型") { Task { await catalog.load(apiKey: apiKey, baseURL: effectiveBaseURL) } }
                    .buttonStyle(.plain).foregroundStyle(cyan)
            }
            TextField("搜索模型名称，例如 DeepSeek、Claude…", text: $search)
                .textFieldStyle(.plain).padding(9).background(raised, in: RoundedRectangle(cornerRadius: 8))
            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(filteredModels) { item in
                        Button { model = item.id } label: {
                            HStack(spacing: 10) {
                                Image(systemName: model == item.id ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(model == item.id ? green : .secondary)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(item.name).font(.system(size: 13, weight: .semibold))
                                    Text(item.id).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                                }
                                Spacer()
                                VStack(alignment: .trailing, spacing: 3) {
                                    Text(item.contextLabel).font(.system(size: 11, weight: .semibold))
                                    Text(item.priceLabel).font(.system(size: 10)).foregroundStyle(.secondary)
                                }
                            }.padding(9).background(model == item.id ? cyan.opacity(0.10) : raised,
                                                   in: RoundedRectangle(cornerRadius: 8))
                        }.buttonStyle(.plain)
                    }
                }
            }.frame(maxHeight: 310)
            if !model.isEmpty {
                Text("已选择： \(model)").font(.system(size: 11, design: .monospaced)).foregroundStyle(green)
            }
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
