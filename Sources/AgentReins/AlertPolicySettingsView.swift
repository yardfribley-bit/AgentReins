import SwiftUI

struct AlertPolicySettingsView: View {
    @EnvironmentObject private var store: AlertPolicyStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Alert policies").font(.title2.bold())
                    Text("Choose what AgentReins should watch. Changes apply to new live evidence immediately.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Restore defaults") { store.reset() }
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            ScrollView {
                LazyVStack(spacing: 12) {
                    ForEach($store.policies) { $policy in
                        VStack(alignment: .leading, spacing: 11) {
                            HStack {
                                Toggle(isOn: $policy.enabled) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(policy.name).font(.headline)
                                        Text(policy.explanation).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                .toggleStyle(.switch)
                            }
                            HStack(spacing: 18) {
                                Picker("Severity", selection: $policy.severity) {
                                    Text("Medium").tag("medium")
                                    Text("High").tag("high")
                                    Text("Critical").tag("critical")
                                }.frame(width: 210)
                                Toggle("System notification", isOn: $policy.notify)
                                Spacer()
                                Text(policy.id).font(.caption.monospaced()).foregroundStyle(.tertiary)
                            }
                            policyListField("Only these Agents", values: $policy.agentNames,
                                            placeholder: "All Agents (or: WorkBuddy, Codex)")
                            policyListField("Only these projects", values: $policy.projectPaths,
                                            placeholder: "All projects (or absolute paths)")
                            policyListField("Excluded paths", values: $policy.excludedPaths,
                                            placeholder: "None (comma-separated absolute paths)")
                        }
                        .padding(14).background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 11))
                        .opacity(policy.enabled ? 1 : 0.55)
                    }
                }
            }
            Text("Policies are stored locally on this Mac. Disabling an alert never deletes raw evidence.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(18).frame(minWidth: 760, minHeight: 650)
    }

    private func policyListField(_ title: String, values: Binding<[String]>, placeholder: String) -> some View {
        let text = Binding<String>(get: { values.wrappedValue.joined(separator: ", ") }, set: { raw in
            values.wrappedValue = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        })
        return HStack {
            Text(title).font(.system(size: 12, weight: .semibold)).frame(width: 135, alignment: .leading)
            TextField(placeholder, text: text).textFieldStyle(.roundedBorder)
        }
    }
}
