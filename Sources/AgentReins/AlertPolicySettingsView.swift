import SwiftUI

struct AlertPolicySettingsView: View {
    @EnvironmentObject private var store: AlertPolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var showingNewPolicy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Alert policies").font(.title2.bold())
                    Text("Choose what AgentReins should watch. Changes apply to new live evidence immediately.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    showingNewPolicy = true
                } label: {
                    Label("New policy", systemImage: "plus")
                }
                Button("Restore defaults") { store.reset() }
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            ScrollView {
                LazyVStack(spacing: 12) {
                    if !store.aiCandidates.isEmpty {
                        aiCandidateSection
                    }
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
                                    .disabled(policy.effectiveMode == "observe")
                                Picker("Mode", selection: Binding(
                                    get: { policy.effectiveMode },
                                    set: { policy.mode = $0 }
                                )) {
                                    Text("Observe").tag("observe")
                                    Text("Active").tag("active")
                                }.frame(width: 170)
                                Spacer()
                                Text(policy.effectiveOrigin.uppercased())
                                    .font(.caption2.bold()).foregroundStyle(policy.effectiveOrigin == "built_in" ? .cyan : .purple)
                                if policy.effectiveOrigin != "built_in" {
                                    Button(role: .destructive) { store.remove(policy) } label: {
                                        Image(systemName: "trash")
                                    }.buttonStyle(.borderless)
                                }
                            }
                            HStack(spacing: 6) {
                                Text("Detector").font(.caption.bold()).foregroundStyle(.secondary)
                                Text(policy.effectiveDetector?.title ?? "Unsupported — cannot execute")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(policy.effectiveDetector == nil ? .orange : .secondary)
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
        .sheet(isPresented: $showingNewPolicy) {
            NewAlertPolicyView { policy in
                store.add(policy)
                showingNewPolicy = false
            } onCancel: {
                showingNewPolicy = false
            }
        }
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

    private var aiCandidateSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "brain.head.profile.fill").foregroundStyle(.purple)
                VStack(alignment: .leading, spacing: 2) {
                    Text("AI rule candidates").font(.headline)
                    Text("Candidates are historical hypotheses. Approval only places a supported rule into Observe mode.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text("\(store.aiCandidates.count) PENDING").font(.caption.bold()).foregroundStyle(.purple)
            }
            ForEach(store.aiCandidates) { candidate in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(candidate.name).font(.system(size: 13, weight: .bold))
                        Text(candidate.verdict.uppercased())
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(candidate.verdict == "rejected" ? .orange : .purple)
                        Spacer()
                        Text("\(Int(candidate.confidence * 100))% confidence")
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    Text(candidate.condition).font(.system(size: 11)).foregroundStyle(.secondary)
                    HStack(spacing: 14) {
                        Label(candidate.historicalSampleCount.map { "\(candidate.historicalMatches) matches / \($0) checked events" } ?? "Historical backtest not recorded", systemImage: "clock.arrow.circlepath")
                        Label(candidate.detector?.title ?? "No executable detector mapping",
                              systemImage: candidate.detector == nil ? "exclamationmark.triangle" : "checkmark.circle")
                    }
                    .font(.caption)
                    .foregroundStyle(candidate.detector == nil ? .orange : .secondary)
                    Text("Self-examination: \(candidate.rationale)")
                        .font(.caption).foregroundStyle(.tertiary)
                    HStack {
                        Text("False-positive risk: \(candidate.falsePositiveRisk)")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("Dismiss") { store.dismiss(candidate) }
                        Button("Approve to Observe") { store.approve(candidate) }
                            .buttonStyle(.borderedProminent).tint(.purple)
                            .disabled(candidate.detector == nil || candidate.verdict == "rejected" || !candidate.evidenceSufficient)
                    }
                }
                .padding(11)
                .background(Color.purple.opacity(0.07), in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding(14)
        .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 11))
        .overlay(RoundedRectangle(cornerRadius: 11).stroke(Color.purple.opacity(0.35)))
    }
}

private struct NewAlertPolicyView: View {
    let onSave: (AlertPolicy) -> Void
    let onCancel: () -> Void
    @State private var name = ""
    @State private var detector: AlertDetector = .crossProjectSensitiveFileRead
    @State private var severity = "high"
    @State private var mode = "observe"

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Create alert policy").font(.title2.bold())
                Text("New policies start in Observe mode so you can review matches before enabling notifications.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            TextField("Policy name", text: $name).textFieldStyle(.roundedBorder)
            Picker("Detector", selection: $detector) {
                ForEach(AlertDetector.allCases) { detector in
                    Text(detector.title).tag(detector)
                }
            }
            Picker("Severity", selection: $severity) {
                Text("Medium").tag("medium")
                Text("High").tag("high")
                Text("Critical").tag("critical")
            }
            Picker("Initial mode", selection: $mode) {
                Text("Observe").tag("observe")
                Text("Active").tag("active")
            }
            HStack {
                Spacer()
                Button("Cancel", action: onCancel)
                Button("Create") {
                    let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
                    onSave(AlertPolicy(
                        id: "user_\(UUID().uuidString.lowercased())",
                        name: cleanName,
                        explanation: "User policy using the \(detector.title) detector.",
                        enabled: true,
                        severity: severity,
                        notify: mode == "active",
                        agentNames: [], projectPaths: [], excludedPaths: [],
                        detector: detector, origin: "user", mode: mode))
                }
                .buttonStyle(.borderedProminent)
                .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(20).frame(width: 520)
    }
}
