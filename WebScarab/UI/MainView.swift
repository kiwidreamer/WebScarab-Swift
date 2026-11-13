// WebScarab (Swift) - the main window: one tab per plugin above the log (ui.swing.UIFramework).

import SwiftUI

struct MainView: View {
    @EnvironmentObject var state: AppState
    @EnvironmentObject var framework: Framework
    @EnvironmentObject var proxy: ProxyController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VSplitView {
            TabView(selection: $state.tab) {
                SummaryView().tabItem { Text("Summary") }.tag(ToolTab.summary)
                ProxyView().tabItem { Text("Proxy") }.tag(ToolTab.proxy)
                ManualRequestView().tabItem { Text("Manual Request") }.tag(ToolTab.manualRequest)
                SpiderView().tabItem { Text("Spider") }.tag(ToolTab.spider)
                ExtensionsView().tabItem { Text("Extensions") }.tag(ToolTab.extensions)
                XSSCRLFView().tabItem { Text("XSS/CRLF") }.tag(ToolTab.xss)
                SessionIDView().tabItem { Text("SessionID Analysis") }.tag(ToolTab.sessionID)
                FuzzerView().tabItem { Text("Fuzzer") }.tag(ToolTab.fuzzer)
                CompareView().tabItem { Text("Compare") }.tag(ToolTab.compare)
                SearchView().tabItem { Text("Search") }.tag(ToolTab.search)
                FragmentsView().tabItem { Text("Fragments") }.tag(ToolTab.fragments)
                SamlView().tabItem { Text("SAML") }.tag(ToolTab.saml)
            }
            .padding(.top, 4)
            .frame(minHeight: 400)
            if state.showLog {
                LogView().frame(minHeight: 60, idealHeight: 110)
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { statusBar }
        .navigationTitle(framework.sessionFolder.map { "WebScarab - \($0.lastPathComponent)" } ?? "WebScarab")
        .onChange(of: proxy.pending.count) { _, count in
            if count > 0 { openWindow(id: "intercept") }
        }
        .sheet(isPresented: $state.showDiscardDialog) { DiscardDialog() }
        .alert(state.alert ?? "", isPresented: Binding(get: { state.alert != nil }, set: { if !$0 { state.alert = nil } })) {
            Button("OK") { state.alert = nil }
        }
    }

    var statusBar: some View {
        HStack(spacing: 14) {
            ForEach(proxy.listeners) { spec in
                Label("\(spec.address):\(String(spec.port)) \(proxy.listenerStatus[spec.id] ?? "Stopped")",
                      systemImage: proxy.listenerStatus[spec.id] == "Listening" ? "circle.fill" : "circle")
                    .foregroundStyle(proxy.listenerStatus[spec.id] == "Listening" ? .green : .secondary)
            }
            Toggle("Intercept requests", isOn: $proxy.interceptRequests)
            Toggle("Intercept responses", isOn: $proxy.interceptResponses)
            Spacer()
            if !proxy.pending.isEmpty {
                Button("\(proxy.pending.count) waiting") { openWindow(id: "intercept") }
            }
            Text("\(framework.conversations.count) conversations").foregroundStyle(.secondary)
        }
        .toggleStyle(.checkbox)
        .font(.callout)
        .padding(.horizontal, 10).padding(.vertical, 5)
        .background(.bar)
    }
}

struct LogView: View {
    @EnvironmentObject var framework: Framework

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Log").font(.caption.bold())
                Spacer()
                Button("Clear") { framework.clearLog() }.buttonStyle(.borderless).font(.caption)
            }
            .padding(.horizontal, 8).padding(.vertical, 2)
            ScrollViewReader { reader in
                List(framework.log) { entry in
                    Text("\(entry.date.formatted(date: .omitted, time: .standard)) \(entry.level.rawValue) \(entry.source): \(entry.message)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(entry.level == .severe ? .red : entry.level == .warning ? .orange : .primary)
                        .textSelection(.enabled)
                        .id(entry.id)
                }
                .listStyle(.plain)
                .onChange(of: framework.log.count) { _, _ in
                    if let last = framework.log.last { reader.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
    }
}

struct DiscardDialog: View {
    @EnvironmentObject var framework: Framework
    @Environment(\.dismiss) private var dismiss
    @State private var pattern = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Discard conversations matching (URL):").font(.headline)
            TextField("regular expression, e.g. .*\\.(gif|jpg|png)$", text: $pattern).frame(width: 420)
            if !pattern.isEmpty && !String.isValidRegex(pattern) { Text("Not a valid regular expression").foregroundStyle(.red) }
            Text("Matching conversations are not recorded. Leave it empty to keep everything.").font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("OK") { framework.dropPattern = pattern; dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!pattern.isEmpty && !String.isValidRegex(pattern))
            }
        }
        .padding()
        .onAppear { pattern = framework.dropPattern }
    }
}
