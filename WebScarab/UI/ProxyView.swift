// WebScarab (Swift) - the Proxy tab (plugin.proxy.swing.ProxyPanel, ManualEditPanel, MiscPanel)
// and the intercept window (ManualEditFrame).

import SwiftUI

struct ProxyView: View {
    @State private var section = 0

    var body: some View {
        VStack {
            Picker("", selection: $section) {
                Text("Listeners").tag(0)
                Text("Manual Edit").tag(1)
                Text("Miscellaneous").tag(2)
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            switch section {
            case 0: ListenersPanel()
            case 1: ManualEditPanel()
            default: MiscPanel()
            }
        }
        .padding()
    }
}

struct ListenersPanel: View {
    @EnvironmentObject var proxy: ProxyController
    @State private var selection: ListenerSpec.ID?
    @State private var address = "127.0.0.1"
    @State private var port = "8008"
    @State private var base = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Point your browser's HTTP and HTTPS proxy at a listener below. Everything it sends is recorded in the Summary tab.")
                .foregroundStyle(.secondary)
            Table(proxy.listeners, selection: $selection) {
                TableColumn("Address", value: \.address)
                TableColumn("Port") { Text(String($0.port)) }
                TableColumn("Base URL") { Text($0.base.isEmpty ? "-" : $0.base) }
                TableColumn("Status") { Text(proxy.listenerStatus[$0.id] ?? "Stopped") }
            }
            .frame(minHeight: 120)
            HStack {
                Button("Start") { if let spec = selected { proxy.start(spec) } }.disabled(selected.map { proxy.isRunning($0) } ?? true)
                Button("Stop") { if let spec = selected { proxy.stop(spec) } }.disabled(!(selected.map { proxy.isRunning($0) } ?? false))
                Button("Remove") { if let spec = selected { proxy.removeListener(spec) } }.disabled(selected == nil)
            }
            GroupBox("New listener") {
                HStack {
                    TextField("Address", text: $address).frame(width: 140)
                    TextField("Port", text: $port).frame(width: 70)
                    TextField("Base URL (reverse proxy, optional)", text: $base)
                    Button("Add") {
                        guard let number = Int(port), (1...65535).contains(number) else { return }
                        proxy.addListener(ListenerSpec(address: address, port: number, base: base))
                    }
                }
                .padding(4)
            }
            Spacer()
        }
    }

    var selected: ListenerSpec? { proxy.listeners.first { $0.id == selection } }
}

struct ManualEditPanel: View {
    @EnvironmentObject var proxy: ProxyController

    var body: some View {
        Form {
            Section("Requests") {
                Toggle("Intercept requests", isOn: $proxy.interceptRequests)
                TextField("Methods", text: $proxy.interceptMethods)
                RegexField(title: "Include paths matching", text: $proxy.includeRegex)
                RegexField(title: "Exclude paths matching", text: $proxy.excludeRegex)
                Toggle("Case sensitive", isOn: $proxy.caseSensitive)
            }
            Section("Responses") {
                Toggle("Intercept responses", isOn: $proxy.interceptResponses)
                RegexField(title: "Only for content types matching", text: $proxy.responseContentRegex)
            }
            Section {
                Text("Intercepted messages open in their own window, where you can change them before they continue.")
                    .foregroundStyle(.secondary)
                Button("Let everything waiting through and stop intercepting") { proxy.releaseAll() }
                    .disabled(proxy.pending.isEmpty)
            }
        }
        .formStyle(.grouped)
    }
}

struct RegexField: View {
    let title: String
    @Binding var text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            TextField(title, text: $text)
            if !text.isEmpty && !String.isValidRegex(text) {
                Text("Not a valid regular expression").font(.caption).foregroundStyle(.red)
            }
        }
    }
}

struct MiscPanel: View {
    @EnvironmentObject var proxy: ProxyController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Form {
            Section("HTTPS") {
                Toggle("Intercept HTTPS (show the browser a WebScarab certificate)", isOn: $proxy.interceptHTTPS)
                Text("Browsers only accept these certificates after you trust the WebScarab CA certificate. When this is off, HTTPS passes through unrecorded.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Certificates…") { openWindow(id: "certificates") }
            }
            Section("Proxy plugins") {
                Toggle("Reveal hidden fields in HTML pages", isOn: $proxy.revealHidden)
                Toggle("Prevent browser from caching content", isOn: $proxy.disableBrowserCache)
                Toggle("Inject known cookies into requests", isOn: $proxy.injectCookies)
            }
        }
        .formStyle(.grouped)
    }
}

struct InterceptWindow: View {
    @EnvironmentObject var proxy: ProxyController
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Group {
            if let item = proxy.pending.first {
                InterceptEditor(item: item)
                    .id(item.id)
            } else {
                VStack(spacing: 8) {
                    Text("Nothing is waiting.").font(.title3)
                    Text("Turn on \"Intercept requests\" or \"Intercept responses\" and browse through the proxy.").foregroundStyle(.secondary)
                    HStack {
                        Toggle("Intercept requests", isOn: $proxy.interceptRequests)
                        Toggle("Intercept responses", isOn: $proxy.interceptResponses)
                    }
                    .toggleStyle(.checkbox)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding()
    }
}

struct InterceptEditor: View {
    @ObservedObject var item: InterceptItem
    @EnvironmentObject var proxy: ProxyController

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(item.title).font(.headline).lineLimit(2).truncationMode(.middle)
            if proxy.pending.count > 1 {
                Text("\(proxy.pending.count - 1) more waiting").font(.caption).foregroundStyle(.secondary)
            }
            CodeTextView(text: $item.text)
                .border(Color.secondary.opacity(0.3))
            HStack {
                Toggle("Intercept requests", isOn: $proxy.interceptRequests)
                Toggle("Intercept responses", isOn: $proxy.interceptResponses)
                Spacer()
                Button(item.kind == .request ? "Abort request" : "Abort response", role: .destructive) { proxy.resolve(item, .abort) }
                Button("Cancel changes") { proxy.resolve(item, .original) }
                Button("Accept changes") {
                    proxy.resolve(item, item.text == item.originalText ? .original : .edited(item.text))
                }
                .keyboardShortcut(.defaultAction)
            }
            .toggleStyle(.checkbox)
        }
    }
}
