// WebScarab (Swift) - viewing messages (ui.swing.RequestPanel / ResponsePanel / ContentPanel and the editors).

import SwiftUI
import AppKit
import WebKit

/// A plain-text view for HTTP messages: monospaced, no smart quotes or autocorrection.
struct CodeTextView: NSViewRepresentable {
    @Binding var text: String
    var editable = true
    var wrap = true

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        let textView = scroll.documentView as! NSTextView
        textView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.isContinuousSpellCheckingEnabled = false
        textView.isRichText = false
        textView.allowsUndo = true
        textView.usesFindBar = true
        textView.isIncrementalSearchingEnabled = true
        textView.delegate = context.coordinator
        textView.textContainerInset = NSSize(width: 4, height: 4)
        configureWrap(textView, scroll)
        textView.string = text
        textView.isEditable = editable
        return scroll
    }

    func configureWrap(_ textView: NSTextView, _ scroll: NSScrollView) {
        if wrap {
            textView.isHorizontallyResizable = false
            textView.textContainer?.widthTracksTextView = true
            scroll.hasHorizontalScroller = false
        } else {
            textView.isHorizontallyResizable = true
            textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
            textView.textContainer?.widthTracksTextView = false
            textView.textContainer?.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
            scroll.hasHorizontalScroller = true
        }
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.parent = self
        guard let textView = scroll.documentView as? NSTextView else { return }
        if textView.string != text { textView.string = text }
        textView.isEditable = editable
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: CodeTextView
        init(_ parent: CodeTextView) { self.parent = parent }
        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            parent.text = textView.string
        }
    }
}

/// Read-only text.
struct ReadOnlyText: View {
    let text: String
    var wrap = true
    var body: some View { CodeTextView(text: .constant(text), editable: false, wrap: wrap) }
}

struct HTMLPreview: NSViewRepresentable {
    let html: String
    let baseURL: URL?

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = false
        return WKWebView(frame: .zero, configuration: configuration)
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        view.loadHTMLString(html, baseURL: baseURL)
    }
}

/// The content editors WebScarab chose by content type (ui.swing.editors.EditorFactory).
enum BodyViewKind: String, CaseIterable, Identifiable {
    case text = "Text", html = "HTML", xml = "XML / JSON", form = "URL-encoded", image = "Image", hex = "Hex"
    var id: String { rawValue }

    static func available<M: HTTPMessage>(for message: M) -> [BodyViewKind] {
        let type = (message.contentType ?? "").lowercased()
        var kinds: [BodyViewKind] = []
        if type.hasPrefix("image/") { kinds.append(.image) }
        if message.isTextual || type.isEmpty { kinds.append(.text) }
        if type.contains("html") { kinds.append(.html) }
        if type.contains("xml") || type.contains("json") { kinds.append(.xml) }
        if type.contains("x-www-form-urlencoded") { kinds.append(.form) }
        kinds.append(.hex)
        return kinds
    }
}

struct BodyView<M: HTTPMessage>: View {
    let message: M
    var baseURL: URL?
    @State private var kind: BodyViewKind?

    var body: some View {
        let kinds = BodyViewKind.available(for: message)
        let current = kind.flatMap { kinds.contains($0) ? $0 : nil } ?? kinds.first ?? .hex
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Picker("", selection: Binding(get: { current }, set: { kind = $0 })) {
                    ForEach(kinds) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                Spacer()
                Text("\(message.body.count) bytes" + (message.header("Content-Encoding").map { ", \($0)" } ?? ""))
                    .font(.caption).foregroundStyle(.secondary)
            }
            content(current)
        }
    }

    @ViewBuilder func content(_ kind: BodyViewKind) -> some View {
        switch kind {
        case .text: ReadOnlyText(text: message.bodyText)
        case .html: HTMLPreview(html: message.bodyText, baseURL: baseURL)
        case .xml: ReadOnlyText(text: Self.pretty(message.bodyText), wrap: false)
        case .hex: ReadOnlyText(text: Encoding.hexDump(message.decodedBody), wrap: false)
        case .image:
            if let image = NSImage(data: message.decodedBody) {
                ScrollView([.horizontal, .vertical]) { Image(nsImage: image) }
            } else {
                Text("The image could not be shown.").foregroundStyle(.secondary)
            }
        case .form:
            let pairs = NamedValue.split(message.bodyText, "&", "=")
            Table(pairs.map { NamedPair(name: Encoding.urlDecode($0.name), value: Encoding.urlDecode($0.value)) }) {
                TableColumn("Variable", value: \.name)
                TableColumn("Value", value: \.value)
            }
        }
    }

    static func pretty(_ text: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") || trimmed.hasPrefix("["),
           let object = try? JSONSerialization.jsonObject(with: Data(trimmed.utf8), options: [.fragmentsAllowed]),
           let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) {
            return String(decoding: data, as: UTF8.self)
        }
        if let document = try? XMLDocument(xmlString: trimmed, options: [.nodePreserveAll]) {
            return document.xmlString(options: [.nodePrettyPrint])
        }
        return text
    }
}

struct NamedPair: Identifiable, Hashable {
    var id: String { name + "=" + value }
    var name: String
    var value: String
}

/// A request or response: parsed (start line, headers, body) or raw.
struct MessageView<M: HTTPMessage>: View {
    let message: M
    var baseURL: URL?
    @State private var raw = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(message.startLine).font(.system(.body, design: .monospaced)).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                Spacer()
                Picker("", selection: $raw) {
                    Text("Parsed").tag(false)
                    Text("Raw").tag(true)
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
            }
            if raw {
                ReadOnlyText(text: message.rawText)
            } else {
                VSplitView {
                    Table(message.headers.enumerated().map { IndexedHeader(index: $0.offset, header: $0.element) }) {
                        TableColumn("Header") { Text($0.header.name).textSelection(.enabled) }.width(min: 80, ideal: 180)
                        TableColumn("Value") { Text($0.header.value).textSelection(.enabled) }
                    }
                    .frame(minHeight: 80, idealHeight: 160)
                    BodyView(message: message, baseURL: baseURL).frame(minHeight: 100)
                }
            }
        }
        .padding(6)
    }
}

struct IndexedHeader: Identifiable {
    var id: Int { index }
    let index: Int
    let header: Header
}

/// The conversation window (ui.swing.ConversationPanel), with previous / next.
struct ConversationWindow: View {
    @State var id: Int
    @EnvironmentObject var framework: Framework
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if let conversation = framework.conversation(id) {
            VStack(spacing: 0) {
                HStack {
                    Button { step(-1) } label: { Image(systemName: "chevron.left") }.help("Previous conversation")
                    Button { step(1) } label: { Image(systemName: "chevron.right") }.help("Next conversation")
                    Text("Conversation \(String(conversation.id)) - \(conversation.method) \(conversation.url.absoluteString)")
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text(conversation.origin).foregroundStyle(.secondary)
                    Text(conversation.date.formatted(date: .abbreviated, time: .standard)).foregroundStyle(.secondary)
                }
                .padding(8)
                Divider()
                VSplitView {
                    GroupBox("Request") { MessageView(message: conversation.request, baseURL: conversation.url) }
                        .frame(minHeight: 150)
                    GroupBox("Response") { MessageView(message: conversation.response, baseURL: conversation.url) }
                        .frame(minHeight: 150)
                }
                .padding(8)
            }
            .navigationTitle("Conversation \(String(conversation.id))")
        } else {
            Text("Conversation \(id) is not in this session.").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    func step(_ delta: Int) {
        let ids = framework.conversations.map(\.id)
        guard let index = ids.firstIndex(of: id) else { return }
        let next = index + delta
        if ids.indices.contains(next) { id = ids[next] }
    }
}
