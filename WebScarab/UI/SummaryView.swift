// WebScarab (Swift) - the Summary tab (ui.swing.SummaryPanel): the site tree above the conversation list.

import SwiftUI
import AppKit

/// The conversation list used across the tools (ui.swing.ConversationTableModel), with its actions.
struct ConversationTable: View {
    let conversations: [Conversation]
    @Binding var selection: Set<Int>
    var extraColumnTitle: String? = nil
    var extraColumn: ((Conversation) -> String)? = nil

    @EnvironmentObject var framework: Framework
    @EnvironmentObject var state: AppState
    @EnvironmentObject var manualRequest: ManualRequest
    @EnvironmentObject var fuzzer: Fuzzer
    @EnvironmentObject var compare: Compare
    @EnvironmentObject var xss: XSSCRLF
    @Environment(\.openWindow) private var openWindow
    @State private var sortOrder = [KeyPathComparator(\Conversation.id, order: .reverse)]
    @State private var tagging: Int?
    @State private var tagText = ""

    var body: some View {
        Table(conversations.sorted(using: sortOrder), selection: $selection, sortOrder: $sortOrder) {
            TableColumn("ID", value: \.id) { Text(String($0.id)).monospacedDigit() }.width(min: 36, ideal: 50, max: 80)
            TableColumn("Date", value: \.date) { Text($0.date.formatted(date: .omitted, time: .standard)) }.width(min: 60, ideal: 80, max: 120)
            TableColumn("Method", value: \.method).width(min: 40, ideal: 60, max: 90)
            TableColumn("Host", value: \.host).width(min: 80, ideal: 200)
            TableColumn("Path", value: \.path).width(min: 80, ideal: 220)
            TableColumn("Parameters", value: \.parameters).width(min: 40, ideal: 140)
            TableColumn("Status", value: \.status).width(min: 50, ideal: 100)
            TableColumn("Origin", value: \.origin).width(min: 50, ideal: 80)
            TableColumn(extraColumnTitle ?? "Tag", value: \.tag) { conversation in
                Text(extraColumn?(conversation) ?? conversation.tag)
            }.width(min: 40, ideal: 80)
            TableColumn("Size", value: \.size) { Text(String($0.size)).monospacedDigit() }.width(min: 40, ideal: 60, max: 100)
        }
        .contextMenu(forSelectionType: Int.self) { ids in
            menu(ids)
        } primaryAction: { ids in
            for id in ids.prefix(5) { openWindow(id: "conversation", value: id) }
        }
        .sheet(item: Binding(get: { tagging.map(TagTarget.init) }, set: { tagging = $0?.id })) { target in
            VStack(alignment: .leading) {
                Text("Tag conversation \(target.id)").font(.headline)
                TextField("Tag", text: $tagText).frame(width: 260)
                HStack {
                    Spacer()
                    Button("Cancel") { tagging = nil }
                    Button("OK") { framework.setTag(tagText, for: target.id); tagging = nil }.keyboardShortcut(.defaultAction)
                }
            }
            .padding()
        }
    }

    @ViewBuilder func menu(_ ids: Set<Int>) -> some View {
        if let first = ids.sorted().first, let conversation = framework.conversation(first) {
            Button("Show conversation") { for id in ids.prefix(5) { openWindow(id: "conversation", value: id) } }
            Button("Tag conversation…") { tagText = conversation.tag; tagging = first }
            Divider()
            Button("Use as Manual Request") { manualRequest.load(conversation.request); state.tab = .manualRequest }
            Button("Use as fuzz template") { fuzzer.load(from: conversation.request); state.tab = .fuzzer }
            Button("Compare responses with this one") { compare.compare(base: first); state.tab = .compare }
            Button("Check for XSS/CRLF") { xss.check(conversations: ids); state.tab = .xss }
            Divider()
            Button("Copy URL") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(ids.sorted().compactMap { framework.conversation($0)?.url.absoluteString }.joined(separator: "\n"), forType: .string)
            }
            Button("Copy request") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(conversation.request.rawText, forType: .string)
            }
        }
    }
}

struct TagTarget: Identifiable { let id: Int }

/// A value snapshot of a site tree node, so the table notices changes.
struct SiteRow: Identifiable, Hashable {
    let id: String
    let name: String
    let methods: String
    let status: String
    let children: [SiteRow]?

    init(_ node: SiteNode) {
        id = node.id
        name = node.name
        methods = node.methodText
        status = node.statusText
        children = node.childNodes?.map(SiteRow.init)
    }
}

struct SummaryView: View {
    @EnvironmentObject var framework: Framework
    @EnvironmentObject var spider: Spider
    @EnvironmentObject var extensions: Extensions
    @EnvironmentObject var state: AppState
    @State private var treeSelection: Set<String> = []
    @State private var conversationSelection: Set<Int> = []
    @State private var treeFilters = true

    var body: some View {
        VSplitView {
            VStack(spacing: 4) {
                HStack {
                    Toggle("Tree selection filters conversation list", isOn: $treeFilters)
                    Spacer()
                    Text("\(framework.conversations.count) conversations").foregroundStyle(.secondary)
                }
                siteTree
            }
            .padding(.horizontal, 8).padding(.top, 6)
            .frame(minHeight: 140, idealHeight: 260)

            ConversationTable(conversations: filtered, selection: $conversationSelection)
                .frame(minHeight: 160)
        }
    }

    var siteTree: some View {
        let _ = framework.treeVersion
        return Table(framework.roots.map(SiteRow.init), children: \.children, selection: $treeSelection) {
            TableColumn("Url") { node in Text(node.name).lineLimit(1) }.width(min: 200, ideal: 420)
            TableColumn("Methods") { node in Text(node.methods) }.width(min: 60, ideal: 100)
            TableColumn("Status") { node in Text(node.status).lineLimit(1) }.width(min: 60, ideal: 160)
        }
        .contextMenu(forSelectionType: String.self) { keys in
            Button("Spider tree") { spider.fetch(under: Array(keys)); state.tab = .spider }
            Button("Check extensions") {
                extensions.check(urls: keys.compactMap { URL(string: $0) })
                state.tab = .extensions
            }
            Button("Copy URL") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(keys.sorted().joined(separator: "\n"), forType: .string)
            }
        }
    }

    var filtered: [Conversation] {
        guard treeFilters, !treeSelection.isEmpty else { return framework.conversations }
        let nodes = treeSelection.compactMap { framework.node($0) }
        return framework.conversations.filter { conversation in
            let key = SiteNode.key(for: conversation.url)
            return nodes.contains { $0.covers(key) }
        }
    }
}
