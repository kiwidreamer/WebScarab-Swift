// WebScarab (Swift) - the tool tabs: Manual Request, Spider, Extensions, XSS/CRLF, Fuzzer,
// Compare, Search and Fragments.

import SwiftUI
import AppKit
import UniformTypeIdentifiers

// MARK: Manual Request (plugin.manualrequest.swing.ManualRequestPanel)

struct ManualRequestView: View {
    @EnvironmentObject var manual: ManualRequest
    @EnvironmentObject var framework: Framework
    @State private var previous: Int?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Picker("Previous requests", selection: $previous) {
                    Text("Choose a recorded request…").tag(Int?.none)
                    ForEach(framework.conversations.suffix(200).reversed()) { conversation in
                        Text("\(conversation.id) \(conversation.method) \(conversation.url.absoluteString)").lineLimit(1).tag(Int?.some(conversation.id))
                    }
                }
                .onChange(of: previous) { _, id in
                    if let id, let conversation = framework.conversation(id) { manual.load(conversation.request) }
                }
                Button("Get cookies") { manual.addCookies() }.help("Add the cookies WebScarab knows for this URL")
                Button(manual.busy ? "Fetching…" : "Fetch Response") { manual.fetch() }
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(manual.busy)
            }
            if let error = manual.error { Text(error).foregroundStyle(.red) }
            VSplitView {
                GroupBox("Request") { CodeTextView(text: $manual.requestText) }.frame(minHeight: 140)
                GroupBox("Response") {
                    if let response = manual.response {
                        MessageView(message: response, baseURL: manual.lastRequest?.url)
                    } else {
                        Text("Edit the request above and choose Fetch Response.").foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
                .frame(minHeight: 140)
            }
        }
        .padding()
    }
}

// MARK: Spider (plugin.spider.swing.SpiderPanel)

struct SpiderView: View {
    @EnvironmentObject var spider: Spider
    @State private var selection: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Form {
                RegexField(title: "Allowed domains", text: $spider.allowedDomains)
                RegexField(title: "Forbidden paths", text: $spider.forbiddenPaths)
                Toggle("Send and remember cookies", isOn: $spider.cookieSync)
                LabeledContent("Extra headers (Name: value per line)") {
                    TextEditor(text: $spider.extraHeaders).font(.system(.body, design: .monospaced)).frame(height: 44)
                }
            }
            .formStyle(.columns)
            HStack {
                Text("Links found but not fetched yet: \(spider.unseen.count)").font(.headline)
                Spacer()
                Text(spider.status).foregroundStyle(.secondary)
            }
            Table(spider.unseenLinks, selection: $selection) {
                TableColumn("URL") { Text($0.url.absoluteString) }
                TableColumn("Found on") { Text($0.referer ?? "") }
            }
            HStack {
                Button("Fetch selection") { spider.fetch(spider.unseenLinks.filter { selection.contains($0.id) }) }.disabled(selection.isEmpty)
                Button("Fetch all") { spider.fetch() }.disabled(spider.unseen.isEmpty)
                Button("Stop") { spider.stop() }
                Button("Clear list") { spider.clearQueue() }
                Spacer()
                if !spider.authRequired.isEmpty { Text("\(spider.authRequired.count) need a login").foregroundStyle(.orange) }
            }
        }
        .padding()
    }
}

// MARK: Extensions (plugin.extensions.swing.ExtensionsPanel)

struct ExtensionsView: View {
    @EnvironmentObject var extensions: Extensions
    @EnvironmentObject var framework: Framework
    @State private var selection: Set<Int> = []
    @State private var urls = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Looks for forgotten copies of files and directories, such as login.php.bak or backup.zip.").foregroundStyle(.secondary)
            Form {
                TextField("File extensions", text: $extensions.fileExtensions)
                TextField("Directory extensions", text: $extensions.directoryExtensions)
            }
            HStack {
                TextField("URLs to check, one per line (or use Check extensions on the Summary site tree)", text: $urls, axis: .vertical)
                    .lineLimit(1...3)
                Button("Check") {
                    extensions.check(urls: urls.split(whereSeparator: \.isNewline).compactMap { URL(string: String($0).trimmingCharacters(in: .whitespaces)) })
                }
                Button("Check every seen file") {
                    extensions.check(urls: framework.allNodes.filter { $0.conversationCount > 0 && !$0.id.contains("?") }.compactMap { URL(string: $0.id) })
                }
            }
            HStack {
                Text("Found: \(extensions.found.count)").font(.headline)
                Spacer()
                Text(extensions.status).foregroundStyle(.secondary)
            }
            ConversationTable(conversations: extensions.found.compactMap { framework.conversation($0) }, selection: $selection)
        }
        .padding()
    }
}

// MARK: XSS/CRLF (plugin.xsscrlf.swing.XSSCRLFPanel)

struct XSSCRLFView: View {
    @EnvironmentObject var xss: XSSCRLF
    @EnvironmentObject var framework: Framework
    @State private var suspiciousSelection: Set<String> = []
    @State private var vulnerableSelection: Set<Int> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Form {
                TextField("XSS test string", text: $xss.xssTestString)
                TextField("CRLF test string", text: $xss.crlfTestString)
            }
            HStack {
                Text("Possibly injectable parameters: \(xss.suspicious.count)").font(.headline)
                Spacer()
                Text(xss.status).foregroundStyle(.secondary)
                Button("Check selected") {
                    let ids = Set(xss.suspicious.filter { suspiciousSelection.contains($0.id) }.map(\.conversation))
                    xss.check(conversations: ids)
                }
                .disabled(suspiciousSelection.isEmpty)
            }
            Table(xss.suspicious, selection: $suspiciousSelection) {
                TableColumn("ID") { Text(String($0.conversation)) }.width(50)
                TableColumn("Kind", value: \.kind).width(50)
                TableColumn("Where", value: \.location).width(50)
                TableColumn("Parameter", value: \.name).width(min: 80, ideal: 140)
                TableColumn("URL") { Text($0.url.absoluteString) }
            }
            Text("Confirmed by a test: \(xss.vulnerable.count)").font(.headline)
            ConversationTable(conversations: xss.vulnerable.compactMap { framework.conversation($0.conversation) }, selection: $vulnerableSelection,
                              extraColumnTitle: "Finding") { conversation in
                xss.vulnerable.first { $0.conversation == conversation.id }.map { "\($0.kind) in \($0.name)" } ?? ""
            }
        }
        .padding()
    }
}

// MARK: Fuzzer (plugin.fuzz.swing.FuzzerPanel)

struct FuzzerView: View {
    @EnvironmentObject var fuzzer: Fuzzer
    @EnvironmentObject var framework: Framework
    @State private var parameterSelection: Set<FuzzParameter.ID> = []
    @State private var resultSelection: Set<Int> = []
    @State private var regexName = ""
    @State private var regexPattern = ""
    @State private var headersText = ""
    @State private var sourceError: String?

    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    TextField("Method", text: $fuzzer.method).frame(width: 80)
                    TextField("URL", text: $fuzzer.url)
                    TextField("Version", text: $fuzzer.version).frame(width: 90)
                }
                Text("Headers").font(.headline)
                TextEditor(text: $headersText)
                    .font(.system(.body, design: .monospaced))
                    .frame(height: 70)
                    .onAppear { headersText = fuzzer.headers.map { "\($0.name): \($0.value)" }.joined(separator: "\n") }
                    .onChange(of: fuzzer.headers) { _, headers in
                        let text = headers.map { "\($0.name): \($0.value)" }.joined(separator: "\n")
                        if text != headersText { headersText = text }
                    }
                    .onChange(of: headersText) { _, text in
                        fuzzer.headers = text.split(separator: "\n").compactMap { line in
                            guard let colon = line.firstIndex(of: ":") else { return nil }
                            return Header(String(line[..<colon]).trimmingCharacters(in: .whitespaces), String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces))
                        }
                    }
                Text("Parameters").font(.headline)
                Table($fuzzer.parameters, selection: $parameterSelection) {
                    TableColumn("Location") { $parameter in
                        Picker("", selection: $parameter.location) { ForEach(FuzzParameter.locations, id: \.self) { Text($0) } }.labelsHidden()
                    }.width(min: 80, ideal: 100)
                    TableColumn("Name") { $parameter in TextField("", text: $parameter.name) }
                    TableColumn("Value") { $parameter in TextField("", text: $parameter.value) }
                    TableColumn("Priority") { $parameter in
                        Stepper(value: $parameter.priority, in: 0...9) { Text(String(parameter.priority)) }
                    }.width(70)
                    TableColumn("Fuzz source") { $parameter in
                        Picker("", selection: $parameter.source) {
                            Text("(fixed value)").tag("")
                            ForEach(fuzzer.sources) { Text($0.name).tag($0.name) }
                        }.labelsHidden()
                    }.width(min: 100, ideal: 150)
                }
                HStack {
                    Button("Add parameter") { fuzzer.parameters.append(FuzzParameter()) }
                    Button("Remove") { fuzzer.parameters.removeAll { parameterSelection.contains($0.id) } }.disabled(parameterSelection.isEmpty)
                    Spacer()
                    Text("\(fuzzer.combinations().count) requests").foregroundStyle(.secondary)
                    Button("Start") { fuzzer.start() }.disabled(fuzzer.isBusy)
                    Button("Stop") { fuzzer.stop() }
                }
                HStack {
                    Text(fuzzer.status)
                    if fuzzer.totalRequests > 0 { ProgressView(value: Double(fuzzer.requestIndex), total: Double(fuzzer.totalRequests)) }
                }
                ConversationTable(conversations: fuzzer.results.compactMap { framework.conversation($0) }, selection: $resultSelection)
                    .frame(minHeight: 120)
            }
            .padding()
            .frame(minWidth: 520)

            VStack(alignment: .leading, spacing: 8) {
                Text("Fuzz sources").font(.headline)
                List(fuzzer.sources) { source in
                    VStack(alignment: .leading) {
                        Text(source.name)
                        Text("\(source.items.count) values: " + source.items.prefix(3).joined(separator: ", ")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                Button("Load from file…") {
                    let panel = NSOpenPanel()
                    panel.allowedContentTypes = [.plainText, .text]
                    if panel.runModal() == .OK, let url = panel.url {
                        do { try fuzzer.addSource(fromFile: url) } catch { sourceError = "\(error)" }
                    }
                }
                GroupBox("From a pattern") {
                    VStack(alignment: .leading) {
                        TextField("Name", text: $regexName)
                        TextField("Pattern, e.g. [a-z]{2}[0-9]", text: $regexPattern)
                        Button("Add") {
                            do {
                                try fuzzer.addRegexSource(name: regexName.isEmpty ? regexPattern : regexName, pattern: regexPattern)
                                sourceError = nil
                            } catch { sourceError = "\(error)" }
                        }
                        .disabled(regexPattern.isEmpty)
                    }
                }
                if let sourceError { Text(sourceError).foregroundStyle(.red).font(.caption) }
            }
            .padding()
            .frame(minWidth: 220, idealWidth: 260)
        }
    }
}

// MARK: Compare (plugin.compare.swing.ComparePanel)

struct CompareView: View {
    @EnvironmentObject var compare: Compare
    @EnvironmentObject var framework: Framework
    @State private var selection: Set<Int> = []
    @State private var baseChoice: Int?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Picker("Base conversation", selection: $baseChoice) {
                    Text("Choose…").tag(Int?.none)
                    ForEach(framework.conversations.suffix(300).reversed()) { c in
                        Text("\(c.id) \(c.method) \(c.url.absoluteString)").lineLimit(1).tag(Int?.some(c.id))
                    }
                }
                Button("Compare") { if let baseChoice { compare.compare(base: baseChoice) } }.disabled(baseChoice == nil)
                if compare.busy { ProgressView().controlSize(.small) }
            }
            .onAppear { baseChoice = compare.baseID }
            .onChange(of: compare.baseID) { _, id in baseChoice = id }
            Text("Responses for the same page, by how many words differ from the base response.").foregroundStyle(.secondary)
            VSplitView {
                ConversationTable(conversations: compare.distances.keys.compactMap { framework.conversation($0) }, selection: $selection,
                                  extraColumnTitle: "Distance") { conversation in
                    compare.distances[conversation.id].map(String.init) ?? ""
                }
                .frame(minHeight: 120)
                diff.frame(minHeight: 120)
            }
        }
        .padding()
    }

    @ViewBuilder var diff: some View {
        if let baseID = compare.baseID, let other = selection.first, let base = framework.conversation(baseID), let target = framework.conversation(other) {
            let lines = LineDiff.diff(base.response.bodyText.components(separatedBy: "\n"), target.response.bodyText.components(separatedBy: "\n"))
            List(Array(lines.enumerated()), id: \.offset) { _, line in
                switch line {
                case .same(let text): Text("  " + text).font(.system(size: 11, design: .monospaced))
                case .removed(let text): Text("- " + text).font(.system(size: 11, design: .monospaced)).foregroundStyle(.red)
                case .added(let text): Text("+ " + text).font(.system(size: 11, design: .monospaced)).foregroundStyle(.green)
                }
            }
        } else {
            Text("Select a conversation to see how its response differs from the base.").foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

// MARK: Search (plugin.search.swing.SearchPanel)

struct SearchView: View {
    @EnvironmentObject var search: Search
    @EnvironmentObject var framework: Framework
    @State private var conversationSelection: Set<Int> = []
    @State private var draft = SearchDefinition(name: "", scope: .body, pattern: "")

    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 8) {
                Text("Searches").font(.headline)
                List(selection: $search.selected) {
                    ForEach(search.searches) { item in
                        VStack(alignment: .leading) {
                            Text(item.name)
                            Text("\(item.scope.rawValue) \(item.isRegex ? "matches" : "contains") \"\(item.pattern)\" - \(search.matches[item.id]?.count ?? 0) found")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .tag(item.id)
                    }
                }
                HStack {
                    Button("Run again") { if let id = search.selected { search.run(id) } }.disabled(search.selected == nil)
                    Button("Remove") { if let id = search.selected { search.remove(id) } }.disabled(search.selected == nil)
                }
                GroupBox("New search") {
                    VStack(alignment: .leading) {
                        TextField("Name", text: $draft.name)
                        Picker("Look in", selection: $draft.scope) { ForEach(SearchDefinition.Scope.allCases) { Text($0.rawValue).tag($0) } }
                        TextField("Text to find", text: $draft.pattern)
                        Toggle("Regular expression", isOn: $draft.isRegex)
                        Toggle("Case sensitive", isOn: $draft.caseSensitive)
                        Button("Add search") {
                            var item = draft
                            item.id = UUID()
                            if item.name.isEmpty { item.name = item.pattern }
                            search.add(item)
                        }
                        .disabled(draft.pattern.isEmpty || (draft.isRegex && !String.isValidRegex(draft.pattern)))
                    }
                }
            }
            .padding()
            .frame(minWidth: 260, idealWidth: 300)

            ConversationTable(conversations: results, selection: $conversationSelection)
                .frame(minWidth: 400)
        }
    }

    var results: [Conversation] {
        guard let id = search.selected, let found = search.matches[id] else { return [] }
        return framework.conversations.filter { found.contains($0.id) }
    }
}

// MARK: Fragments (plugin.fragments.swing.FragmentsPanel)

struct FragmentsView: View {
    @EnvironmentObject var fragments: Fragments
    @EnvironmentObject var framework: Framework
    @State private var kind = Fragments.kinds[0]
    @State private var selectedFragment: String?
    @State private var conversationSelection: Set<Int> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Type", selection: $kind) {
                ForEach(Fragments.kinds, id: \.self) { name in
                    Text("\(name) (\(fragments.fragments[name]?.count ?? 0))").tag(name)
                }
            }
            .onChange(of: kind) { _, _ in selectedFragment = nil }
            VSplitView {
                List(selection: $selectedFragment) {
                    ForEach((fragments.fragments[kind] ?? [:]).keys.sorted(), id: \.self) { fragment in
                        Text(fragment).font(.system(size: 11, design: .monospaced)).lineLimit(3).tag(fragment)
                    }
                }
                .frame(minHeight: 150)
                ConversationTable(conversations: (selectedFragment.flatMap { fragments.fragments[kind]?[$0] } ?? []).compactMap { framework.conversation($0) },
                                  selection: $conversationSelection)
                    .frame(minHeight: 120)
            }
        }
        .padding()
    }
}
