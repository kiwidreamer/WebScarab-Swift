// WebScarab (Swift) - analysis plugins: Search, Compare, Fragments, XSS/CRLF and Extensions.

import Foundation

// MARK: - Search (plugin.search)

public struct SearchDefinition: Identifiable, Hashable, Codable {
    public enum Scope: String, Codable, CaseIterable, Identifiable {
        case body = "Response body", request = "Whole request", response = "Whole response", parameter = "Request parameters", url = "URL"
        public var id: String { rawValue }
    }
    public var id = UUID()
    public var name: String
    public var scope: Scope
    public var pattern: String
    public var isRegex = false
    public var caseSensitive = false

    func matches(_ conversation: Conversation) -> Bool {
        guard !pattern.isEmpty else { return false }
        let haystacks: [String]
        switch scope {
        case .body: haystacks = [conversation.response.bodyText]
        case .request: haystacks = [conversation.request.rawText]
        case .response: haystacks = [conversation.response.headerText + conversation.response.bodyText]
        case .parameter: haystacks = conversation.request.parameters.flatMap { [$0.name, $0.value] }
        case .url: haystacks = [conversation.url.absoluteString]
        }
        return haystacks.contains { text in
            if isRegex { return text.contains(regex: pattern, caseSensitive: caseSensitive) }
            return caseSensitive ? text.contains(pattern) : text.range(of: pattern, options: .caseInsensitive) != nil
        }
    }
}

@MainActor
public final class Search: ObservableObject {
    @Published public var searches: [SearchDefinition] { didSet { Settings.set("Search.definitions", searches) } }
    @Published public private(set) var matches: [UUID: Set<Int>] = [:]
    @Published public var selected: UUID?

    init(framework: Framework) {
        searches = Settings.value("Search.definitions", default: [
            SearchDefinition(name: "Body search", scope: .body, pattern: "password"),
            SearchDefinition(name: "Request search", scope: .request, pattern: "Authorization"),
            SearchDefinition(name: "Response search", scope: .response, pattern: "Set-Cookie"),
            SearchDefinition(name: "Request parameter search", scope: .parameter, pattern: "id"),
        ])
        framework.addAnalyser("Search") { [weak self] conversation in
            guard let self else { return }
            for search in self.searches where search.matches(conversation) { self.matches[search.id, default: []].insert(conversation.id) }
        }
    }

    public func run(_ id: UUID) {
        guard let search = searches.first(where: { $0.id == id }) else { return }
        matches[id] = Set(Framework.shared.conversations.filter { search.matches($0) }.map(\.id))
    }

    public func add(_ search: SearchDefinition) {
        searches.append(search)
        run(search.id)
        selected = search.id
    }

    public func remove(_ id: UUID) {
        searches.removeAll { $0.id == id }
        matches[id] = nil
        if selected == id { selected = nil }
    }
}

// MARK: - Compare (plugin.compare)

@MainActor
public final class Compare: ObservableObject {
    @Published public var baseID: Int?
    @Published public private(set) var distances: [Int: Int] = [:]
    @Published public private(set) var busy = false

    /// Distances from the base conversation's response to every response for the same URL (ignoring the query).
    public func compare(base id: Int) {
        guard let base = Framework.shared.conversation(id) else { return }
        baseID = id
        busy = true
        let baseURL = base.url.shpp
        let candidates = Framework.shared.conversations.filter { $0.url.shpp == baseURL }
        let baseline = LevenshteinDistance.tokenize(base.response.decodedBody)
        let items = candidates.map { ($0.id, LevenshteinDistance.tokenize($0.response.decodedBody)) }
        Task.detached(priority: .userInitiated) {
            var result: [Int: Int] = [:]
            for (cid, tokens) in items { result[cid] = cid == id ? 0 : LevenshteinDistance.distance(baseline, tokens) }
            let final = result
            await MainActor.run {
                self.distances = final
                self.busy = false
            }
        }
    }
}

// MARK: - Fragments (plugin.fragments)

@MainActor
public final class Fragments: ObservableObject {
    public static let kinds = ["Comments", "Scripts", "Forms", "Hidden fields", "File upload fields", "DOM-based XSS"]

    /// kind -> fragment -> conversations it was seen in
    @Published public private(set) var fragments: [String: [String: [Int]]] = [:]

    nonisolated static let domPatterns: [NSRegularExpression] = [
        "[^\\s=]+\\s*=\\s*window\\.(?:top\\.)?location",
        "[^\\s=]+\\s*=\\s*document\\.(?:URL|URLUnencoded|location)",
        "\\+\\s*window\\.(?:top\\.)?location",
        "\\+\\s*document\\.(?:URL|URLUnencoded|location)",
    ].map { try! NSRegularExpression(pattern: $0) }
    nonisolated static let falsePositives: [NSRegularExpression] = [
        ".+[!=]+=.*(?:document|window)",
        "escape\\((?:document.|window.).+\\)",
    ].map { try! NSRegularExpression(pattern: $0) }

    init(framework: Framework) {
        framework.addAnalyser("Fragments") { [weak self] conversation in self?.analyse(conversation) }
    }

    func add(_ kind: String, _ fragment: String, _ id: Int) {
        var list = fragments[kind, default: [:]][fragment, default: []]
        if !list.contains(id) { list.append(id) }
        fragments[kind, default: [:]][fragment] = list
    }

    nonisolated public static func find(in response: HTTPResponse) -> [(String, String)] {
        var found: [(String, String)] = []
        if let html = HTMLScanner.html(of: response) {
            for token in HTMLScanner.tokens(html) {
                switch token {
                case .comment(let text): found.append(("Comments", text))
                case .script(let text): found.append(("Scripts", text))
                case .tag(let name, let attributes, let raw, false):
                    if name == "form" { found.append(("Forms", "action:\(attributes["action"] ?? "null") method:\(attributes["method"] ?? "null")")) }
                    if name == "input" {
                        switch attributes["type"]?.lowercased() {
                        case "hidden": found.append(("Hidden fields", raw))
                        case "file": found.append(("File upload fields", raw))
                        default: break
                        }
                    }
                default: break
                }
            }
        }
        if response.isTextual {
            let content = response.bodyText
            let ns = content as NSString
            for pattern in domPatterns {
                for match in pattern.matches(in: content, range: NSRange(location: 0, length: ns.length)) {
                    let fragment = ns.substring(with: match.range)
                    let fns = fragment as NSString
                    let isFalsePositive = falsePositives.contains { $0.firstMatch(in: fragment, range: NSRange(location: 0, length: fns.length)) != nil }
                    if !isFalsePositive { found.append(("DOM-based XSS", fragment)) }
                }
            }
        }
        return found
    }

    func analyse(_ conversation: Conversation) {
        for (kind, fragment) in Self.find(in: conversation.response) { add(kind, fragment, conversation.id) }
    }
}

// MARK: - XSS/CRLF (plugin.xsscrlf)

public struct SuspiciousParameter: Identifiable, Hashable {
    public var id: String { "\(conversation)|\(location)|\(name)|\(kind)" }
    public var conversation: Int
    public var url: URL
    public var location: String   // GET or POST
    public var name: String
    public var kind: String       // XSS or CRLF
}

@MainActor
public final class XSSCRLF: ObservableObject {
    @Published public var xssTestString = "><script>a=/XSS BUG/; alert(a.source)</script>"
    @Published public var crlfTestString = "%0d%0aWebscarabXSSCRLFTest:%20OK%0d%0a"
    public let crlfInjectedHeader = "WebscarabXSSCRLFTest"
    @Published public private(set) var suspicious: [SuspiciousParameter] = []
    @Published public private(set) var vulnerable: [SuspiciousParameter] = []
    @Published public private(set) var status = "Idle"
    private let fetcher = FetcherQueue(threads: 4, delayMilliseconds: 100)
    static let minimumLength = 3

    init(framework: Framework) {
        framework.addAnalyser("XSS/CRLF") { [weak self] conversation in self?.analyse(conversation) }
    }

    func analyse(_ conversation: Conversation) {
        if conversation.origin == "XSS/CRLF" { return }
        let response = conversation.response
        guard let type = response.contentType?.lowercased(), type.hasPrefix("text/") || type == "application/x-javascript" else { return }
        if response.body.isEmpty && !response.status.hasPrefix("3") { return }
        let body = response.bodyText.uppercased()
        let headers = response.headers.map { ($0.name.uppercased(), $0.value.uppercased()) }
        let request = conversation.request
        if let query = request.url.query(percentEncoded: true), !query.isEmpty {
            check(conversation, NamedValue.split(query, "&", "="), "GET", headers, body)
        }
        if request.method == "POST", request.contentType == "application/x-www-form-urlencoded" {
            check(conversation, NamedValue.split(String(decoding: request.body, as: UTF8.self), "&", "="), "POST", headers, body)
        }
    }

    func check(_ conversation: Conversation, _ parameters: [NamedValue], _ location: String, _ headers: [(String, String)], _ body: String) {
        for parameter in parameters {
            let value = parameter.value.uppercased()
            guard value.count >= Self.minimumLength else { continue }
            let decoded = Encoding.urlDecode(value)
            if headers.contains(where: { $0.1.contains(decoded) || $0.0.contains(decoded) }) {
                mark(SuspiciousParameter(conversation: conversation.id, url: conversation.url, location: location, name: parameter.name, kind: "CRLF"))
            }
            if body.contains(value) {
                mark(SuspiciousParameter(conversation: conversation.id, url: conversation.url, location: location, name: parameter.name, kind: "XSS"))
            }
        }
    }

    func mark(_ item: SuspiciousParameter) {
        if !suspicious.contains(item) { suspicious.append(item) }
    }

    /// Sends the test strings in each suspicious query parameter of these conversations.
    public func check(conversations ids: Set<Int>) {
        let targets = suspicious.filter { ids.contains($0.conversation) && $0.location == "GET" }
        guard !targets.isEmpty else { status = "Nothing to test in the selection (only GET parameters can be tested)"; return }
        status = "Testing \(targets.count) parameters"
        var remaining = targets.count
        for item in targets {
            guard let original = Framework.shared.conversation(item.conversation)?.request else { continue }
            let value = item.kind == "XSS" ? Encoding.urlEncode(xssTestString) : crlfTestString
            guard let request = Self.request(original, replacing: item.name, with: value) else { continue }
            Task {
                let result = await fetcher.fetch(request)
                remaining -= 1
                if remaining == 0 { status = "Finished" }
                guard case .success(var response) = result else { return }
                HTTPReader.normalizeLength(&response)
                let body = response.bodyText
                let xss = item.kind == "XSS" && body.contains(xssTestString)
                let crlf = item.kind == "CRLF" && response.header(crlfInjectedHeader) != nil
                if xss || crlf, let id = Framework.shared.addConversation(request: request, response: response, origin: "XSS/CRLF") {
                    var found = item
                    found.conversation = id
                    found.url = request.url
                    vulnerable.append(found)
                    Framework.shared.log(.info, "XSS/CRLF", "\(item.kind) - Possibly vulnerable: \(request.url.absoluteString)")
                }
            }
        }
    }

    static func request(_ original: HTTPRequest, replacing name: String, with value: String) -> HTTPRequest? {
        guard let query = original.url.query(percentEncoded: true) else { return nil }
        let parameters = NamedValue.split(query, "&", "=").map { $0.name == name ? "\($0.name)=\(value)" : "\($0.name)=\($0.value)" }
        guard let url = URL(string: original.url.shpp + "?" + parameters.joined(separator: "&")) else { return nil }
        var request = original
        request.url = url
        return request
    }
}

// MARK: - Extensions (plugin.extensions)

@MainActor
public final class Extensions: ObservableObject {
    @Published public var fileExtensions = ".bak, ~, .old, .rej, .orig, .inc"
    @Published public var directoryExtensions = ".zip, .arj, .tar, .tar.gz, .tar.bz2, .tgz, .exe, .rar, .tbz"
    @Published public private(set) var found: [Int] = []
    @Published public private(set) var tested: Set<String> = []
    @Published public private(set) var status = "Idle"
    private let fetcher = FetcherQueue(threads: 4)

    func list(_ text: String) -> [String] { text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }

    /// Try each extension on the files and directories at or under these URLs.
    public func check(urls: [URL]) {
        var candidates: [URL] = []
        for url in urls {
            let base = url.shpp
            if base.hasSuffix("/") {
                let trimmed = String(base.dropLast())
                guard !trimmed.hasSuffix(":\(url.effectivePort)") else { continue } // site root has no name to extend
                candidates += list(directoryExtensions).compactMap { URL(string: trimmed + $0) }
            } else {
                candidates += list(fileExtensions).compactMap { URL(string: base + $0) }
            }
        }
        candidates = candidates.filter { !tested.contains($0.absoluteString) }
        guard !candidates.isEmpty else { status = "Nothing new to test"; return }
        status = "Testing \(candidates.count) URLs"
        var remaining = candidates.count
        for url in candidates {
            tested.insert(url.absoluteString)
            var request = HTTPRequest(method: "GET", url: url, version: "HTTP/1.1")
            request.setHeader("Host", url.port.map { "\(url.host(percentEncoded: false) ?? ""):\($0)" } ?? (url.host(percentEncoded: false) ?? ""))
            request.setHeader("Connection", "close")
            Task {
                let result = await fetcher.fetch(request)
                remaining -= 1
                if remaining == 0 { status = "Finished" }
                if case .success(let response) = result, response.statusCode == 200,
                   let id = Framework.shared.addConversation(request: request, response: response, origin: "Extensions") {
                    found.append(id)
                }
            }
        }
    }
}
