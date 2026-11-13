// WebScarab (Swift) - the shared model of everything seen (model.FrameworkModel + plugin.Framework).

import Foundation
import Combine

/// One node of the site tree: a host, a directory, a file or a query.
public final class SiteNode: Identifiable, Hashable {
    public let id: String          // the URL this node stands for
    public let name: String
    public private(set) var children: [SiteNode] = []
    private var childIndex: [String: SiteNode] = [:]
    public var methods: Set<String> = []
    public var statuses: Set<String> = []
    public var conversationCount = 0

    init(id: String, name: String) {
        self.id = id
        self.name = name
    }

    public var childNodes: [SiteNode]? { children.isEmpty ? nil : children }
    public var methodText: String { methods.sorted().joined(separator: ", ") }
    public var statusText: String { statuses.sorted().joined(separator: ", ") }

    func child(_ key: String, name: String) -> SiteNode {
        if let existing = childIndex[key] { return existing }
        let node = SiteNode(id: key, name: name)
        childIndex[key] = node
        let position = children.firstIndex { $0.name > name } ?? children.count
        children.insert(node, at: position)
        return node
    }

    public static func == (lhs: SiteNode, rhs: SiteNode) -> Bool { lhs.id == rhs.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }

    /// The keys from the site root down to this URL.
    static func chain(for url: URL) -> [(key: String, name: String)] {
        let root = url.siteRoot
        var chain: [(String, String)] = [(root, root)]
        let path = url.path(percentEncoded: true)
        let segments = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().map(String.init)
        var current = root
        for (index, segment) in segments.enumerated() {
            let isLast = index == segments.count - 1
            if isLast && segment.isEmpty { break }
            current += segment + (isLast ? "" : "/")
            chain.append((current, segment + (isLast ? "" : "/")))
        }
        if let query = url.query(percentEncoded: true) {
            chain.append((current + "?" + query, "?" + query))
        }
        return chain
    }

    public static func key(for url: URL) -> String { chain(for: url).last!.key }

    /// Is the conversation at `conversationKey` at or below this node?
    public func covers(_ conversationKey: String) -> Bool {
        conversationKey == id || conversationKey.hasPrefix(id + "?") || (id.hasSuffix("/") && conversationKey.hasPrefix(id))
    }
}

public struct LogEntry: Identifiable, Hashable {
    public enum Level: String { case severe = "SEVERE", warning = "WARNING", info = "INFO", fine = "FINE" }
    public let id = UUID()
    public let date = Date()
    public let level: Level
    public let source: String
    public let message: String
}

@MainActor
public final class Framework: ObservableObject {
    public static let shared = Framework()

    @Published public private(set) var conversations: [Conversation] = []
    @Published public private(set) var treeVersion = 0
    @Published public private(set) var cookieHistory: [String: [Cookie]] = [:]
    @Published public private(set) var log: [LogEntry] = []
    @Published public var dropPattern: String = Settings.dropPattern { didSet { Settings.dropPattern = dropPattern } }
    @Published public var sessionFolder: URL?
    @Published public var modified = false

    public private(set) var roots: [SiteNode] = []
    private var rootIndex: [String: SiteNode] = [:]
    private var nodeIndex: [String: SiteNode] = [:]
    private var byID: [Int: Int] = [:]
    private var nextID = 1

    /// Called with every new conversation (ConversationHandler / Plugin.analyse).
    private var analysers: [(String, (Conversation) -> Void)] = []

    public func addAnalyser(_ name: String, _ analyse: @escaping (Conversation) -> Void) {
        analysers.append((name, analyse))
    }

    public func reserveID() -> Int {
        defer { nextID += 1 }
        return nextID
    }

    public func conversation(_ id: Int) -> Conversation? {
        byID[id].map { conversations[$0] }
    }

    public func shouldDrop(_ url: URL) -> Bool {
        !dropPattern.isEmpty && url.absoluteString.matches(regex: dropPattern)
    }

    @discardableResult
    public func addConversation(request: HTTPRequest, response: HTTPResponse, origin: String, id reserved: Int? = nil, date: Date = Date(), tag: String = "") -> Int? {
        if shouldDrop(request.url) { return nil }
        let id = reserved ?? reserveID()
        if id >= nextID { nextID = id + 1 }
        let conversation = Conversation(id: id, date: date, request: request, response: response, origin: origin, tag: tag)
        let position = conversations.lastIndex(where: { $0.id < id }).map { $0 + 1 } ?? 0
        if position == conversations.count {
            conversations.append(conversation)
            byID[id] = position
        } else {
            conversations.insert(conversation, at: position)
            rebuildIndex()
        }
        addToTree(conversation)
        for header in response.headerValues("Set-Cookie") + response.headerValues("Set-Cookie2") {
            if let cookie = Cookie(date: date, url: request.url, setCookie: header) { addCookie(cookie) }
        }
        modified = true
        for (name, analyse) in analysers {
            analyse(conversation)
            _ = name
        }
        return id
    }

    public func setTag(_ tag: String, for id: Int) {
        guard let index = byID[id] else { return }
        conversations[index].tag = tag
        modified = true
    }

    private func rebuildIndex() {
        byID = Dictionary(uniqueKeysWithValues: conversations.enumerated().map { ($1.id, $0) })
    }

    private func addToTree(_ conversation: Conversation) {
        let chain = SiteNode.chain(for: conversation.url)
        guard let rootEntry = chain.first else { return }
        var node: SiteNode
        if let root = rootIndex[rootEntry.key] {
            node = root
        } else {
            node = SiteNode(id: rootEntry.key, name: rootEntry.name)
            rootIndex[rootEntry.key] = node
            roots.append(node)
            roots.sort { $0.name < $1.name }
        }
        nodeIndex[node.id] = node
        for entry in chain.dropFirst() {
            node = node.child(entry.key, name: entry.name)
            nodeIndex[node.id] = node
        }
        node.methods.insert(conversation.method)
        node.statuses.insert(conversation.status)
        node.conversationCount += 1
        treeVersion += 1
    }

    public func node(_ key: String) -> SiteNode? { nodeIndex[key] }

    /// Every URL WebScarab has a conversation for.
    public func hasSeen(_ url: URL) -> Bool { nodeIndex[SiteNode.key(for: url)]?.conversationCount ?? 0 > 0 }

    public var allNodes: [SiteNode] { Array(nodeIndex.values) }

    // MARK: cookies

    public func addCookie(_ cookie: Cookie) {
        var list = cookieHistory[cookie.key] ?? []
        if list.last?.value == cookie.value && list.last?.attributes == cookie.attributes { return }
        list.append(cookie)
        cookieHistory[cookie.key] = list
        modified = true
    }

    public func removeCookies(key: String) {
        cookieHistory[key] = nil
        modified = true
    }

    /// The latest value of each cookie.
    public var currentCookies: [Cookie] {
        cookieHistory.values.compactMap(\.last).sorted { $0.key < $1.key }
    }

    public func cookies(for url: URL) -> [Cookie] {
        currentCookies.filter { $0.applies(to: url) && $0.attributes["max-age"] != "0" }
    }

    // MARK: log

    public func log(_ level: LogEntry.Level, _ source: String, _ message: String) {
        log.append(LogEntry(level: level, source: source, message: message))
        if log.count > 2000 { log.removeFirst(log.count - 2000) }
    }

    public func clearLog() { log.removeAll() }

    // MARK: sessions

    public func reset() {
        conversations = []
        byID = [:]
        roots = []
        rootIndex = [:]
        nodeIndex = [:]
        cookieHistory = [:]
        nextID = 1
        treeVersion += 1
        sessionFolder = nil
        modified = false
    }

    public func save(to folder: URL) throws {
        try SessionStore.save(conversations: conversations, roots: Array(nodeIndex.values), cookies: cookieHistory, to: folder)
        sessionFolder = folder
        modified = false
        log(.info, "Framework", "Saved \(conversations.count) conversations to \(folder.path)")
    }

    public func open(_ folder: URL) async throws {
        let loaded = try await SessionStore.load(from: folder)
        reset()
        for item in loaded.conversations {
            addConversation(request: item.request, response: item.response, origin: item.origin, id: item.id, date: item.date, tag: item.tag)
        }
        for cookie in loaded.cookies { addCookie(cookie) }
        sessionFolder = folder
        modified = false
        log(.info, "Framework", "Opened \(loaded.conversations.count) conversations from \(folder.path)")
    }
}

/// Lets code off the main thread report to the log.
public func webscarabLog(_ level: LogEntry.Level, _ source: String, _ message: String) {
    Task { @MainActor in Framework.shared.log(level, source, message) }
}
