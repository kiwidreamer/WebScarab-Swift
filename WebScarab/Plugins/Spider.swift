// WebScarab (Swift) - plugin.spider: finds links in what was seen and fetches the ones not yet seen.

import Foundation

public struct SpiderLink: Identifiable, Hashable {
    public var id: String { url.absoluteString }
    public var url: URL
    public var referer: String?
}

@MainActor
public final class Spider: ObservableObject {
    @Published public var allowedDomains: String { didSet { UserDefaults.standard.set(allowedDomains, forKey: "Spider.domains") } }
    @Published public var forbiddenPaths: String { didSet { UserDefaults.standard.set(forbiddenPaths, forKey: "Spider.excludePaths") } }
    @Published public var cookieSync = true
    @Published public var extraHeaders = ""
    @Published public private(set) var unseen: [String: SpiderLink] = [:]
    @Published public private(set) var queued = 0
    @Published public private(set) var status = "Idle"
    @Published public private(set) var authRequired: [URL] = []
    private let fetcher = FetcherQueue(threads: 4)
    private var stopRequested = false

    init(framework: Framework) {
        allowedDomains = UserDefaults.standard.string(forKey: "Spider.domains") ?? ".*"
        forbiddenPaths = UserDefaults.standard.string(forKey: "Spider.excludePaths") ?? ""
        framework.addAnalyser("Spider") { [weak self] conversation in self?.analyse(conversation) }
    }

    public var unseenLinks: [SpiderLink] { unseen.values.sorted { $0.id < $1.id } }

    func isAllowed(_ url: URL) -> Bool {
        let host = url.host(percentEncoded: false) ?? ""
        guard !allowedDomains.isEmpty, host.matches(regex: allowedDomains) else { return false }
        if !forbiddenPaths.isEmpty, url.absoluteString.matches(regex: forbiddenPaths) { return false }
        if Framework.shared.shouldDrop(url) { return false }
        return true
    }

    func analyse(_ conversation: Conversation) {
        unseen[SiteNode.key(for: conversation.url)] = nil
        let base = conversation.url
        if conversation.response.status.hasPrefix("3"), let location = conversation.response.header("Location") {
            addLink(location, base: base)
            return
        }
        guard let html = HTMLScanner.html(of: conversation.response) else { return }
        var baseURL = base
        for token in HTMLScanner.tokens(html) {
            guard case .tag(let name, let attributes, _, false) = token else { continue }
            if name == "base", let href = attributes["href"], let url = URL(string: href, relativeTo: base) { baseURL = url.absoluteURL }
            for attribute in ["href", "src", "action"] {
                if let link = attributes[attribute] { addLink(link, base: baseURL) }
            }
            for attribute in ["onclick", "onblur"] {
                if let script = attributes[attribute] { processScript(script, base: baseURL) }
            }
        }
    }

    func processScript(_ script: String, base: URL) {
        // location.href='...' / window.open("...") style links
        let pattern = "(?:location(?:\\.href)?\\s*=|open\\s*\\()\\s*['\"]([^'\"]+)['\"]"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return }
        let ns = script as NSString
        for match in regex.matches(in: script, range: NSRange(location: 0, length: ns.length)) {
            addLink(ns.substring(with: match.range(at: 1)), base: base)
        }
    }

    func addLink(_ link: String, base: URL) {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()
        if trimmed.isEmpty || trimmed.hasPrefix("#") || lower.hasPrefix("mailto:") || lower.hasPrefix("data:") { return }
        if lower.hasPrefix("javascript:") { processScript(String(trimmed.dropFirst(11)), base: base); return }
        if trimmed.range(of: "^[a-zA-Z][a-zA-Z0-9+.-]*:", options: .regularExpression) != nil && !lower.hasPrefix("http:") && !lower.hasPrefix("https:") { return }
        guard var components = URLComponents(url: URL(string: trimmed, relativeTo: base)?.absoluteURL ?? base, resolvingAgainstBaseURL: true) else { return }
        components.fragment = nil
        guard let url = components.url, let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else { return }
        let key = SiteNode.key(for: url)
        if unseen[key] != nil || Framework.shared.hasSeen(url) || !isAllowed(url) { return }
        unseen[key] = SpiderLink(url: url, referer: base.absoluteString)
    }

    /// Fetch the unseen links at or under these tree nodes (or all of them).
    public func fetch(under keys: [String]? = nil) {
        let links = unseenLinks.filter { link in
            guard let keys, !keys.isEmpty else { return true }
            let key = SiteNode.key(for: link.url)
            return keys.contains { $0 == key || (($0.hasSuffix("/") && key.hasPrefix($0))) }
        }
        fetch(links)
    }

    public func fetch(_ links: [SpiderLink]) {
        stopRequested = false
        for link in links {
            unseen[SiteNode.key(for: link.url)] = nil
            var request = HTTPRequest(method: "GET", url: link.url, version: "HTTP/1.0")
            request.setHeader("Host", link.url.port.map { "\(link.url.host(percentEncoded: false) ?? ""):\($0)" } ?? (link.url.host(percentEncoded: false) ?? ""))
            if let referer = link.referer { request.setHeader("Referer", referer) }
            request.setHeader("Connection", "Keep-Alive")
            for line in extraHeaders.split(separator: "\n") {
                if let colon = line.firstIndex(of: ":") {
                    request.addHeader(String(line[..<colon]).trimmingCharacters(in: .whitespaces), String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces))
                }
            }
            if cookieSync {
                let cookies = Framework.shared.cookies(for: link.url)
                if !cookies.isEmpty { request.setHeader("Cookie", cookies.map { "\($0.name)=\($0.value)" }.joined(separator: "; ")) }
            }
            submit(request)
        }
    }

    private func submit(_ request: HTTPRequest) {
        queued += 1
        status = "Fetching (\(queued) queued)"
        Task {
            let result = await fetcher.fetch(request)
            queued -= 1
            status = queued > 0 ? "Fetching (\(queued) queued)" : "Idle"
            guard !stopRequested else { return }
            switch result {
            case .success(let response):
                if response.status.hasPrefix("401") {
                    authRequired.append(request.url)
                    Framework.shared.log(.info, "Spider", "Authentication required for \(request.url.absoluteString)")
                    return
                }
                Framework.shared.addConversation(request: request, response: response, origin: "Spider")
            case .failure(let error):
                Framework.shared.log(.info, "Spider", "Requested \(request.url.absoluteString) got \(error)")
            }
        }
    }

    public func stop() {
        stopRequested = true
        status = "Stopped"
    }

    public func clearQueue() { unseen.removeAll() }
}
