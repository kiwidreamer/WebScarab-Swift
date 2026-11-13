// WebScarab (Swift) - a recorded request/response pair and the shared cookie jar.

import Foundation

public struct Conversation: Identifiable, Hashable, Sendable {
    public var id: Int
    public var date: Date
    public var request: HTTPRequest
    public var response: HTTPResponse
    public var origin: String
    public var tag: String = ""

    public var method: String { request.method }
    public var host: String { String(request.url.siteRoot.dropLast()) }
    public var path: String {
        let path = request.url.path(percentEncoded: true)
        return path.isEmpty ? "/" : path
    }
    public var parameters: String { request.url.parameterText }
    public var status: String { response.statusLine }
    public var size: Int { response.body.count }
    public var url: URL { request.url }
}

/// model.Cookie - one Set-Cookie value seen at a date.
public struct Cookie: Identifiable, Hashable, Sendable {
    public var id: String { key + "@\(date.timeIntervalSince1970)" }
    public var date: Date
    public var name: String
    public var value: String
    public var domain: String
    public var path: String
    public var attributes: [String: String] = [:]

    /// domain + path + " " + name, as in WebScarab.
    public var key: String { domain + path + " " + name }

    public init(date: Date, name: String, value: String, domain: String, path: String, attributes: [String: String] = [:]) {
        self.date = date
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.attributes = attributes
    }

    /// Parses a Set-Cookie header seen in a response to `url`.
    public init?(date: Date, url: URL?, setCookie: String) {
        let parts = setCookie.split(separator: ";", omittingEmptySubsequences: true).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = parts.first, let equals = first.firstIndex(of: "=") else { return nil }
        self.date = date
        name = String(first[..<equals])
        value = String(first[first.index(after: equals)...])
        var domain = url?.host(percentEncoded: false) ?? ""
        var path = "/"
        if let url {
            let urlPath = url.path(percentEncoded: true)
            if let slash = urlPath.lastIndex(of: "/") { path = String(urlPath[...slash]) }
        }
        var attributes: [String: String] = [:]
        for part in parts.dropFirst() {
            let pieces = part.split(separator: "=", maxSplits: 1).map(String.init)
            let key = pieces[0].lowercased()
            let attributeValue = pieces.count > 1 ? pieces[1] : ""
            switch key {
            case "domain": domain = attributeValue
            case "path": path = attributeValue
            default: attributes[key] = attributeValue
            }
        }
        self.domain = domain
        self.path = path
        self.attributes = attributes
    }

    /// The Set-Cookie form WebScarab writes in its "cookies" file.
    public var setCookieString: String {
        var text = "\(name)=\(value); domain=\(domain); path=\(path)"
        for (key, attributeValue) in attributes.sorted(by: { $0.key < $1.key }) {
            text += attributeValue.isEmpty ? "; \(key)" : "; \(key)=\(attributeValue)"
        }
        return text
    }

    public func applies(to url: URL) -> Bool {
        let host = (url.host(percentEncoded: false) ?? "").lowercased()
        let cookieDomain = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard host == cookieDomain || host.hasSuffix("." + cookieDomain) else { return false }
        let urlPath = url.path(percentEncoded: true).isEmpty ? "/" : url.path(percentEncoded: true)
        guard urlPath.hasPrefix(path) else { return false }
        if attributes["secure"] != nil && url.scheme?.lowercased() != "https" { return false }
        return true
    }
}
