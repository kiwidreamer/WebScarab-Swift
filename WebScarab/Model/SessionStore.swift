// WebScarab (Swift) - saving and opening sessions in WebScarab's own folder format
// (model.FileSystemStore): conversationlog, urlinfo, cookies and conversations/<id>-request|response.
// Sessions saved by the Java WebScarab open here and the other way round.

import Foundation

public enum SessionStore {
    public struct Loaded {
        public var conversations: [Conversation] = []
        public var cookies: [Cookie] = []
    }

    public static func save(conversations: [Conversation], roots nodes: [SiteNode], cookies: [String: [Cookie]], to folder: URL) throws {
        let manager = FileManager.default
        let conversationsFolder = folder.appendingPathComponent("conversations", isDirectory: true)
        try manager.createDirectory(at: conversationsFolder, withIntermediateDirectories: true)

        var log = ""
        for conversation in conversations {
            try conversation.request.serialized().write(to: conversationsFolder.appendingPathComponent("\(conversation.id)-request"))
            try conversation.response.serialized().write(to: conversationsFolder.appendingPathComponent("\(conversation.id)-response"))
            log += "### Conversation : \(conversation.id)\n"
            log += "METHOD: \(conversation.method)\n"
            log += "URL: \(conversation.url.absoluteString)\n"
            log += "STATUS: \(conversation.status)\n"
            log += "WHEN: \(Int64(conversation.date.timeIntervalSince1970 * 1000))\n"
            log += "ORIGIN: \(conversation.origin)\n"
            if !conversation.tag.isEmpty { log += "TAG: \(conversation.tag)\n" }
            log += "RESPONSE_SIZE: \(conversation.size)\n\n"
        }
        try log.write(to: folder.appendingPathComponent("conversationlog"), atomically: true, encoding: .utf8)

        var urlInfo = ""
        for node in nodes.sorted(by: { $0.id < $1.id }) where !node.methods.isEmpty {
            urlInfo += "### URL : \(node.id)\n"
            for method in node.methods.sorted() { urlInfo += "METHODS: \(method)\n" }
            for status in node.statuses.sorted() { urlInfo += "STATUS: \(status)\n" }
            urlInfo += "\n"
        }
        try urlInfo.write(to: folder.appendingPathComponent("urlinfo"), atomically: true, encoding: .utf8)

        var cookieText = ""
        for (key, list) in cookies.sorted(by: { $0.key < $1.key }) {
            cookieText += "### Cookie : \(key)\n"
            for cookie in list { cookieText += "\(Int64(cookie.date.timeIntervalSince1970 * 1000)) \(cookie.setCookieString)\n" }
            cookieText += "\n"
        }
        try cookieText.write(to: folder.appendingPathComponent("cookies"), atomically: true, encoding: .utf8)
    }

    public static func load(from folder: URL) async throws -> Loaded {
        var loaded = Loaded()
        let logURL = folder.appendingPathComponent("conversationlog")
        guard let text = (try? String(contentsOf: logURL, encoding: .utf8)) ?? (try? String(contentsOf: logURL, encoding: .isoLatin1)) else {
            throw HTTPError.malformed("no conversationlog in \(folder.path)")
        }
        var properties: [(Int, [String: String])] = []
        var currentID: Int?
        var current: [String: String] = [:]
        for line in text.components(separatedBy: "\n") {
            if line.hasPrefix("### Conversation :") {
                if let id = currentID { properties.append((id, current)) }
                currentID = Int(line.dropFirst("### Conversation :".count).trimmingCharacters(in: .whitespaces))
                current = [:]
            } else if line.isEmpty {
                if let id = currentID { properties.append((id, current)) }
                currentID = nil
                current = [:]
            } else if let colon = line.firstIndex(of: ":") {
                let key = String(line[..<colon])
                let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                if current[key] == nil { current[key] = value }
            }
        }
        if let id = currentID { properties.append((id, current)) }

        let conversationsFolder = folder.appendingPathComponent("conversations", isDirectory: true)
        for (id, map) in properties {
            guard let requestData = try? Data(contentsOf: conversationsFolder.appendingPathComponent("\(id)-request")) else { continue }
            let base = map["URL"].flatMap(URL.init(string:))
            guard var request = try? await HTTPParser.request(from: requestData, base: base) else { continue }
            if let base, request.url.host == nil { request.url = base }
            var response = HTTPResponse(status: "000", message: "No response")
            if let responseData = try? Data(contentsOf: conversationsFolder.appendingPathComponent("\(id)-response")),
               let parsed = try? await HTTPParser.response(from: responseData, method: request.method) {
                response = parsed
                HTTPReader.normalizeLength(&response)
            }
            let when = map["WHEN"].flatMap(Double.init).map { Date(timeIntervalSince1970: $0 / 1000) } ?? Date()
            loaded.conversations.append(Conversation(id: id, date: when, request: request, response: response,
                                                     origin: map["ORIGIN"] ?? "Proxy", tag: map["TAG"] ?? ""))
        }
        loaded.conversations.sort { $0.id < $1.id }

        if let cookieText = try? String(contentsOf: folder.appendingPathComponent("cookies"), encoding: .utf8) {
            for line in cookieText.components(separatedBy: "\n") where !line.isEmpty && !line.hasPrefix("###") {
                guard let space = line.firstIndex(of: " "), let millis = Double(line[..<space]) else { continue }
                let setCookie = String(line[line.index(after: space)...])
                if let cookie = Cookie(date: Date(timeIntervalSince1970: millis / 1000), url: nil, setCookie: setCookie) {
                    loaded.cookies.append(cookie)
                }
            }
        }
        return loaded
    }
}
