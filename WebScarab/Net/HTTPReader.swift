// WebScarab (Swift) - reading HTTP messages from a byte stream
// (Message.read, ChunkedInputStream, FixedLengthInputStream).

import Foundation

public enum HTTPError: Error, CustomStringConvertible {
    case malformed(String)
    case closed
    case timeout
    case tooLarge

    public var description: String {
        switch self {
        case .malformed(let what): return "Malformed HTTP message: \(what)"
        case .closed: return "Connection closed"
        case .timeout: return "Timed out"
        case .tooLarge: return "Message too large"
        }
    }
}

/// Buffers reads from an async source of byte chunks (nil = end of stream).
public final class ByteReader: @unchecked Sendable {
    private var buffer = Data()
    private var finished = false
    private let source: () async throws -> Data?
    public static let maxLine = 256 * 1024

    public init(source: @escaping () async throws -> Data?) { self.source = source }

    /// A reader over bytes already in memory.
    public convenience init(data: Data) {
        var pending: Data? = data
        self.init(source: {
            defer { pending = nil }
            return pending
        })
    }

    private func fill() async throws -> Bool {
        if finished { return false }
        guard let chunk = try await source(), !chunk.isEmpty else {
            finished = true
            return false
        }
        buffer.append(chunk)
        return true
    }

    /// One line without its CR LF, or nil at end of stream with nothing buffered.
    public func readLine() async throws -> String? {
        while true {
            if let newline = buffer.firstIndex(of: 10) {
                var line = buffer[buffer.startIndex..<newline]
                if line.last == 13 { line = line.dropLast() }
                buffer = Data(buffer[buffer.index(after: newline)...])
                return String(decoding: line, as: UTF8.self)
            }
            if buffer.count > Self.maxLine { throw HTTPError.tooLarge }
            if try await !fill() {
                if buffer.isEmpty { return nil }
                let line = String(decoding: buffer, as: UTF8.self)
                buffer = Data()
                return line
            }
        }
    }

    public func read(exactly count: Int) async throws -> Data {
        while buffer.count < count {
            if try await !fill() { throw HTTPError.closed }
        }
        let result = Data(buffer.prefix(count))
        buffer = Data(buffer.dropFirst(count))
        return result
    }

    public func readToEnd(limit: Int = 512 * 1024 * 1024) async throws -> Data {
        while try await fill() {
            if buffer.count > limit { throw HTTPError.tooLarge }
        }
        let result = buffer
        buffer = Data()
        return result
    }

    /// Bytes already received but not consumed (handed over when a connection becomes a tunnel).
    public func takeBuffered() -> Data {
        let result = buffer
        buffer = Data()
        return result
    }
}

public enum HTTPReader {
    static func readHeaders(_ reader: ByteReader) async throws -> [Header] {
        var headers: [Header] = []
        while let line = try await reader.readLine() {
            if line.isEmpty { return headers }
            if (line.hasPrefix(" ") || line.hasPrefix("\t")), !headers.isEmpty {
                headers[headers.count - 1].value += " " + line.trimmingCharacters(in: .whitespaces)
                continue
            }
            guard let colon = line.firstIndex(of: ":") else { throw HTTPError.malformed("header line '\(line)'") }
            let name = String(line[..<colon])
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            headers.append(Header(name, value))
            if headers.count > 500 { throw HTTPError.tooLarge }
        }
        return headers
    }

    /// Reads a request. `base` is the scheme://host:port the connection belongs to
    /// (for a CONNECT tunnel or a reverse proxy); otherwise the request line or Host header gives it.
    public static func readRequest(_ reader: ByteReader, base: URL?) async throws -> HTTPRequest? {
        var line: String?
        repeat { line = try await reader.readLine() } while line == ""
        guard let requestLine = line else { return nil }
        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard parts.count >= 2 else { throw HTTPError.malformed("request line '\(requestLine)'") }
        let method = parts[0]
        let target = parts[1]
        let version = parts.count >= 3 ? parts[2] : "HTTP/1.0"
        let headers = try await readHeaders(reader)
        var request = HTTPRequest(method: method, url: URL(string: "http://localhost/")!, version: version, headers: headers)
        guard let url = resolve(target: target, method: method, base: base, host: request.header("Host")) else {
            throw HTTPError.malformed("request target '\(target)'")
        }
        request.url = url
        request.body = try await readBody(reader, message: request, isResponseTo: nil, status: 0)
        return request
    }

    static func resolve(target: String, method: String, base: URL?, host: String?) -> URL? {
        if method == "CONNECT" { return URL(string: "https://\(target)") }
        if target.lowercased().hasPrefix("http://") || target.lowercased().hasPrefix("https://") {
            return URL(string: target) ?? URL(string: target.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? target)
        }
        var root: String
        if let base {
            root = "\(base.scheme ?? "https")://\(base.host(percentEncoded: false) ?? "")"
            if let port = base.port, port != (base.scheme == "https" ? 443 : 80) { root += ":\(port)" }
        } else if let host {
            root = "http://\(host)"
        } else {
            return nil
        }
        let path = target.hasPrefix("/") ? target : "/" + target
        return URL(string: root + path) ?? URL(string: root + (path.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? path))
    }

    /// Reads a response, skipping interim 1xx responses.
    public static func readResponse(_ reader: ByteReader, requestMethod: String) async throws -> HTTPResponse {
        while true {
            guard let statusLine = try await reader.readLine() else { throw HTTPError.closed }
            if statusLine.isEmpty { continue }
            let parts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
            guard parts.count >= 2, parts[0].uppercased().hasPrefix("HTTP/") else { throw HTTPError.malformed("status line '\(statusLine)'") }
            var response = HTTPResponse(version: parts[0], status: parts[1], message: parts.count > 2 ? parts[2] : "")
            response.headers = try await readHeaders(reader)
            let code = response.statusCode
            if code >= 100 && code < 200 && code != 101 { continue }
            response.body = try await readBody(reader, message: response, isResponseTo: requestMethod, status: code)
            return response
        }
    }

    static func readBody<M: HTTPMessage>(_ reader: ByteReader, message: M, isResponseTo method: String?, status: Int) async throws -> Data {
        if let method {
            if method == "HEAD" || method == "CONNECT" || status == 204 || status == 304 || (status >= 100 && status < 200) { return Data() }
        }
        if let encoding = message.header("Transfer-Encoding"), encoding.lowercased().contains("chunked") {
            return try await readChunked(reader)
        }
        if let lengthText = message.header("Content-Length"), let length = Int(lengthText.trimmingCharacters(in: .whitespaces)) {
            return try await reader.read(exactly: max(0, length))
        }
        // Requests without a length have no body; responses run to the end of the connection.
        return method == nil ? Data() : try await reader.readToEnd()
    }

    static func readChunked(_ reader: ByteReader) async throws -> Data {
        var body = Data()
        while true {
            guard let sizeLine = try await reader.readLine() else { throw HTTPError.closed }
            let sizeText = sizeLine.split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
            if sizeText.isEmpty { continue }
            guard let size = Int(sizeText, radix: 16) else { throw HTTPError.malformed("chunk size '\(sizeLine)'") }
            if size == 0 {
                while let trailer = try await reader.readLine(), !trailer.isEmpty {}
                return body
            }
            body.append(try await reader.read(exactly: size))
            _ = try await reader.readLine()
        }
    }

    /// After a chunked or open-ended body was read whole, describe it with Content-Length
    /// so it can be stored and forwarded as one piece.
    public static func normalizeLength<M: HTTPMessage>(_ message: inout M, wasRead: Bool = true) {
        if let encoding = message.header("Transfer-Encoding"), encoding.lowercased().contains("chunked") {
            message.removeHeader("Transfer-Encoding")
            message.setHeader("Content-Length", String(message.body.count))
        } else if message.header("Content-Length") == nil, !message.body.isEmpty {
            message.setHeader("Content-Length", String(message.body.count))
        }
    }
}

/// Parsing messages from text (edited in the app) or from saved files.
public enum HTTPParser {
    public static func request(from data: Data, base: URL? = nil) async throws -> HTTPRequest {
        guard let request = try await HTTPReader.readRequest(ByteReader(data: data), base: base) else { throw HTTPError.malformed("empty request") }
        return request
    }

    public static func response(from data: Data, method: String = "GET") async throws -> HTTPResponse {
        try await HTTPReader.readResponse(ByteReader(data: data), requestMethod: method)
    }

    /// Parses edited request text synchronously. Bodies are taken as typed;
    /// Content-Length is kept in step with them.
    public static func request(fromText text: String, base: URL? = nil) throws -> HTTPRequest {
        let (head, body) = HTTPMessageCoding.headerAndBody(from: text)
        guard let first = head.first else { throw HTTPError.malformed("empty request") }
        let parts = first.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard parts.count >= 2 else { throw HTTPError.malformed("request line '\(first)'") }
        let headers = try parseHeaderLines(Array(head.dropFirst()))
        var request = HTTPRequest(method: parts[0], url: URL(string: "http://localhost/")!, version: parts.count > 2 ? parts[2] : "HTTP/1.1", headers: headers, body: body)
        guard let url = HTTPReader.resolve(target: parts[1], method: parts[0], base: base, host: request.header("Host")) else {
            throw HTTPError.malformed("request target '\(parts[1])'")
        }
        request.url = url
        fixLength(&request)
        return request
    }

    public static func response(fromText text: String) throws -> HTTPResponse {
        let (head, body) = HTTPMessageCoding.headerAndBody(from: text)
        guard let first = head.first else { throw HTTPError.malformed("empty response") }
        let parts = first.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 2 else { throw HTTPError.malformed("status line '\(first)'") }
        var response = HTTPResponse(version: parts[0], status: parts[1], message: parts.count > 2 ? parts[2] : "",
                                    headers: try parseHeaderLines(Array(head.dropFirst())), body: body)
        if response.header("Transfer-Encoding")?.lowercased().contains("chunked") == true { response.removeHeader("Transfer-Encoding") }
        fixLength(&response)
        return response
    }

    static func parseHeaderLines(_ lines: [String]) throws -> [Header] {
        try lines.map { line in
            guard let colon = line.firstIndex(of: ":") else { throw HTTPError.malformed("header line '\(line)'") }
            return Header(String(line[..<colon]), String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces))
        }
    }

    static func fixLength<M: HTTPMessage>(_ message: inout M) {
        if message.header("Content-Length") != nil || !message.body.isEmpty {
            message.setHeader("Content-Length", String(message.body.count))
        }
    }
}
