// WebScarab (Swift) - HTTP request and response messages.
// Mirrors org.owasp.webscarab.model.Message / Request / Response.

import Foundation
import Compression

public struct Header: Hashable, Codable, Sendable, Identifiable {
    public var id: String { name + "\u{0}" + value }
    public var name: String
    public var value: String
    public init(_ name: String, _ value: String) {
        self.name = name
        self.value = value
    }
}

public protocol HTTPMessage: Sendable {
    var version: String { get set }
    var headers: [Header] { get set }
    var body: Data { get set }
    var startLine: String { get }
}

public extension HTTPMessage {
    func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    func headerValues(_ name: String) -> [String] {
        headers.filter { $0.name.caseInsensitiveCompare(name) == .orderedSame }.map(\.value)
    }

    /// Replaces the first header with this name (removing any others), or appends it.
    mutating func setHeader(_ name: String, _ value: String) {
        if let index = headers.firstIndex(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
            headers[index].value = value
            var seen = false
            headers.removeAll { header in
                guard header.name.caseInsensitiveCompare(name) == .orderedSame else { return false }
                if !seen { seen = true; return false }
                return true
            }
        } else {
            headers.append(Header(name, value))
        }
    }

    mutating func addHeader(_ name: String, _ value: String) {
        headers.append(Header(name, value))
    }

    mutating func removeHeader(_ name: String) {
        headers.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
    }

    var contentType: String? { header("Content-Type") }

    var isTextual: Bool {
        guard let type = contentType?.lowercased() else {
            return HTTPMessageCoding.looksLikeText(decodedBody)
        }
        return type.hasPrefix("text/") || type.contains("json") || type.contains("xml")
            || type.contains("javascript") || type.contains("x-www-form-urlencoded")
    }

    /// The body with any gzip/deflate Content-Encoding removed, for display and analysis.
    var decodedBody: Data {
        guard let encoding = header("Content-Encoding")?.lowercased() else { return body }
        if encoding.contains("gzip"), let data = HTTPMessageCoding.gunzip(body) { return data }
        if encoding.contains("deflate"), let data = HTTPMessageCoding.inflate(body, zlibWrapped: true) { return data }
        return body
    }

    var bodyText: String { HTTPMessageCoding.string(from: decodedBody, contentType: contentType) }

    /// Header block (start line + headers + blank line) as text.
    var headerText: String {
        var text = startLine + "\r\n"
        for header in headers { text += "\(header.name): \(header.value)\r\n" }
        return text + "\r\n"
    }

    /// The message as text, for raw views and editing.
    var rawText: String {
        headerText.replacingOccurrences(of: "\r\n", with: "\n") + HTTPMessageCoding.string(from: body, contentType: contentType)
    }

    /// Wire bytes.
    func serialized() -> Data {
        var data = Data(headerText.utf8)
        data.append(body)
        return data
    }
}

public struct HTTPRequest: HTTPMessage, Hashable {
    public var method: String
    public var url: URL
    public var version: String
    public var headers: [Header]
    public var body: Data

    public init(method: String = "GET", url: URL, version: String = "HTTP/1.1", headers: [Header] = [], body: Data = Data()) {
        self.method = method
        self.url = url
        self.version = version
        self.headers = headers
        self.body = body
    }

    /// Start line with the absolute URL, as WebScarab stores requests.
    public var startLine: String { "\(method) \(url.absoluteString) \(version)" }

    /// Path and query, as sent to the origin server.
    public var directTarget: String {
        if method == "CONNECT" { return "\(url.host ?? ""):\(url.effectivePort)" }
        return url.pathAndQuery
    }

    /// Wire bytes for the origin server (origin-form request target).
    public func serializedDirect() -> Data {
        var text = "\(method) \(directTarget) \(version)\r\n"
        for header in headers { text += "\(header.name): \(header.value)\r\n" }
        text += "\r\n"
        var data = Data(text.utf8)
        data.append(body)
        return data
    }

    /// Query and form-body parameters, decoded.
    public var parameters: [(location: String, name: String, value: String)] {
        var result: [(String, String, String)] = []
        if let query = url.query(percentEncoded: true), !query.isEmpty {
            for pair in NamedValue.split(query, "&", "=") { result.append(("Query", pair.name, Encoding.urlDecode(pair.value))) }
        }
        if method == "POST", (contentType ?? "").lowercased().hasPrefix("application/x-www-form-urlencoded") {
            let text = String(decoding: body, as: UTF8.self)
            for pair in NamedValue.split(text, "&", "=") { result.append(("Body", pair.name, Encoding.urlDecode(pair.value))) }
        }
        for cookie in headerValues("Cookie") {
            for pair in NamedValue.split(cookie, ";", "=") { result.append(("Cookie", pair.name, pair.value)) }
        }
        return result
    }
}

public struct HTTPResponse: HTTPMessage, Hashable {
    public var version: String
    public var status: String
    public var message: String
    public var headers: [Header]
    public var body: Data

    public init(version: String = "HTTP/1.1", status: String = "200", message: String = "OK", headers: [Header] = [], body: Data = Data()) {
        self.version = version
        self.status = status
        self.message = message
        self.headers = headers
        self.body = body
    }

    public var startLine: String { "\(version) \(status) \(message)" }
    public var statusLine: String { "\(status) \(message)" }
    public var statusCode: Int { Int(status) ?? 0 }

    public static func error(for request: HTTPRequest, _ error: Error) -> HTTPResponse {
        let html = """
        <HTML><HEAD><TITLE>WebScarab Error</TITLE></HEAD><BODY>WebScarab encountered an error trying to retrieve <P><pre>\
        \(HtmlEncoder.encode(request.rawText))</pre><P>The error was : <P><pre>\(HtmlEncoder.encode(String(describing: error)))</pre></BODY></HTML>
        """
        var response = HTTPResponse(version: "HTTP/1.0", status: "500", message: "WebScarab error")
        response.setHeader("Content-Type", "text/html")
        response.setHeader("Connection", "Close")
        response.body = Data(html.utf8)
        response.setHeader("Content-Length", String(response.body.count))
        return response
    }
}

public enum HTTPMessageCoding {
    public static func string(from data: Data, contentType: String?) -> String {
        if let charset = contentType.flatMap(charset(of:)),
           let encoding = stringEncoding(charset), let text = String(data: data, encoding: encoding) {
            return text
        }
        if let text = String(data: data, encoding: .utf8) { return text }
        return String(data: data, encoding: .isoLatin1) ?? ""
    }

    static func charset(of contentType: String) -> String? {
        for part in contentType.split(separator: ";") {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("charset=") {
                return String(trimmed.dropFirst(8)).trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
            }
        }
        return nil
    }

    static func stringEncoding(_ charset: String) -> String.Encoding? {
        let cf = CFStringConvertIANACharSetNameToEncoding(charset as CFString)
        guard cf != kCFStringEncodingInvalidId else { return nil }
        return String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(cf))
    }

    public static func looksLikeText(_ data: Data) -> Bool {
        let sample = data.prefix(1024)
        if sample.isEmpty { return true }
        let printable = sample.filter { $0 == 9 || $0 == 10 || $0 == 13 || ($0 >= 32 && $0 != 127) }.count
        return Double(printable) / Double(sample.count) > 0.95
    }

    /// Re-encodes an edited message text into wire form: newlines become CRLF in the
    /// header block, and Content-Length follows the new body when it was present.
    public static func headerAndBody(from text: String) -> (head: [String], body: Data) {
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
        var lines: [String] = []
        var rest = Substring(normalized)
        while let newline = rest.firstIndex(of: "\n") {
            let line = rest[rest.startIndex..<newline]
            rest = rest[rest.index(after: newline)...]
            if line.isEmpty { return (lines, Data(rest.utf8)) }
            lines.append(String(line))
        }
        if !rest.isEmpty { lines.append(String(rest)) }
        return (lines, Data())
    }

    public static func gunzip(_ data: Data) -> Data? {
        let bytes = [UInt8](data)
        guard bytes.count > 18, bytes[0] == 0x1f, bytes[1] == 0x8b, bytes[2] == 8 else { return nil }
        let flags = bytes[3]
        var index = 10
        if flags & 0x04 != 0 { // FEXTRA
            guard index + 2 <= bytes.count else { return nil }
            index += 2 + Int(bytes[index]) + Int(bytes[index + 1]) << 8
        }
        if flags & 0x08 != 0 { while index < bytes.count && bytes[index] != 0 { index += 1 }; index += 1 } // FNAME
        if flags & 0x10 != 0 { while index < bytes.count && bytes[index] != 0 { index += 1 }; index += 1 } // FCOMMENT
        if flags & 0x02 != 0 { index += 2 } // FHCRC
        guard index < bytes.count else { return nil }
        return inflate(Data(bytes[index...]), zlibWrapped: false)
    }

    public static func inflate(_ data: Data, zlibWrapped: Bool) -> Data? {
        var input = data
        if zlibWrapped, input.count > 2, let first = input.first, first & 0x0f == 8 {
            input = input.dropFirst(2)
        }
        guard !input.isEmpty else { return Data() }
        let source = [UInt8](input)
        var output = Data()
        let chunk = 64 * 1024
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }
        guard compression_stream_init(stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(stream) }
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
        defer { buffer.deallocate() }
        return source.withUnsafeBufferPointer { src -> Data? in
            stream.pointee.src_ptr = src.baseAddress!
            stream.pointee.src_size = src.count
            while true {
                stream.pointee.dst_ptr = buffer
                stream.pointee.dst_size = chunk
                let status = compression_stream_process(stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                output.append(buffer, count: chunk - stream.pointee.dst_size)
                switch status {
                case COMPRESSION_STATUS_END: return output
                case COMPRESSION_STATUS_OK: if output.count > 256 * 1024 * 1024 { return nil }
                default: return output.isEmpty ? nil : output
                }
            }
        }
    }
}

public extension URL {
    var effectivePort: Int {
        if let port { return port }
        return scheme?.lowercased() == "https" ? 443 : 80
    }

    var pathAndQuery: String {
        var path = self.path(percentEncoded: true)
        if path.isEmpty { path = "/" }
        if let query = self.query(percentEncoded: true) { path += "?" + query }
        return path
    }

    /// scheme://host:port/ - WebScarab's site root key.
    var siteRoot: String {
        "\(scheme?.lowercased() ?? "http")://\(host(percentEncoded: false) ?? ""):\(effectivePort)/"
    }

    /// scheme://host:port/path (no query), WebScarab's "SHPP".
    var shpp: String {
        var path = self.path(percentEncoded: true)
        if path.isEmpty { path = "/" }
        return String(siteRoot.dropLast()) + path
    }

    /// Path parameters (;x) and query, shown in the "Parameters" column.
    var parameterText: String {
        var text = ""
        if let query = self.query(percentEncoded: true) { text += "?" + query }
        return text
    }
}
