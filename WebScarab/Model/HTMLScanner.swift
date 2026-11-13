// WebScarab (Swift) - a forgiving HTML scanner, standing in for the HTMLParser library
// that WebScarab's parser.HTMLParser used. It finds tags with their attributes,
// comments and whole <script> elements.

import Foundation

public enum HTMLToken: Hashable {
    case tag(name: String, attributes: [String: String], raw: String, isEnd: Bool)
    case comment(String)
    case script(String)
}

public enum HTMLScanner {
    public static func tokens(_ html: String) -> [HTMLToken] {
        let bytes = Array(html.utf8)
        var tokens: [HTMLToken] = []
        var i = 0
        let count = bytes.count

        func text(_ from: Int, _ to: Int) -> String { String(decoding: bytes[from..<min(to, count)], as: UTF8.self) }
        func find(_ needle: [UInt8], from start: Int, caseInsensitive: Bool = false) -> Int? {
            guard needle.count <= count else { return nil }
            var j = start
            while j + needle.count <= count {
                var matched = true
                for k in 0..<needle.count {
                    var a = bytes[j + k], b = needle[k]
                    if caseInsensitive { if a >= 65 && a <= 90 { a += 32 }; if b >= 65 && b <= 90 { b += 32 } }
                    if a != b { matched = false; break }
                }
                if matched { return j }
                j += 1
            }
            return nil
        }

        while i < count {
            guard bytes[i] == UInt8(ascii: "<") else { i += 1; continue }
            if i + 3 < count, bytes[i + 1] == UInt8(ascii: "!"), bytes[i + 2] == UInt8(ascii: "-"), bytes[i + 3] == UInt8(ascii: "-") {
                let end = find(Array("-->".utf8), from: i + 4).map { $0 + 3 } ?? count
                tokens.append(.comment(text(i, end)))
                i = end
                continue
            }
            // find the end of the tag, respecting quotes
            var j = i + 1
            var quote: UInt8 = 0
            while j < count {
                let c = bytes[j]
                if quote != 0 { if c == quote { quote = 0 } }
                else if c == UInt8(ascii: "\"") || c == UInt8(ascii: "'") { quote = c }
                else if c == UInt8(ascii: ">") { break }
                j += 1
            }
            let raw = text(i, min(j + 1, count))
            guard let (name, attributes, isEnd) = parseTag(raw) else { i += 1; continue }
            if name == "script" && !isEnd {
                let close = find(Array("</script".utf8), from: j, caseInsensitive: true)
                let end = close.flatMap { c in bytes[c...].firstIndex(of: UInt8(ascii: ">")).map { $0 + 1 } } ?? count
                tokens.append(.tag(name: name, attributes: attributes, raw: raw, isEnd: false))
                tokens.append(.script(text(i, end)))
                i = end
                continue
            }
            tokens.append(.tag(name: name, attributes: attributes, raw: raw, isEnd: isEnd))
            i = j + 1
        }
        return tokens
    }

    static func parseTag(_ raw: String) -> (String, [String: String], Bool)? {
        var body = Substring(raw.dropFirst())
        if body.hasSuffix(">") { body = body.dropLast() }
        var isEnd = false
        if body.hasPrefix("/") { isEnd = true; body = body.dropFirst() }
        if body.hasPrefix("!") || body.hasPrefix("?") { return nil }
        let scalars = Array(body.unicodeScalars)
        var index = 0
        var name = ""
        while index < scalars.count, CharacterSet.alphanumerics.contains(scalars[index]) || scalars[index] == "-" || scalars[index] == ":" {
            name.unicodeScalars.append(scalars[index]); index += 1
        }
        guard !name.isEmpty else { return nil }
        var attributes: [String: String] = [:]
        func skipSpace() { while index < scalars.count, CharacterSet.whitespacesAndNewlines.contains(scalars[index]) || scalars[index] == "/" { index += 1 } }
        while index < scalars.count {
            skipSpace()
            var attribute = ""
            while index < scalars.count, !CharacterSet.whitespacesAndNewlines.contains(scalars[index]), scalars[index] != "=", scalars[index] != ">" {
                attribute.unicodeScalars.append(scalars[index]); index += 1
            }
            if attribute.isEmpty { index += 1; continue }
            while index < scalars.count, CharacterSet.whitespacesAndNewlines.contains(scalars[index]) { index += 1 }
            var value = ""
            if index < scalars.count, scalars[index] == "=" {
                index += 1
                while index < scalars.count, CharacterSet.whitespacesAndNewlines.contains(scalars[index]) { index += 1 }
                if index < scalars.count, scalars[index] == "\"" || scalars[index] == "'" {
                    let quote = scalars[index]
                    index += 1
                    while index < scalars.count, scalars[index] != quote { value.unicodeScalars.append(scalars[index]); index += 1 }
                    index += 1
                } else {
                    while index < scalars.count, !CharacterSet.whitespacesAndNewlines.contains(scalars[index]) {
                        value.unicodeScalars.append(scalars[index]); index += 1
                    }
                }
            }
            let key = attribute.lowercased()
            if attributes[key] == nil { attributes[key] = HtmlEncoder.decode(value) }
        }
        return (name.lowercased(), attributes, isEnd)
    }

    /// Is this response HTML, and if so its text.
    public static func html(of response: HTTPResponse) -> String? {
        let type = (response.contentType ?? "").lowercased()
        guard type.contains("html") || (type.isEmpty && response.bodyText.lowercased().contains("<html")) else { return nil }
        return response.bodyText
    }
}
